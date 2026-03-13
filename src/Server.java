import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.*;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.lang.JoseException;

import javax.crypto.Cipher;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Server {

    // === Keys and crypto ===
// === JWE key ring (supports rotation) ===
    private static final Map<String, RSAPublicKey> JWE_PUBLIC_KEYS = new HashMap<>();
    private static final Map<String, RSAPrivateKey> JWE_PRIVATE_KEYS = new HashMap<>();
    private static String CURRENT_JWE_KID;

    private static RSAPublicKey SIG_PUB;
    private static RSAPrivateKey SIG_PRIV;

    // === Registered per-SW ephemeral request verification keys ===
    private static final Map<String, RegisteredClientKey> REGISTERED_CLIENT_KEYS =
            Collections.synchronizedMap(new LinkedHashMap<>());

    // === Metrics storage ===
    private static final Object METRICS_LOCK = new Object();
    private static final Path METRICS_DIR = Paths.get("metrics");
    private static final Path METRICS_FILE = METRICS_DIR.resolve("metrics.ndjson");
    private static final ObjectMapper OM = new ObjectMapper();

    private static final Set<String> ALLOWED_METRICS_ORIGINS = Set.of(
            "https://masteroppgave2026.no",
            "https://app.masteroppgave2026.no"
    );

    // Paths that should NOT be request-verified
    private static final Set<String> UNVERIFIED_REQ_PATHS = Set.of(
            "/",
            "/baseline.html",
            "/styles.css",
            "/favicon.ico",

            "/assets/metrics-client.js",
            "/assets/metrics-debug.html",

            "/metrics",
            "/metrics/ingest",
            "/metrics/debug/stats",
            "/metrics/debug/recent",

            "/sig-pub",
            "/key-exchange",
            "/req-key/register",

            "/big.html",
            "/big.css",
            "/big.js",

            "/unsigned/big.html",
            "/unsigned/big.css",
            "/unsigned/big.js"
    );

    public static void main(String[] args) throws Exception {
        rotateJweKeypair();

        // Host response signing key
        String jwkJson = Files.readString(Paths.get("sig-key.jwk.json"), StandardCharsets.UTF_8);
        RsaJsonWebKey sigJwk = (RsaJsonWebKey) RsaJsonWebKey.Factory.newPublicJwk(jwkJson);
        SIG_PUB = (RSAPublicKey) sigJwk.getPublicKey();
        SIG_PRIV = (RSAPrivateKey) sigJwk.getPrivateKey();

        Files.createDirectories(METRICS_DIR);
        if (!Files.exists(METRICS_FILE)) Files.createFile(METRICS_FILE);

        System.out.println("== Host starting ==");
        System.out.println("JWE key: " + CURRENT_JWE_KID);
        System.out.println("SIG key: sig-key-1");
        System.out.println("Metrics file: " + METRICS_FILE.toAbsolutePath());

        HttpServer http = HttpServer.create(new InetSocketAddress("0.0.0.0", 8080), 0);
        List<HttpContext> contexts = new ArrayList<>();

        // Static
        contexts.add(http.createContext("/", Server::handleFile));
        contexts.add(http.createContext("/login", Server::handleFile));
        contexts.add(http.createContext("/index", Server::handleFile));
        // Public APIs
        contexts.add(http.createContext("/sig-pub", Server::handleSigPub));
        contexts.add(http.createContext("/key-exchange", Server::handleKeyExchange));
        contexts.add(http.createContext("/req-key/register", Server::handleClientKeyRegister));

        // Login APIs
        contexts.add(http.createContext("/api/login", Server::handleLogin));
        contexts.add(http.createContext("/api/login_plain", Server::handleLoginPlain));

        // Metrics APIs
        contexts.add(http.createContext("/metrics", Server::handleMetricsIngest));
        contexts.add(http.createContext("/metrics/ingest", Server::handleMetricsIngest));
        contexts.add(http.createContext("/metrics/debug/stats", Server::handleMetricsDebugStats));
        contexts.add(http.createContext("/metrics/debug/recent", Server::handleMetricsDebugRecent));

        // Protected endpoints
        HttpContext ctxEcho = http.createContext("/api/echo", Server::handleEcho);
        HttpContext secured1 = http.createContext("/secured/index.html", Server::handleFile);

        SessionFilter sessionFilter = new SessionFilter();
        ctxEcho.getFilters().add(sessionFilter);
        secured1.getFilters().add(sessionFilter);

        contexts.addAll(List.of(ctxEcho, secured1));

        for (HttpContext ctx : contexts) {
            ctx.getFilters().add(new OptionsPreflightFilter());
            ctx.getFilters().add(new RequestVerifierFilter());
            ctx.getFilters().add(new ResponseSignerFilter());
        }

        http.setExecutor(java.util.concurrent.Executors.newFixedThreadPool(32));
        http.start();
        System.out.println("HTTP server running on http://0.0.0.0:8080");
    }

    /* =========================
       MODELS
       ========================= */

    static class RegisteredClientKey {
        String clientKeyId;
        PublicKey publicKey;
        long created;
        long expires;
        String swBuild;
        long registeredAtMs;
    }

    static class DecryptResult {
        String payload;
        double decryptMs;
    }

    static class SigParams {
        String label;
        String kid;
        String paramsRaw;
    }

    /* =========================
       METRICS HELPERS
       ========================= */

    private static String kidsSummary() {
        List<String> kids = new ArrayList<>(JWE_PUBLIC_KEYS.keySet());
        Collections.sort(kids);
        return "CURRENT_JWE_KID=" + CURRENT_JWE_KID + " knownKids=" + kids;
    }

    private static final Set<String> SEEN_METRIC_IDS =
            Collections.synchronizedSet(new LinkedHashSet<>());

    private static boolean isDuplicateMetricId(String metricId) {
        if (metricId == null || metricId.isBlank()) return false;

        synchronized (SEEN_METRIC_IDS) {
            if (SEEN_METRIC_IDS.contains(metricId)) {
                return true;
            }

            SEEN_METRIC_IDS.add(metricId);

            if (SEEN_METRIC_IDS.size() > 100000) {
                Iterator<String> it = SEEN_METRIC_IDS.iterator();
                if (it.hasNext()) {
                    it.next();
                    it.remove();
                }
            }

            return false;
        }
    }

    private static void writeMetric(Map<String, Object> m) {
        try {
            m.put("server_received_at_ms", System.currentTimeMillis());
            String line = OM.writeValueAsString(m) + "\n";

            synchronized (METRICS_LOCK) {
                Files.writeString(METRICS_FILE, line, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            }

            System.out.println("[METRICS] APPENDED event=" + m.get("event") + " metric_id=" + m.get("metric_id"));
        } catch (Exception e) {
            System.out.println("[METRICS] WRITE FAILED " + e);
            e.printStackTrace();
        }
    }

    private static boolean isAllowedMetricsOrigin(String origin) {
        return origin != null && ALLOWED_METRICS_ORIGINS.contains(origin);
    }

    private static void applyMetricsCors(HttpExchange ex) {
        // CORS handled only by Apache
    }

    private static int parseIntOrDefault(String s, int fallback) {
        try { return Integer.parseInt(s); } catch (Exception e) { return fallback; }
    }

    private static String jsonBody(Object obj) throws Exception {
        return OM.writeValueAsString(obj);
    }

    private static int headerBytesApprox(Headers h) {
        int sum = 0;
        for (Map.Entry<String, List<String>> e : h.entrySet()) {
            String k = e.getKey();
            List<String> vals = e.getValue();
            if (vals == null || vals.isEmpty()) continue;
            for (String v : vals) {
                String line = k + ": " + (v == null ? "" : v) + "\r\n";
                sum += line.getBytes(StandardCharsets.UTF_8).length;
            }
        }
        sum += 2;
        return sum;
    }

    private static int requestLineBytesApprox(HttpExchange ex) {
        String method = ex.getRequestMethod();
        String path = ex.getRequestURI().toString();
        String line = method + " " + path + " HTTP/1.1\r\n";
        return line.getBytes(StandardCharsets.UTF_8).length;
    }

    private static byte[] getRequestBodyBytes(HttpExchange ex) throws IOException {
        Object o = ex.getAttribute("reqBodyBytes");
        if (o instanceof byte[]) return (byte[]) o;

        try (InputStream in = ex.getRequestBody();
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            in.transferTo(bos);
            byte[] b = bos.toByteArray();
            ex.setAttribute("reqBodyBytes", b);
            return b;
        }
    }

    private static String getRunTag(HttpExchange ex) {
        String q = ex.getRequestURI().getQuery();
        if (q == null) return null;

        for (String part : q.split("&")) {
            if (part.startsWith("rt=")) {
                return part.substring(3);
            }
        }
        return null;
    }

    private static void pruneExpiredClientKeys() {
        long now = System.currentTimeMillis() / 1000L;
        synchronized (REGISTERED_CLIENT_KEYS) {
            Iterator<Map.Entry<String, RegisteredClientKey>> it = REGISTERED_CLIENT_KEYS.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<String, RegisteredClientKey> e = it.next();
                RegisteredClientKey v = e.getValue();
                if (v == null || v.expires < now) {
                    it.remove();
                }
            }
        }
    }

    /* =========================
       HANDLERS
       ========================= */

    private static void handleFile(HttpExchange ex) {
        try {
            String path = ex.getRequestURI().getPath();

            if ("/".equals(path)) {
                path = "/baseline.html";
            } else if ("/login".equals(path)) {
                path = "/login.html";
            } else if ("/index".equals(path)) {
                path = "/index.html";
            }

            String filePath = path;

            if (path.startsWith("/unsigned/")) {
                filePath = path.substring("/unsigned".length());
            }

            File file = new File("www" + filePath);
            if (!file.exists() || file.isDirectory()) {
                ex.setAttribute("handlerResult", HandlerResult.text(404, "Not Found"));
                return;
            }

            byte[] data = Files.readAllBytes(file.toPath());
            ex.setAttribute("handlerResult", HandlerResult.bytes(contentType(path), data));
        } catch (Exception e) {
            ex.setAttribute("handlerResult", HandlerResult.error(e.toString()));
        }
    }

    private static void handleSigPub(HttpExchange ex) {
        try {
            ex.getResponseHeaders().set("Cache-Control", "no-store, no-cache");
            long now = System.currentTimeMillis() / 1000L;
            long exp = now + 86400;

            String n = b64urlUnsigned(SIG_PUB.getModulus().toByteArray());
            String e = b64urlUnsigned(SIG_PUB.getPublicExponent().toByteArray());

            String json =
                    "{"
                            + "\"kty\":\"RSA\","
                            + "\"kid\":\"sig-key-1\","
                            + "\"use\":\"sig\","
                            + "\"alg\":\"PS256\","
                            + "\"created\":" + now + ","
                            + "\"expires\":" + exp + ","
                            + "\"n\":\"" + n + "\","
                            + "\"e\":\"" + e + "\""
                            + "}";

            ex.setAttribute("handlerResult", HandlerResult.json(json));
        } catch (Exception e) {
            ex.setAttribute("handlerResult", HandlerResult.error(e.toString()));
        }
    }

    private static void handleKeyExchange(HttpExchange ex) {
        try {
            ex.getResponseHeaders().set("Cache-Control", "no-store, no-cache");
            System.out.println("[KEY_EXCHANGE] " + kidsSummary());
            System.out.println("[KEY_EXCHANGE] remote=" + ex.getRemoteAddress()
                    + " origin=" + ex.getRequestHeaders().getFirst("Origin")
                    + " host=" + ex.getRequestHeaders().getFirst("Host"));
            RSAPublicKey pub = JWE_PUBLIC_KEYS.get(CURRENT_JWE_KID);

            String n = b64urlUnsigned(pub.getModulus().toByteArray());
            String e = b64urlUnsigned(pub.getPublicExponent().toByteArray());

            String body =
                    "{\"kty\":\"RSA\",\"kid\":\"" + CURRENT_JWE_KID + "\",\"n\":\"" + n + "\",\"e\":\"" + e + "\"}";
            ex.setAttribute("handlerResult", HandlerResult.json(body));
        } catch (Exception e) {
            ex.setAttribute("handlerResult", HandlerResult.error(e.toString()));
        }
    }

    private static void handleClientKeyRegister(HttpExchange ex) {
        try {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
                ex.setAttribute("handlerResult", HandlerResult.text(405, "Method Not Allowed"));
                return;
            }

            byte[] bodyBytes = getRequestBodyBytes(ex);
            String body = new String(bodyBytes, StandardCharsets.UTF_8);

            Map<String, Object> req = OM.readValue(body, Map.class);

            String enc = asString(req.get("enc"));
            String kid = asString(req.get("kid"));

            if (!"jwe".equals(enc)) {
                ex.setAttribute("handlerResult",
                        HandlerResult.jsonStatus(400, "{\"ok\":false,\"error\":\"bad_enc\"}"));
                return;
            }

            // Accept any known kid (supports rotation / multi-instance)
            if (kid == null || kid.isBlank() || !JWE_PUBLIC_KEYS.containsKey(kid)) {
                System.out.println("[REQ_KEY_REGISTER] BAD_KID body.kid=" + kid + " " + kidsSummary());
                ex.setAttribute("handlerResult",
                        HandlerResult.jsonStatus(400, "{\"ok\":false,\"error\":\"bad_kid\"}"));
                return;
            }

            String ciphertext = asString(req.get("ciphertext"));

            if (ciphertext == null || ciphertext.isBlank()) {
                ex.setAttribute("handlerResult",
                        HandlerResult.jsonStatus(400, "{\"ok\":false,\"error\":\"missing_ciphertext\"}"));
                return;
            }

            String jweCompact = asString(req.get("ciphertext"));

            if (jweCompact == null || jweCompact.isBlank()) {
                ex.setAttribute("handlerResult",
                        HandlerResult.jsonStatus(400, "{\"ok\":false,\"error\":\"missing_ciphertext\"}"));
                return;
            }

            JsonWebEncryption jwe = new JsonWebEncryption();
            jwe.setCompactSerialization(jweCompact);

            String kidHeader = jwe.getKeyIdHeaderValue();
            RSAPrivateKey priv = JWE_PRIVATE_KEYS.get(kidHeader);

            if (priv == null) {
                throw new SecurityException("unknown JWE kid " + kidHeader);
            }

            jwe.setKey(priv);

            String plaintextJson = jwe.getPayload();

            Map<String, Object> env = OM.readValue(plaintextJson, Map.class);
            Map<String, Object> payload = castMap(env.get("payload"));
            String proofSigB64 = asString(env.get("proof_sig_b64"));

            if (payload == null || proofSigB64 == null || proofSigB64.isBlank()) {
                ex.setAttribute("handlerResult",
                        HandlerResult.jsonStatus(400, "{\"ok\":false,\"error\":\"bad_registration_envelope\"}"));
                return;
            }

            String clientKeyId = asString(payload.get("client_key_id"));
            Number createdN = (Number) payload.get("created");
            Number expiresN = (Number) payload.get("expires");
            String swBuild = asString(payload.get("sw_build"));
            Map<String, Object> pubJwkMap = castMap(payload.get("pub_jwk"));

            if (clientKeyId == null || clientKeyId.isBlank() || pubJwkMap == null) {
                ex.setAttribute("handlerResult",
                        HandlerResult.jsonStatus(400, "{\"ok\":false,\"error\":\"missing_client_key_fields\"}"));
                return;
            }

            long now = System.currentTimeMillis() / 1000L;
            long created = createdN == null ? 0 : createdN.longValue();
            long expires = expiresN == null ? 0 : expiresN.longValue();

            if (created > now + 60) {
                ex.setAttribute("handlerResult",
                        HandlerResult.jsonStatus(400, "{\"ok\":false,\"error\":\"client_key_created_in_future\"}"));
                return;
            }

            if (expires < now) {
                ex.setAttribute("handlerResult",
                        HandlerResult.jsonStatus(400, "{\"ok\":false,\"error\":\"client_key_expired\"}"));
                return;
            }

            String stablePayloadJson = stableRegistrationJson(payload);

            String pubJwkJson = OM.writeValueAsString(pubJwkMap);
            PublicJsonWebKey pjwk = PublicJsonWebKey.Factory.newPublicJwk(pubJwkJson);
            PublicKey publicKey = (PublicKey) pjwk.getKey();

            boolean ok = verifyPss(
                    stablePayloadJson.getBytes(StandardCharsets.UTF_8),
                    Base64.getDecoder().decode(proofSigB64),
                    publicKey
            );

            if (!ok) {
                ex.setAttribute("handlerResult",
                        HandlerResult.jsonStatus(401, "{\"ok\":false,\"error\":\"registration_proof_invalid\"}"));
                return;
            }

            RegisteredClientKey reg = new RegisteredClientKey();
            reg.clientKeyId = clientKeyId;
            reg.publicKey = publicKey;
            reg.created = created;
            reg.expires = expires;
            reg.swBuild = swBuild;
            reg.registeredAtMs = System.currentTimeMillis();

            synchronized (REGISTERED_CLIENT_KEYS) {
                REGISTERED_CLIENT_KEYS.put(clientKeyId, reg);
                pruneExpiredClientKeys();
            }

            Map<String, Object> m = new LinkedHashMap<>();
            m.put("event", "host_client_key_registered");
            m.put("client_key_id", clientKeyId);
            m.put("sw_build", swBuild);
            m.put("created", created);
            m.put("expires", expires);
            writeMetric(m);

            Map<String, Object> resp = new LinkedHashMap<>();
            resp.put("ok", true);
            resp.put("registered", true);
            resp.put("client_key_id", clientKeyId);

            ex.setAttribute("handlerResult", HandlerResult.json(jsonBody(resp)));
        } catch (Exception e) {
            ex.setAttribute("handlerResult",
                    HandlerResult.jsonStatus(500, "{\"ok\":false,\"error\":\"" + json(e.toString()) + "\"}"));
        }
    }

    private static void handleMetricsIngest(HttpExchange ex) {
        try {
            applyMetricsCors(ex);

            Headers h = ex.getResponseHeaders();
            h.set("X-Metrics-Handler", "java-host");

            if ("OPTIONS".equalsIgnoreCase(ex.getRequestMethod())) {
                ex.setAttribute("handlerResult",
                        new HandlerResult(204, "text/plain; charset=utf-8", new byte[0]));
                return;
            }

            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
                ex.setAttribute("handlerResult",
                        HandlerResult.jsonStatus(405, "{\"ok\":false,\"error\":\"method_not_allowed\"}"));
                return;
            }

            byte[] bodyBytes = getRequestBodyBytes(ex);
            String body = new String(bodyBytes, StandardCharsets.UTF_8).trim();

            System.out.println("--------------------------------------------------");
            System.out.println("[METRICS] REQUEST RECEIVED");
            System.out.println("[METRICS] origin=" + ex.getRequestHeaders().getFirst("Origin"));
            System.out.println("[METRICS] remote=" + ex.getRemoteAddress());
            System.out.println("[METRICS] path=" + ex.getRequestURI().getPath());
            System.out.println("[METRICS] bytes=" + bodyBytes.length);
            System.out.println("[METRICS] body=" + body);

            if (body.isEmpty()) {
                ex.setAttribute("handlerResult",
                        HandlerResult.jsonStatus(400, "{\"ok\":false,\"error\":\"empty_body\"}"));
                return;
            }

            Map<String, Object> root;
            try {
                root = OM.readValue(body, Map.class);
            } catch (Exception parseFail) {
                System.out.println("[METRICS] JSON PARSE FAILED");
                parseFail.printStackTrace();

                Map<String, Object> fallback = new LinkedHashMap<>();
                fallback.put("event", "metrics_parse_fallback");
                fallback.put("raw", body);
                fallback.put("request_path", ex.getRequestURI().getPath());
                fallback.put("request_origin", ex.getRequestHeaders().getFirst("Origin"));
                writeMetric(fallback);

                ex.setAttribute("handlerResult", HandlerResult.json("{\"ok\":true,\"fallback\":true}"));
                return;
            }

            String mode = String.valueOf(root.getOrDefault("metric_mode", "single"));

            if ("batch".equals(mode)) {
                Object metricsObj = root.get("metrics");

                if (!(metricsObj instanceof List)) {
                    ex.setAttribute("handlerResult",
                            HandlerResult.jsonStatus(400, "{\"ok\":false,\"error\":\"missing_metrics_array\"}"));
                    return;
                }

                List<Map<String, Object>> metrics = (List<Map<String, Object>>) metricsObj;
                String batchId = String.valueOf(root.get("batch_id"));
                String requestOrigin = ex.getRequestHeaders().getFirst("Origin");

                int stored = 0;
                int duplicates = 0;

                for (Map<String, Object> m : metrics) {
                    if (m == null) continue;

                    String metricId = m.get("metric_id") == null ? null : String.valueOf(m.get("metric_id"));
                    if (isDuplicateMetricId(metricId)) {
                        duplicates++;
                        continue;
                    }

                    m.putIfAbsent("batch_id", batchId);
                    m.putIfAbsent("runTag", root.get("runTag"));
                    m.putIfAbsent("batch_kind", root.get("batch_kind"));
                    m.putIfAbsent("batch_started_at", root.get("batch_started_at"));
                    m.putIfAbsent("batch_flushed_at", root.get("batch_flushed_at"));
                    m.putIfAbsent("origin", root.get("origin"));
                    m.putIfAbsent("page_url", root.get("page_url"));
                    m.putIfAbsent("user_agent", root.get("user_agent"));

                    m.put("request_origin", requestOrigin);
                    m.put("request_path", ex.getRequestURI().getPath());
                    m.put("server_remote", String.valueOf(ex.getRemoteAddress()));

                    writeMetric(m);
                    stored++;
                }

                Map<String, Object> resp = new LinkedHashMap<>();
                resp.put("ok", true);
                resp.put("mode", "batch");
                resp.put("stored", stored);
                resp.put("duplicates", duplicates);
                resp.put("handler", "java-host");

                ex.setAttribute("handlerResult", HandlerResult.json(jsonBody(resp)));
                return;
            }

            String metricId = root.get("metric_id") == null ? null : String.valueOf(root.get("metric_id"));
            String event = root.get("event") == null ? null : String.valueOf(root.get("event"));

            if (isDuplicateMetricId(metricId)) {
                System.out.println("[METRICS] DUPLICATE metric ignored event=" + event + " metric_id=" + metricId);
                ex.setAttribute("handlerResult",
                        HandlerResult.json("{\"ok\":true,\"duplicate\":true,\"handler\":\"java-host\"}"));
                return;
            }

            root.put("request_origin", ex.getRequestHeaders().getFirst("Origin"));
            root.put("request_path", ex.getRequestURI().getPath());
            root.put("server_remote", String.valueOf(ex.getRemoteAddress()));

            writeMetric(root);

            ex.setAttribute("handlerResult",
                    HandlerResult.json("{\"ok\":true,\"duplicate\":false,\"handler\":\"java-host\"}"));
        } catch (Exception e) {
            System.out.println("[METRICS] ERROR " + e);
            e.printStackTrace();

            ex.setAttribute("handlerResult",
                    HandlerResult.jsonStatus(
                            500,
                            "{\"ok\":false,\"error\":\"" + json(e.toString()) + "\"}"
                    )
            );
        }
    }

    private static void handleMetricsDebugStats(HttpExchange ex) {
        try {
            applyMetricsCors(ex);

            if ("OPTIONS".equalsIgnoreCase(ex.getRequestMethod())) {
                ex.setAttribute("handlerResult",
                        new HandlerResult(204, "text/plain; charset=utf-8", new byte[0]));
                return;
            }

            if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) {
                ex.setAttribute("handlerResult",
                        HandlerResult.jsonStatus(405, "{\"ok\":false,\"error\":\"method_not_allowed\"}"));
                return;
            }

            long lineCount = 0;
            Map<String, Integer> eventCounts = new LinkedHashMap<>();

            if (Files.exists(METRICS_FILE)) {
                try (BufferedReader br = Files.newBufferedReader(METRICS_FILE, StandardCharsets.UTF_8)) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        lineCount++;
                        try {
                            Map<String, Object> m = OM.readValue(line, Map.class);
                            String ev = String.valueOf(m.get("event"));
                            eventCounts.put(ev, eventCounts.getOrDefault(ev, 0) + 1);
                        } catch (Exception ignore) {
                        }
                    }
                }
            }

            Map<String, Object> resp = new LinkedHashMap<>();
            resp.put("ok", true);
            resp.put("metrics_file", METRICS_FILE.toAbsolutePath().toString());
            resp.put("metrics_file_exists", Files.exists(METRICS_FILE));
            resp.put("metrics_file_size_bytes", Files.exists(METRICS_FILE) ? Files.size(METRICS_FILE) : 0);
            resp.put("total_lines", lineCount);
            resp.put("seen_metric_ids_size", SEEN_METRIC_IDS.size());
            resp.put("registered_client_keys", REGISTERED_CLIENT_KEYS.size());
            resp.put("event_counts", eventCounts);

            ex.setAttribute("handlerResult", HandlerResult.json(jsonBody(resp)));
        } catch (Exception e) {
            ex.setAttribute("handlerResult",
                    HandlerResult.jsonStatus(500, "{\"ok\":false,\"error\":\"" + json(e.toString()) + "\"}"));
        }
    }

    private static void handleMetricsDebugRecent(HttpExchange ex) {
        try {
            applyMetricsCors(ex);

            if ("OPTIONS".equalsIgnoreCase(ex.getRequestMethod())) {
                ex.setAttribute("handlerResult",
                        new HandlerResult(204, "text/plain; charset=utf-8", new byte[0]));
                return;
            }

            if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) {
                ex.setAttribute("handlerResult",
                        HandlerResult.jsonStatus(405, "{\"ok\":false,\"error\":\"method_not_allowed\"}"));
                return;
            }

            int limit = 40;
            String q = ex.getRequestURI().getQuery();
            if (q != null) {
                for (String part : q.split("&")) {
                    if (part.startsWith("limit=")) {
                        limit = parseIntOrDefault(part.substring(6), 40);
                    }
                }
            }
            limit = Math.max(1, Math.min(200, limit));

            List<String> lines = Files.exists(METRICS_FILE)
                    ? Files.readAllLines(METRICS_FILE, StandardCharsets.UTF_8)
                    : List.of();

            int from = Math.max(0, lines.size() - limit);
            List<Map<String, Object>> recent = new ArrayList<>();

            for (int i = from; i < lines.size(); i++) {
                String line = lines.get(i);
                try {
                    recent.add(OM.readValue(line, Map.class));
                } catch (Exception ignore) {
                }
            }

            Map<String, Object> resp = new LinkedHashMap<>();
            resp.put("ok", true);
            resp.put("limit", limit);
            resp.put("count", recent.size());
            resp.put("items", recent);

            ex.setAttribute("handlerResult", HandlerResult.json(jsonBody(resp)));
        } catch (Exception e) {
            ex.setAttribute("handlerResult",
                    HandlerResult.jsonStatus(500, "{\"ok\":false,\"error\":\"" + json(e.toString()) + "\"}"));
        }
    }

    private static void handleLogin(HttpExchange ex) {
        try {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
                ex.setAttribute("handlerResult", HandlerResult.text(405, "Method Not Allowed"));
                return;
            }

            byte[] bodyBytes = getRequestBodyBytes(ex);
            String body = new String(bodyBytes, StandardCharsets.UTF_8);
            String runTag = getRunTag(ex);

            Map<String, Object> reqMetric = new LinkedHashMap<>();
            reqMetric.put("event", "host_login_req_sizes");
            reqMetric.put("runTag", runTag);
            reqMetric.put("path", ex.getRequestURI().toString());
            reqMetric.put("req_line_bytes", requestLineBytesApprox(ex));
            reqMetric.put("req_headers_bytes", headerBytesApprox(ex.getRequestHeaders()));
            reqMetric.put("req_body_bytes", bodyBytes.length);
            writeMetric(reqMetric);

            Map<String, Object> reqObj = OM.readValue(body, Map.class);
            String usernameEnc = asString(reqObj.get("username"));
            String passwordEnc = asString(reqObj.get("password"));

            DecryptResult userDecrypt;
            DecryptResult passDecrypt;

            long wallStart = System.nanoTime();

            {
                String enc = usernameEnc;
                if (enc != null && enc.startsWith("JWE: ")) enc = enc.substring(5).trim();
                userDecrypt = (enc == null) ? new DecryptResult() : jweDecryptTimed(enc);
            }

            {
                String enc = passwordEnc;
                if (enc != null && enc.startsWith("JWE: ")) enc = enc.substring(5).trim();
                passDecrypt = (enc == null) ? new DecryptResult() : jweDecryptTimed(enc);
            }

            double wallTotalMs = (System.nanoTime() - wallStart) / 1_000_000.0;

            String user = userDecrypt.payload;
            String pass = passDecrypt.payload;

            Map<String, Object> decryptMetric = new LinkedHashMap<>();
            decryptMetric.put("event", "host_jwe_decrypt_timings");
            decryptMetric.put("runTag", runTag);
            decryptMetric.put("path", ex.getRequestURI().getPath());
            decryptMetric.put("decrypt_username_ms", userDecrypt.decryptMs);
            decryptMetric.put("decrypt_password_ms", passDecrypt.decryptMs);
            decryptMetric.put("decrypt_crypto_sum_ms", userDecrypt.decryptMs + passDecrypt.decryptMs);
            decryptMetric.put("decrypt_wall_ms", wallTotalMs);
            decryptMetric.put("username_is_null", user == null);
            decryptMetric.put("password_is_null", pass == null);
            writeMetric(decryptMetric);

            boolean success = "alice".equals(user) && "secret".equals(pass);

            Map<String, Object> resultMetric = new LinkedHashMap<>();
            resultMetric.put("event", "host_login_result");
            resultMetric.put("runTag", runTag);
            resultMetric.put("path", ex.getRequestURI().getPath());
            resultMetric.put("login_success", success);
            resultMetric.put("user_matches", "alice".equals(user));
            resultMetric.put("pass_matches", "secret".equals(pass));
            writeMetric(resultMetric);

            if (success) {
                long now = System.currentTimeMillis() / 1000L;
                long exp = now + 1800;
                String session = "{\"u\":\"" + json(user) + "\",\"role\":\"admin\",\"iat\":" + now + ",\"exp\":" + exp + "}";
                String cookieVal = jweEncrypt(session);
                CookieOptions opts = CookieOptions.defaultSession(1800);
                setCookie(ex, "sess", cookieVal, opts);
                ex.setAttribute("handlerResult", HandlerResult.json("{\"ok\":true}"));
            } else {
                ex.setAttribute("handlerResult", HandlerResult.json("{\"ok\":false}"));
            }
        } catch (Exception e) {
            ex.setAttribute("handlerResult", HandlerResult.error(e.toString()));
        }
    }

    private static void handleLoginPlain(HttpExchange ex) {
        try {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
                ex.setAttribute("handlerResult", HandlerResult.text(405, "Method Not Allowed"));
                return;
            }

            byte[] bodyBytes = getRequestBodyBytes(ex);
            String body = new String(bodyBytes, StandardCharsets.UTF_8);

            Map<String, Object> m = new LinkedHashMap<>();
            m.put("event", "host_login_plain_req_sizes");
            m.put("path", ex.getRequestURI().toString());
            m.put("req_line_bytes", requestLineBytesApprox(ex));
            m.put("req_headers_bytes", headerBytesApprox(ex.getRequestHeaders()));
            m.put("req_body_bytes", bodyBytes.length);
            writeMetric(m);

            Map<String, Object> reqObj = OM.readValue(body, Map.class);
            String user = asString(reqObj.get("username"));
            String pass = asString(reqObj.get("password"));

            boolean success = "alice".equalsIgnoreCase(user) && "secret".equals(pass);
            ex.setAttribute("handlerResult", HandlerResult.json(success ? "{\"ok\":true}" : "{\"ok\":false}"));
        } catch (Exception e) {
            ex.setAttribute("handlerResult", HandlerResult.error(e.toString()));
        }
    }

    private static void handleEcho(HttpExchange ex) {
        try {
            String rawBody = new String(getRequestBodyBytes(ex), StandardCharsets.UTF_8);
            ex.setAttribute("handlerResult", HandlerResult.json("{\"echo\":" + json(rawBody) + "}"));
        } catch (Exception e) {
            ex.setAttribute("handlerResult", HandlerResult.error(e.toString()));
        }
    }

    /* =========================
       FILTERS
       ========================= */

    static class OptionsPreflightFilter extends Filter {
        public String description() { return "OPTIONS preflight responder"; }

        public void doFilter(HttpExchange ex, Chain chain) throws IOException {
            if ("OPTIONS".equalsIgnoreCase(ex.getRequestMethod())) {
                ex.setAttribute("handlerResult",
                        new HandlerResult(204, "text/plain; charset=utf-8", new byte[0]));
                return;
            }
            chain.doFilter(ex);
        }
    }

    static class RequestVerifierFilter extends Filter {
        public String description() { return "Verifies incoming requests using Content-Digest + Signature"; }

        public void doFilter(HttpExchange ex, Chain chain) throws IOException {
            String path = ex.getRequestURI().getPath();
            boolean isUnsignedPrefix = path.startsWith("/unsigned/img/");
            boolean skip = UNVERIFIED_REQ_PATHS.contains(path) || isUnsignedPrefix;

            if (skip) {
                chain.doFilter(ex);
                return;
            }

            byte[] body = getRequestBodyBytes(ex);

            try {
                long v0 = System.nanoTime();

                verifyRequest(ex, body);

                double verifyMs = (System.nanoTime() - v0) / 1_000_000.0;

                Map<String, Object> m = new LinkedHashMap<>();
                m.put("event", "host_req_verify_ok");
                m.put("runTag", getRunTag(ex));
                m.put("path", path);
                m.put("verify_request_sig_ms", verifyMs);
                m.put("x_client_key_id", ex.getRequestHeaders().getFirst("X-Client-Key-Id"));
                writeMetric(m);

                chain.doFilter(ex);
            } catch (Exception ve) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("event", "host_req_verify_fail");
                m.put("runTag", getRunTag(ex));
                m.put("path", path);
                m.put("err", ve.getMessage());
                m.put("has_signature", ex.getRequestHeaders().getFirst("Signature") != null);
                m.put("has_signature_input", ex.getRequestHeaders().getFirst("Signature-Input") != null);
                m.put("has_content_digest", ex.getRequestHeaders().getFirst("Content-Digest") != null);
                m.put("x_client_key_id", ex.getRequestHeaders().getFirst("X-Client-Key-Id"));
                writeMetric(m);

                ex.setAttribute("handlerResult",
                        HandlerResult.jsonStatus(401, "{\"ok\":false,\"error\":\"" + json(ve.getMessage()) + "\"}")
                );
                chain.doFilter(ex);  // ← ADD THIS
            }
        }
    }

    static class ResponseSignerFilter extends Filter {
        public String description() { return "Signs responses using Content-Digest + Signature"; }

        public void doFilter(HttpExchange ex, Chain chain) throws IOException {
            chain.doFilter(ex);

            String path = ex.getRequestURI().getPath();
            HandlerResult result = (HandlerResult) ex.getAttribute("handlerResult");
            if (result == null) result = HandlerResult.text(500, "Missing response");

            boolean unsigned = path.startsWith("/unsigned/");

            Headers h = ex.getResponseHeaders();
            h.set("Content-Type", result.contentType);

            if (unsigned) {
                ex.sendResponseHeaders(result.status, result.body.length);
                try (OutputStream os = ex.getResponseBody()) {
                    os.write(result.body);
                }
                return;
            }

            byte[] body = result.body;
            int status = result.status;

            String digestHeader = "sha-256=:" + Base64.getEncoder().encodeToString(sha256(body)) + ":";
            long created = System.currentTimeMillis() / 1000L;
            String method = ex.getRequestMethod().toLowerCase(Locale.ROOT);
            String target = ex.getRequestURI().toString();

            String sigInput =
                    "(\"@method\" \"@target-uri\" \"@status\" \"content-digest\");" +
                            "created=" + created + ";" +
                            "keyid=\"sig-key-1\";" +
                            "alg=\"rsa-pss-sha256\"";

            String base =
                    "\"@method\": \"" + method + "\"\n" +
                            "\"@target-uri\": \"" + target + "\"\n" +
                            "\"@status\": " + status + "\n" +
                            "content-digest: " + digestHeader + "\n" +
                            "\"@signature-params\": " + sigInput;

            String sigB64;
            try {
                byte[] sig = signPss(base.getBytes(StandardCharsets.UTF_8), SIG_PRIV);
                sigB64 = Base64.getEncoder().encodeToString(sig);
            } catch (Exception e) {
                ex.sendResponseHeaders(500, 0);
                ex.close();
                return;
            }

            h.set("Content-Digest", digestHeader);
            h.set("Signature-Input", "sig1=" + sigInput);
            h.set("Signature", "sig1=:" + sigB64 + ":");

            ex.sendResponseHeaders(status, body.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(body);
            }
        }
    }

    /* =========================
       REQUEST VERIFY
       ========================= */

    private static void verifyRequest(HttpExchange ex, byte[] body) throws Exception {
        Headers reqH = ex.getRequestHeaders();

        String clientKeyId = reqH.getFirst("X-Client-Key-Id");
        String cd = reqH.getFirst("Content-Digest");
        String sig = reqH.getFirst("Signature");
        String sigInput = reqH.getFirst("Signature-Input");

        System.out.println("----- VERIFY START -----");
        System.out.println("[VERIFY] method=" + ex.getRequestMethod());
        System.out.println("[VERIFY] uri=" + ex.getRequestURI());
        System.out.println("[VERIFY] x-client-key-id=" + clientKeyId);
        System.out.println("[VERIFY] content-length=" + reqH.getFirst("Content-length"));
        System.out.println("[VERIFY] transfer-encoding=" + reqH.getFirst("Transfer-encoding"));
        System.out.println("[VERIFY] content-type=" + reqH.getFirst("Content-type"));
        System.out.println("[VERIFY] x-run-tag=" + reqH.getFirst("X-Run-Tag"));
        System.out.println("[VERIFY] x-req-seq=" + reqH.getFirst("X-Req-Seq"));

        if (clientKeyId == null || clientKeyId.isBlank()) {
            throw new SecurityException("missing x-client-key-id");
        }

        if (cd == null || sig == null || sigInput == null) {
            throw new SecurityException("missing security headers");
        }

        RegisteredClientKey reg;
        synchronized (REGISTERED_CLIENT_KEYS) {
            pruneExpiredClientKeys();
            reg = REGISTERED_CLIENT_KEYS.get(clientKeyId);
        }

        if (reg == null || reg.publicKey == null) {
            throw new SecurityException("unknown client key");
        }

        String expectedB64 = parseDigestB64(cd);
        if (expectedB64 == null) throw new SecurityException("bad Content-Digest");

        byte[] actualHash = sha256(body);
        String actualB64 = Base64.getEncoder().encodeToString(actualHash);

        System.out.println("[VERIFY] expected digest b64=" + expectedB64);
        System.out.println("[VERIFY] actual   digest b64=" + actualB64);
        System.out.println("[VERIFY] body length=" + body.length);
        System.out.println("[VERIFY] body first32 b64=" +
                Base64.getEncoder().encodeToString(Arrays.copyOf(body, Math.min(body.length, 32))));
        if (body.length > 0) {
            String preview = new String(body, StandardCharsets.UTF_8);
            System.out.println("[VERIFY] body preview=" + preview.substring(0, Math.min(preview.length(), 220)));
        }

        if (!actualB64.equals(expectedB64)) {
            Path p = Paths.get("metrics", "failed-body-" + System.currentTimeMillis() + ".bin");
            Files.write(p, body);
            System.out.println("[VERIFY] wrote failing body to " + p.toAbsolutePath());
            throw new SecurityException("digest mismatch");
        }

        SigParams p = parseSigInput(sigInput);
        String sigB64 = parseSigB64(sig);

        String method = ex.getRequestMethod().toLowerCase(Locale.ROOT);
        String target = ex.getRequestURI().toString();

        String base =
                "x-client-key-id: " + clientKeyId + "\n" +
                        "\"@method\": \"" + method + "\"\n" +
                        "\"@target-uri\": \"" + target + "\"\n" +
                        "content-digest: " + cd + "\n" +
                        "\"@signature-params\": " + p.paramsRaw;

        boolean ok = verifyPss(
                base.getBytes(StandardCharsets.UTF_8),
                Base64.getDecoder().decode(sigB64),
                reg.publicKey
        );

        if (!ok) throw new SecurityException("signature verification failed");
    }

    /* =========================
       CRYPTO + UTILS
       ========================= */

    private static DecryptResult jweDecryptTimed(String compact) {
        DecryptResult r = new DecryptResult();
        try {
            JsonWebEncryption jwe = new JsonWebEncryption();
            jwe.setCompactSerialization(compact);
            String kid = jwe.getKeyIdHeaderValue();
            RSAPrivateKey priv = JWE_PRIVATE_KEYS.get(kid);

            if (priv == null) throw new RuntimeException("Unknown JWE kid " + kid);

            jwe.setKey(priv);

            long t0 = System.nanoTime();
            r.payload = jwe.getPayload();
            r.decryptMs = (System.nanoTime() - t0) / 1_000_000.0;
        } catch (Exception e) {
            r.payload = null;
            r.decryptMs = 0;
        }
        return r;
    }

    private static byte[] rsaOaep256Decrypt(byte[] ciphertext, PrivateKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(ciphertext);
    }

    private static String stableRegistrationJson(Map<String, Object> payload) throws Exception {
        Map<String, Object> pub = castMap(payload.get("pub_jwk"));

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("client_key_id", payload.get("client_key_id"));
        out.put("created", payload.get("created"));
        out.put("expires", payload.get("expires"));
        out.put("sw_build", payload.get("sw_build"));

        Map<String, Object> pubOut = new LinkedHashMap<>();
        pubOut.put("kty", pub.get("kty"));
        pubOut.put("kid", pub.get("kid"));
        pubOut.put("use", pub.get("use"));
        pubOut.put("alg", pub.get("alg"));
        pubOut.put("key_ops", pub.get("key_ops"));
        pubOut.put("ext", pub.get("ext"));
        pubOut.put("n", pub.get("n"));
        pubOut.put("e", pub.get("e"));

        out.put("pub_jwk", pubOut);
        return OM.writeValueAsString(out);
    }

    private static void rotateJweKeypair() throws Exception {

        RsaJsonWebKey jwk = RsaJwkGenerator.generateJwk(2048);

        String kid = "host-jwe-key-" + System.currentTimeMillis();

        RSAPublicKey pub = (RSAPublicKey) jwk.getPublicKey();
        RSAPrivateKey priv = (RSAPrivateKey) jwk.getPrivateKey();

        JWE_PUBLIC_KEYS.put(kid, pub);
        JWE_PRIVATE_KEYS.put(kid, priv);

        CURRENT_JWE_KID = kid;

        System.out.println("Rotated JWE key → " + kid);
    }

    private static String jweEncrypt(String json) throws JoseException {
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setPayload(json);
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
        RSAPublicKey pub = JWE_PUBLIC_KEYS.get(CURRENT_JWE_KID);

        jwe.setKey(pub);
        jwe.setKeyIdHeaderValue(CURRENT_JWE_KID);
        return jwe.getCompactSerialization();
    }

    private static byte[] sha256(byte[] in) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(in);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] signPss(byte[] input, PrivateKey key) throws Exception {
        Signature s = Signature.getInstance("RSASSA-PSS");
        s.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        s.initSign(key);
        s.update(input);
        return s.sign();
    }

    private static boolean verifyPss(byte[] input, byte[] sig, PublicKey key) throws Exception {
        Signature s = Signature.getInstance("RSASSA-PSS");
        s.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        s.initVerify(key);
        s.update(input);
        return s.verify(sig);
    }

    private static String b64urlUnsigned(byte[] in) {
        if (in.length > 1 && in[0] == 0) in = Arrays.copyOfRange(in, 1, in.length);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(in);
    }

    private static String parseDigestB64(String cd) {
        Matcher m = Pattern.compile("sha-256=:(.+):", Pattern.CASE_INSENSITIVE).matcher(cd);
        return m.find() ? m.group(1) : null;
    }

    private static String parseSigB64(String sig) {
        Matcher m = Pattern.compile("sig1=:(.+):", Pattern.CASE_INSENSITIVE).matcher(sig);
        return m.find() ? m.group(1) : null;
    }

    private static SigParams parseSigInput(String sigInput) {
        SigParams p = new SigParams();
        Matcher m = Pattern.compile("^\\s*([a-zA-Z0-9_]+)\\s*=\\s*(.+)\\s*$").matcher(sigInput);
        if (!m.find()) throw new IllegalArgumentException("bad Signature-Input");
        p.label = m.group(1);
        p.paramsRaw = m.group(2);

        Matcher km = Pattern.compile("keyid\\s*=\\s*\"([^\"]+)\"").matcher(p.paramsRaw);
        if (km.find()) p.kid = km.group(1);

        return p;
    }

    private static String jsonField(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"(.*?)\"", Pattern.DOTALL).matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private static String json(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }

    private static String asString(Object o) {
        return o == null ? null : String.valueOf(o);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castMap(Object o) {
        return (o instanceof Map) ? (Map<String, Object>) o : null;
    }

    private static String contentType(String path) {
        if (path.endsWith(".html")) return "text/html; charset=utf-8";
        if (path.endsWith(".css")) return "text/css; charset=utf-8";
        if (path.endsWith(".js")) return "application/javascript; charset=utf-8";
        if (path.endsWith(".json")) return "application/json; charset=utf-8";
        if (path.endsWith(".png")) return "image/png";
        if (path.endsWith(".jpg") || path.endsWith(".jpeg")) return "image/jpeg";
        if (path.endsWith(".webp")) return "image/webp";
        if (path.endsWith(".svg")) return "image/svg+xml";
        return "application/octet-stream";
    }

    /* =========================
       SESSION / COOKIE
       ========================= */

    static class SessionFilter extends Filter {
        public String description() { return "sess"; }
        public void doFilter(HttpExchange ex, Chain c) throws IOException { c.doFilter(ex); }
    }

    static class CookieOptions {
        String path = "/";
        boolean httpOnly = true, secure = true;
        Long maxAgeSeconds = null;

        static CookieOptions defaultSession(long secs) {
            CookieOptions o = new CookieOptions();
            o.maxAgeSeconds = secs;
            return o;
        }
    }

    static void setCookie(HttpExchange ex, String name, String value, CookieOptions o) {
        StringBuilder sb = new StringBuilder();
        sb.append(name).append("=").append(value != null ? value : "");
        if (o.path != null) sb.append("; Path=").append(o.path);
        if (o.maxAgeSeconds != null) {
            sb.append("; Max-Age=").append(o.maxAgeSeconds);
            ZonedDateTime exp = ZonedDateTime.now(ZoneOffset.UTC).plusSeconds(o.maxAgeSeconds);
            String date = DateTimeFormatter.RFC_1123_DATE_TIME.format(exp);
            sb.append("; Expires=").append(date);
        }
        if (o.secure) sb.append("; Secure");
        if (o.httpOnly) sb.append("; HttpOnly");
        ex.getResponseHeaders().add("Set-Cookie", sb.toString());
    }

    /* =========================
       RESPONSE MODEL
       ========================= */

    static class HandlerResult {
        int status;
        String contentType;
        byte[] body;

        static HandlerResult json(String body) {
            return new HandlerResult(200, "application/json; charset=utf-8", body.getBytes(StandardCharsets.UTF_8));
        }

        static HandlerResult jsonStatus(int status, String body) {
            return new HandlerResult(status, "application/json; charset=utf-8", body.getBytes(StandardCharsets.UTF_8));
        }

        static HandlerResult text(int status, String msg) {
            return new HandlerResult(status, "text/plain; charset=utf-8", msg.getBytes(StandardCharsets.UTF_8));
        }

        static HandlerResult bytes(String ct, byte[] b) {
            return new HandlerResult(200, ct, b);
        }

        static HandlerResult error(String msg) {
            return jsonStatus(500, "{\"error\":\"" + json(msg) + "\"}");
        }

        HandlerResult(int status, String contentType, byte[] body) {
            this.status = status;
            this.contentType = contentType;
            this.body = body;
        }
    }
}