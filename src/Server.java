import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.*;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.lang.JoseException;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
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
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Server {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Path METRICS_DIR = Paths.get("metrics");
    private static final Path METRICS_FILE = METRICS_DIR.resolve("metrics.ndjson");
    private static final Map<String, RSAPublicKey> CLIENT_REQ_PUBS = new ConcurrentHashMap<>();

    private static RSAPublicKey JWE_PUB;
    private static RSAPrivateKey JWE_PRIV;
    private static String JWE_KID = "host-jwe-key-1";
    private static RSAPublicKey SIG_PUB;
    private static RSAPrivateKey SIG_PRIV;

    public static void main(String[] args) throws Exception {
        Files.createDirectories(METRICS_DIR);

        rotateJweKeypair();

        String jwkJson = Files.readString(Paths.get("sig-key.jwk.json"), StandardCharsets.UTF_8);
        RsaJsonWebKey sigJwk = (RsaJsonWebKey) JsonWebKey.Factory.newJwk(jwkJson);
        SIG_PUB = (RSAPublicKey) sigJwk.getPublicKey();
        SIG_PRIV = (RSAPrivateKey) sigJwk.getPrivateKey();

        System.out.println("== Host starting ==");
        System.out.println("JWE key: " + JWE_KID);
        System.out.println("SIG key: " + sigJwk.getKeyId());

        HttpServer http = HttpServer.create(new InetSocketAddress("0.0.0.0", 8080), 0);
        List<HttpContext> contexts = new ArrayList<>();

        contexts.add(http.createContext("/", Server::handleFile));
        contexts.add(http.createContext("/login.html", Server::handleFile));
        contexts.add(http.createContext("/baseline.html", Server::handleFile));
        contexts.add(http.createContext("/big.html", Server::handleFile));
        contexts.add(http.createContext("/index.html", Server::handleFile));
        contexts.add(http.createContext("/styles.css", Server::handleFile));
        contexts.add(http.createContext("/sig-pub", Server::handleSigPub));
        contexts.add(http.createContext("/key-exchange", Server::handleKeyExchange));
        contexts.add(http.createContext("/metrics", Server::handleMetrics));
        contexts.add(http.createContext("/api/login", Server::handleLogin));
        contexts.add(http.createContext("/api/login_plain", Server::handleLoginPlain));
        contexts.add(http.createContext("/req-key/register", Server::handleReqKeyRegister));

        HttpContext ctxEcho = http.createContext("/api/echo", Server::handleEcho);
        HttpContext secured1 = http.createContext("/secured/index.html", Server::handleFile);

        SessionFilter sessionFilter = new SessionFilter();
        ctxEcho.getFilters().add(sessionFilter);
        secured1.getFilters().add(sessionFilter);

        contexts.addAll(List.of(ctxEcho, secured1));

        for (HttpContext ctx : contexts) {
            ctx.getFilters().add(new ResponseSignerFilter());
        }

        http.setExecutor(null);
        http.start();
        System.out.println("HTTP server running on http://0.0.0.0:8080");
    }

    private static void handleFile(HttpExchange ex) {
        try {
            String path = ex.getRequestURI().getPath();
            if ("/".equals(path)) path = "/login.html";

            File file = new File("www" + path);
            if (!file.exists() || file.isDirectory()) {
                ex.setAttribute("handlerResult", HandlerResult.text(404, "Not Found"));
                return;
            }

            if (path.startsWith("/unsigned/") || path.equals("/baseline.html")) {
                ex.setAttribute("disableSigning", Boolean.TRUE);
            }

            byte[] data = Files.readAllBytes(file.toPath());
            String ct = contentType(path);
            ex.setAttribute("handlerResult", HandlerResult.bytes(200, ct, data));
        } catch (Exception e) {
            ex.setAttribute("handlerResult", HandlerResult.error(e.toString()));
        }
    }

    private static void handleSigPub(HttpExchange ex) {
        try {
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
            String tamper = getQueryParam(ex.getRequestURI().getRawQuery(), "tamper");

            String n = b64urlUnsigned(JWE_PUB.getModulus().toByteArray());
            String e = b64urlUnsigned(JWE_PUB.getPublicExponent().toByteArray());
            String body = "{\"kty\":\"RSA\",\"kid\":\"" + JWE_KID + "\",\"n\":\"" + n + "\",\"e\":\"" + e + "\"}";

            if (tamper != null && !tamper.isBlank() && !"normal".equalsIgnoreCase(tamper)) {
                ex.setAttribute("tamperMode", tamper.toLowerCase(Locale.ROOT));
            }

            ex.setAttribute("handlerResult", HandlerResult.json(body));
        } catch (Exception e) {
            ex.setAttribute("handlerResult", HandlerResult.error(e.toString()));
        }
    }

    private static void handleReqKeyRegister(HttpExchange ex) {
        try {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
                ex.setAttribute("handlerResult", HandlerResult.text(405, "Method Not Allowed"));
                return;
            }

            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            Map<String, Object> req = tryParseJsonMap(body);

            String kid = stringValue(req.get("kid"));
            String suppliedThumbprint = stringValue(req.get("jwkThumbprint"));
            String proofB64 = stringValue(req.get("proof"));
            Object jwkObj = req.get("jwk");

            if (kid == null || kid.isBlank() || suppliedThumbprint == null || suppliedThumbprint.isBlank() ||
                    proofB64 == null || proofB64.isBlank() || jwkObj == null) {
                ex.setAttribute("handlerResult", HandlerResult.text(400, "Missing kid/jwk/jwkThumbprint/proof"));
                return;
            }

            String jwkJson = MAPPER.writeValueAsString(jwkObj);
            RsaJsonWebKey clientJwk = (RsaJsonWebKey) JsonWebKey.Factory.newJwk(jwkJson);
            RSAPublicKey clientPub = (RSAPublicKey) clientJwk.getPublicKey();

            String computedThumbprint = computeReqSignJwkThumbprint(clientJwk);
            if (!computedThumbprint.equals(suppliedThumbprint)) {
                ex.setAttribute("handlerResult", HandlerResult.text(400, "JWK thumbprint mismatch"));
                return;
            }

            String proofBase = buildReqKeyRegistrationProofBase(kid, computedThumbprint);
            if (!verifyReqKeyRegistrationProof(clientPub, proofBase, proofB64)) {
                ex.setAttribute("handlerResult", HandlerResult.text(401, "Bad registration proof"));
                return;
            }

            CLIENT_REQ_PUBS.put(kid, clientPub);

            String resp =
                    "{"
                            + "\"ok\":true,"
                            + "\"acceptedKid\":\"" + json(kid) + "\","
                            + "\"acceptedThumbprint\":\"" + json(computedThumbprint) + "\""
                            + "}";

            ex.setAttribute("handlerResult", HandlerResult.json(resp));
        } catch (Exception e) {
            ex.setAttribute("handlerResult", HandlerResult.error(e.toString()));
        }
    }

    private static boolean verifyClientSignedRequest(HttpExchange ex, byte[] bodyBytes) {
        try {
            String kid = headerFirst(ex, "X-client-key-id");
            String created = headerFirst(ex, "X-req-created");
            String cd = headerFirst(ex, "X-req-content-digest");
            String sigB64 = headerFirst(ex, "X-req-signature");

            if (kid == null || created == null || cd == null || sigB64 == null) {
                return false;
            }

            long createdSec;
            try {
                createdSec = Long.parseLong(created);
            } catch (Exception e) {
                return false;
            }

            long nowSec = System.currentTimeMillis() / 1000L;
            if (Math.abs(nowSec - createdSec) > 300) {
                return false;
            }

            RSAPublicKey pub = CLIENT_REQ_PUBS.get(kid);
            if (pub == null) {
                return false;
            }

            String expectedCd = "sha-256=:" + Base64.getEncoder().encodeToString(sha256(bodyBytes)) + ":";
            if (!expectedCd.equals(cd)) {
                return false;
            }

            String method = ex.getRequestMethod().toLowerCase(Locale.ROOT);
            String target = ex.getRequestURI().toString();

            String base =
                    "\"@method\": \"" + method + "\"\n" +
                            "\"@target-uri\": \"" + target + "\"\n" +
                            "\"x-req-created\": " + created + "\n" +
                            "\"x-req-content-digest\": " + cd + "\n" +
                            "\"x-client-key-id\": " + kid;

            Signature s = Signature.getInstance("RSASSA-PSS");
            s.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
            s.initVerify(pub);
            s.update(base.getBytes(StandardCharsets.UTF_8));
            return s.verify(Base64.getDecoder().decode(sigB64));
        } catch (Exception e) {
            return false;
        }
    }

    private static double verifyClientSignedRequestTimed(HttpExchange ex, byte[] bodyBytes) {
        long t0 = System.nanoTime();
        boolean ok = verifyClientSignedRequest(ex, bodyBytes);
        double ms = (System.nanoTime() - t0) / 1_000_000.0;
        ex.getResponseHeaders().set("X-Metric-Req-Verify-Ms", formatMs(ms));
        return ok ? ms : -1.0;
    }

    private static void handleMetrics(HttpExchange ex) {
        try {
            if ("OPTIONS".equalsIgnoreCase(ex.getRequestMethod())) {
                ex.setAttribute("disableSigning", Boolean.TRUE);
                ex.setAttribute("handlerResult", HandlerResult.text(204, ""));
                return;
            }

            ex.setAttribute("disableSigning", Boolean.TRUE);

            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
                ex.setAttribute("handlerResult", HandlerResult.text(405, "Method Not Allowed"));
                return;
            }

            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            if (body.isBlank()) {
                ex.setAttribute("handlerResult", HandlerResult.text(400, "Empty body"));
                return;
            }

            appendNdjson(body);
            ex.setAttribute("handlerResult", HandlerResult.json("{\"ok\":true}"));
        } catch (Exception e) {
            ex.setAttribute("handlerResult", HandlerResult.error(e.toString()));
        }
    }

    private static void handleLoginPlain(HttpExchange ex) {
        try {
            ex.setAttribute("disableSigning", Boolean.TRUE);

            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
                ex.setAttribute("handlerResult", HandlerResult.text(405, "Method Not Allowed"));
                return;
            }

            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            Map<String, Object> bodyMap = tryParseJsonMap(body);

            String user = bodyMap.getOrDefault("username", "").toString();
            String pass = bodyMap.getOrDefault("password", "").toString();

            boolean success = "alice".equals(user) && "secret".equals(pass);
            String respJson = success ? "{\"ok\":true}" : "{\"ok\":false}";
            HandlerResult hr = HandlerResult.json(respJson);

            int reqHeaderBytes = approximateRequestHeaderBytes(ex);
            int reqBodyBytes = utf8Bytes(body);

            ex.getResponseHeaders().set("X-Metric-Req-Header-Bytes", String.valueOf(reqHeaderBytes));
            ex.getResponseHeaders().set("X-Metric-Req-Body-Bytes", String.valueOf(reqBodyBytes));

            ex.setAttribute("handlerResult", hr);
        } catch (Exception e) {
            ex.setAttribute("handlerResult", HandlerResult.error(e.toString()));
        }
    }

    private static void handleLogin(HttpExchange ex) {
        try {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
                ex.setAttribute("handlerResult", HandlerResult.text(405, "Method Not Allowed"));
                return;
            }

            byte[] bodyBytes = ex.getRequestBody().readAllBytes();
            String body = new String(bodyBytes, StandardCharsets.UTF_8);

            logReqSigningHeaders(ex, "/api/login");

            double verifyMs = verifyClientSignedRequestTimed(ex, bodyBytes, "/api/login");
            if (verifyMs < 0) {
                ex.setAttribute("handlerResult", HandlerResult.text(401, "Bad client request signature"));
                return;
            }

            String usernameEnc = jsonField(body, "username");
            String passwordEnc = jsonField(body, "password");

            long decStart = System.nanoTime();
            String user = tryDecryptAndValidate(usernameEnc);
            String pass = tryDecryptAndValidate(passwordEnc);
            double decryptMs = (System.nanoTime() - decStart) / 1_000_000.0;

            boolean success = "alice".equals(user) && "secret".equals(pass);
            HandlerResult hr;

            if (success) {
                long now = System.currentTimeMillis() / 1000L;
                long exp = now + 1800;
                String session = "{\"u\":\"" + json(user) + "\",\"role\":\"admin\",\"iat\":" + now + ",\"exp\":" + exp + "}";
                String cookieVal = jweEncrypt(session);
                CookieOptions opts = CookieOptions.defaultSession(1800);
                setCookie(ex, "sess", cookieVal, opts);
                hr = HandlerResult.json("{\"ok\":true}");
            } else {
                hr = HandlerResult.json("{\"ok\":false}");
            }

            int reqHeaderBytes = approximateRequestHeaderBytes(ex);
            int reqBodyBytes = bodyBytes.length;
            int reqSignHeaderBytes = approximateRequestSigningHeaderBytes(ex);

            ex.getResponseHeaders().set("X-Metric-Req-Header-Bytes", String.valueOf(reqHeaderBytes));
            ex.getResponseHeaders().set("X-Metric-Req-Body-Bytes", String.valueOf(reqBodyBytes));
            ex.getResponseHeaders().set("X-Metric-Req-Sign-Header-Bytes", String.valueOf(reqSignHeaderBytes));
            ex.getResponseHeaders().set("X-Metric-Decrypt-Ms", formatMs(decryptMs));

            ex.setAttribute("handlerResult", hr);
        } catch (Exception e) {
            ex.setAttribute("handlerResult", HandlerResult.error(e.toString()));
        }
    }

    private static void handleEcho(HttpExchange ex) {
        try {
            byte[] rawBytes = ex.getRequestBody().readAllBytes();
            String rawBody = new String(rawBytes, StandardCharsets.UTF_8);

            logReqSigningHeaders(ex, "/api/echo");

            double verifyMs = verifyClientSignedRequestTimed(ex, rawBytes, "/api/echo");
            if (verifyMs < 0) {
                ex.setAttribute("handlerResult", HandlerResult.text(401, "Bad client request signature"));
                return;
            }

            Map<String, Object> resp = new LinkedHashMap<>();

            Map<String, Object> req = new LinkedHashMap<>();
            req.put("method", ex.getRequestMethod());
            req.put("path", ex.getRequestURI().toString());
            resp.put("request", req);

            Map<String, Object> session = new LinkedHashMap<>();
            session.put("user", ex.getAttribute("session.user"));
            resp.put("session", session);

            Map<String, Object> client = new LinkedHashMap<>();
            client.put("origin", headerFirst(ex, "Origin"));
            client.put("referer", headerFirst(ex, "Referer"));
            client.put("userAgent", headerFirst(ex, "User-agent"));
            client.put("xForwardedFor", headerFirst(ex, "X-forwarded-for"));
            client.put("xForwardedProto", headerFirst(ex, "X-forwarded-proto"));
            client.put("xForwardedHost", headerFirst(ex, "X-forwarded-host"));
            client.put("xForwardedServer", headerFirst(ex, "X-forwarded-server"));
            resp.put("client", client);

            Map<String, Object> headers = new LinkedHashMap<>();
            headers.put("interesting", pickInterestingHeaders(ex));
            headers.put("all", flattenHeaders(ex.getRequestHeaders()));
            resp.put("headers", headers);

            Object parsedBody = tryParseJson(rawBody);
            resp.put("body", parsedBody);

            Map<String, Object> decrypted = new LinkedHashMap<>();
            List<String> notes = new ArrayList<>();

            if (parsedBody instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> bodyMap = (Map<String, Object>) parsedBody;
                decryptIfJweString(bodyMap, "name", decrypted, notes);
                decryptIfJweString(bodyMap, "message", decrypted, notes);
                decryptIfJweString(bodyMap, "username", decrypted, notes);
                decryptIfJweString(bodyMap, "password", decrypted, notes);
            } else {
                notes.add("Body is not a JSON object; cannot field-decrypt.");
            }

            String encHdr = headerFirst(ex, "X-Enc-X-Custom");
            if (encHdr != null) {
                String dec = tryDecryptAndValidate("JWE: " + encHdr);
                if (dec != null) decrypted.put("X-Enc-X-Custom", dec);
                else notes.add("Failed to decrypt header X-Enc-X-Custom");
            }

            String json = MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(resp);

            ex.getResponseHeaders().set("X-Metric-Req-Header-Bytes", String.valueOf(approximateRequestHeaderBytes(ex)));
            ex.getResponseHeaders().set("X-Metric-Req-Body-Bytes", String.valueOf(rawBytes.length));
            ex.getResponseHeaders().set("X-Metric-Req-Sign-Header-Bytes", String.valueOf(approximateRequestSigningHeaderBytes(ex)));

            ex.setAttribute("handlerResult", HandlerResult.json(json));
        } catch (Exception e) {
            ex.setAttribute("handlerResult", HandlerResult.error(e.toString()));
        }
    }

    static class ResponseSignerFilter extends Filter {
        public String description() { return "Signs responses and adds metric headers"; }

        public void doFilter(HttpExchange ex, Chain chain) throws IOException {
            chain.doFilter(ex);

            HandlerResult result = (HandlerResult) ex.getAttribute("handlerResult");
            if (result == null) result = HandlerResult.text(500, "Missing response");

            boolean disableSigning = Boolean.TRUE.equals(ex.getAttribute("disableSigning"))
                    || ex.getRequestURI().getPath().equals("/metrics")
                    || ex.getRequestURI().getPath().equals("/api/login_plain")
                    || ex.getRequestURI().getPath().startsWith("/unsigned/");

            Headers h = ex.getResponseHeaders();

            if (disableSigning) {
                h.set("Content-Type", result.contentType);
                h.set("Connection", "close");

                int headerBytes = approximateResponseHeaderBytes(h, result.body.length, false);
                h.set("X-Metric-Resp-Header-Bytes", String.valueOf(headerBytes));
                h.set("X-Metric-Resp-Body-Bytes", String.valueOf(result.body.length));
                h.set("X-Metric-Resp-Total-Bytes", String.valueOf(headerBytes + result.body.length));

                ex.sendResponseHeaders(result.status, result.body.length);
                try (OutputStream os = ex.getResponseBody()) {
                    os.write(result.body);
                }
                return;
            }

            String tamper = (String) ex.getAttribute("tamperMode");

            byte[] originalBody = result.body;
            int status = result.status;

            String digestHeader = "sha-256=:" + Base64.getEncoder().encodeToString(sha256(originalBody)) + ":";
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
            long signStart = System.nanoTime();
            try {
                byte[] sig = signPss(base.getBytes(StandardCharsets.US_ASCII), SIG_PRIV);
                sigB64 = Base64.getEncoder().encodeToString(sig);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            double signMs = (System.nanoTime() - signStart) / 1_000_000.0;

            byte[] sendBody = originalBody;
            String sendDigest = digestHeader;
            String sendSigB64 = sigB64;

            boolean tSig = "signature".equals(tamper) || "all".equals(tamper);
            boolean tDig = "digest".equals(tamper) || "all".equals(tamper);
            boolean tBody = "body".equals(tamper) || "all".equals(tamper);

            if (tBody) {
                if (result.contentType.startsWith("application/json") || result.contentType.startsWith("text/") || result.contentType.contains("javascript")) {
                    String s = new String(originalBody, StandardCharsets.UTF_8) + " ";
                    sendBody = s.getBytes(StandardCharsets.UTF_8);
                } else if (originalBody.length > 0) {
                    sendBody = Arrays.copyOf(originalBody, originalBody.length);
                    sendBody[sendBody.length - 1] ^= 0x01;
                }
            }

            if (tDig) {
                sendDigest = "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:";
            }

            if (tSig) {
                sendSigB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
            }

            h.set("Content-Type", result.contentType);
            h.set("Connection", "close");
            h.set("Content-Digest", sendDigest);
            h.set("Signature-Input", "sig1=" + sigInput);
            h.set("Signature", "sig1=:" + sendSigB64 + ":");
            h.set("X-Metric-Sign-Ms", formatMs(signMs));
            h.set("X-Metric-Resp-Body-Bytes", String.valueOf(sendBody.length));

            int headerBytes = approximateResponseHeaderBytes(h, sendBody.length, true);
            h.set("X-Metric-Resp-Header-Bytes", String.valueOf(headerBytes));
            h.set("X-Metric-Resp-Total-Bytes", String.valueOf(headerBytes + sendBody.length));

            ex.sendResponseHeaders(status, sendBody.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(sendBody);
            }
        }
    }

    static class SessionFilter extends Filter {
        public String description(){ return "sess"; }

        public void doFilter(HttpExchange ex, Chain c) throws IOException {
            String s = getCookie(ex, "sess");
            if (s != null) {
                String p = jweDecrypt(s);
                if (p != null) ex.setAttribute("session.user", jsonField(p,"u"));
            }
            c.doFilter(ex);
        }
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

    static String getCookie(HttpExchange ex, String name) {
        List<String> headers = ex.getRequestHeaders().get("Cookie");
        if (headers == null) return null;
        for (String h : headers) {
            for (String part : h.split(";")) {
                String[] nv = part.trim().split("=", 2);
                if (nv.length == 2 && nv[0].trim().equals(name)) return nv[1].trim();
            }
        }
        return null;
    }

    private static void rotateJweKeypair() throws Exception {
        RsaJsonWebKey j = RsaJwkGenerator.generateJwk(2048);
        JWE_PUB = (RSAPublicKey) j.getPublicKey();
        JWE_PRIV = (RSAPrivateKey) j.getPrivateKey();
    }

    private static String jweEncrypt(String json) throws JoseException {
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setPayload(json);
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
        jwe.setKey(JWE_PUB);
        jwe.setKeyIdHeaderValue(JWE_KID);
        return jwe.getCompactSerialization();
    }

    private static String jweDecrypt(String compact) {
        try {
            JsonWebEncryption jwe = new JsonWebEncryption();
            jwe.setCompactSerialization(compact);
            jwe.setKey(JWE_PRIV);
            return jwe.getPayload();
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] sha256(byte[] in) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(in);
        } catch (Exception e) {
            return new byte[0];
        }
    }

    private static byte[] signPss(byte[] input, PrivateKey key) throws Exception {
        Signature s = Signature.getInstance("RSASSA-PSS");
        s.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        s.initSign(key);
        s.update(input);
        return s.sign();
    }

    private static String b64urlUnsigned(byte[] in) {
        if (in.length > 1 && in[0] == 0) in = Arrays.copyOfRange(in, 1, in.length);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(in);
    }

    private static String buildReqKeyRegistrationProofBase(String kid, String thumbprint) {
        return "\"kid\": \"" + kid + "\"\n" +
                "\"thumbprint\": \"" + thumbprint + "\"";
    }

    private static String computeReqSignJwkThumbprint(RsaJsonWebKey jwk) throws Exception {
        RSAPublicKey pub = (RSAPublicKey) jwk.getPublicKey();
        String n = b64urlUnsigned(pub.getModulus().toByteArray());
        String e = b64urlUnsigned(pub.getPublicExponent().toByteArray());
        String canonical = "{\"e\":\"" + e + "\",\"kty\":\"RSA\",\"n\":\"" + n + "\"}";
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private static boolean verifyReqKeyRegistrationProof(RSAPublicKey pub, String proofBase, String proofB64) {
        try {
            Signature s = Signature.getInstance("RSASSA-PSS");
            s.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
            s.initVerify(pub);
            s.update(proofBase.getBytes(StandardCharsets.UTF_8));
            return s.verify(Base64.getDecoder().decode(proofB64));
        } catch (Exception e) {
            return false;
        }
    }

    private static String jsonField(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"(.*?)\"", Pattern.DOTALL).matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private static String tryDecryptAndValidate(String enc) {
        if (enc == null) return null;
        if (enc.startsWith("JWE: ")) {
            enc = enc.substring(5).trim();
        }
        String payload = jweDecrypt(enc);
        if (payload != null && isSafeString(payload)) return payload;
        return null;
    }

    private static boolean isSafeString(String input) {
        if (input == null || input.length() > 10000) return false;
        String lower = input.toLowerCase(Locale.ROOT);
        String[] sql = {"select", "insert", "update", "delete", "--", ";drop ", "xp_"};
        for (String k : sql) if (lower.contains(k)) return false;
        String[] xss = {"<script", "javascript:", "onerror", "onload", "<img", "<iframe"};
        for (String x : xss) if (lower.contains(x)) return false;
        return true;
    }

    private static String json(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }

    private static String contentType(String path) {
        if (path.endsWith(".html")) return "text/html; charset=utf-8";
        if (path.endsWith(".css"))  return "text/css; charset=utf-8";
        if (path.endsWith(".js"))   return "application/javascript; charset=utf-8";
        if (path.endsWith(".json")) return "application/json; charset=utf-8";
        if (path.endsWith(".png"))  return "image/png";
        if (path.endsWith(".jpg") || path.endsWith(".jpeg")) return "image/jpeg";
        if (path.endsWith(".webp")) return "image/webp";
        if (path.endsWith(".svg"))  return "image/svg+xml";
        return "application/octet-stream";
    }

    private static Map<String, Object> tryParseJsonMap(String raw) throws IOException {
        return MAPPER.readValue(raw, new TypeReference<Map<String, Object>>() {});
    }

    private static Object tryParseJson(String raw) {
        try {
            return MAPPER.readValue(raw, Object.class);
        } catch (Exception ignored) {
            return raw;
        }
    }

    private static void decryptIfJweString(
            Map<String, Object> bodyMap,
            String field,
            Map<String, Object> decryptedOut,
            List<String> notes
    ) {
        Object v = bodyMap.get(field);
        if (!(v instanceof String)) return;

        String s = (String) v;
        if (!s.startsWith("JWE: ")) return;

        String dec = tryDecryptAndValidate(s);
        if (dec != null) {
            decryptedOut.put(field, dec);
        } else {
            decryptedOut.put(field, "[decrypt failed]");
            notes.add("Failed to decrypt field: " + field);
        }
    }

    private static String headerFirst(HttpExchange ex, String name) {
        List<String> v = ex.getRequestHeaders().get(name);
        return (v == null || v.isEmpty()) ? null : v.get(0);
    }

    private static Map<String, Object> flattenHeaders(Headers h) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> e : h.entrySet()) {
            if (e.getValue() == null) continue;
            if ("Cookie".equalsIgnoreCase(e.getKey())) {
                out.put("Cookie", "[redacted]");
                continue;
            }
            out.put(e.getKey(), e.getValue().size() == 1 ? e.getValue().get(0) : e.getValue());
        }
        return out;
    }

    private static Map<String, Object> pickInterestingHeaders(HttpExchange ex) {
        Map<String, Object> m = new LinkedHashMap<>();
        String[] keys = new String[] {
                "Host", "Origin", "Referer",
                "X-forwarded-for", "X-forwarded-proto", "X-forwarded-host", "X-forwarded-server",
                "Content-type", "Content-length",
                "X-custom", "X-Enc-X-Custom",
                "Tailscale-user-name", "Tailscale-user-login",
                "X-Run-Tag", "X-Req-Seq", "X-Bench-Kind",
                "X-Client-Key-Id", "X-Req-Created", "X-Req-Content-Digest", "X-Req-Signature"
        };
        for (String k : keys) {
            String v = headerFirst(ex, k);
            if (v != null) m.put(k, v);
        }
        return m;
    }

    private static String getQueryParam(String rawQuery, String key) {
        if (rawQuery == null) return null;
        for (String part : rawQuery.split("&")) {
            String[] kv = part.split("=", 2);
            if (kv.length >= 1 && kv[0].equals(key)) {
                return kv.length == 2 ? urlDecode(kv[1]) : "";
            }
        }
        return null;
    }

    private static String urlDecode(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return s;
        }
    }

    private static int utf8Bytes(String s) {
        return s == null ? 0 : s.getBytes(StandardCharsets.UTF_8).length;
    }

    private static String stringValue(Object v) {
        return v == null ? null : String.valueOf(v);
    }

    private static int approximateRequestHeaderBytes(HttpExchange ex) {
        int total = 0;
        for (Map.Entry<String, List<String>> e : ex.getRequestHeaders().entrySet()) {
            String k = e.getKey();
            if (e.getValue() == null) continue;
            for (String v : e.getValue()) {
                total += utf8Bytes(k) + 2 + utf8Bytes(v) + 1;
            }
        }
        total += 1;
        return total;
    }

    private static int approximateRequestSigningHeaderBytes(HttpExchange ex) {
        String[] keys = new String[] {
                "X-client-key-id",
                "X-req-created",
                "X-req-content-digest",
                "X-req-signature"
        };

        int total = 0;
        for (String k : keys) {
            List<String> vals = ex.getRequestHeaders().get(k);
            if (vals == null) continue;
            for (String v : vals) {
                total += utf8Bytes(k) + 2 + utf8Bytes(v) + 1;
            }
        }
        total += 1;
        return total;
    }

    private static int approximateResponseHeaderBytes(Headers h, int bodyLen, boolean signed) {
        int total = 0;
        for (Map.Entry<String, List<String>> e : h.entrySet()) {
            String k = e.getKey();
            if (e.getValue() == null) continue;
            for (String v : e.getValue()) {
                total += utf8Bytes(k) + 2 + utf8Bytes(v) + 1;
            }
        }
        total += utf8Bytes("Content-Length") + 2 + utf8Bytes(String.valueOf(bodyLen)) + 1;
        if (!h.containsKey("Connection")) {
            total += utf8Bytes("Connection") + 2 + utf8Bytes("close") + 1;
        }
        total += 1;
        return total;
    }

    private static String formatMs(double ms) {
        return String.format(Locale.US, "%.3f", ms);
    }

    private static synchronized void appendNdjson(String line) throws IOException {
        Files.createDirectories(METRICS_DIR);
        Files.writeString(
                METRICS_FILE,
                line.strip() + System.lineSeparator(),
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
                StandardOpenOption.APPEND
        );
    }

    private static void logReqSigningHeaders(HttpExchange ex, String endpoint) {
        System.out.println("---- REQUEST SIGN HEADERS [" + endpoint + "] ----");
        System.out.println("method = " + ex.getRequestMethod());
        System.out.println("path   = " + ex.getRequestURI());

        System.out.println("X-Client-Key-Id      = " + headerFirst(ex, "X-Client-Key-Id"));
        System.out.println("X-Req-Created        = " + headerFirst(ex, "X-Req-Created"));
        System.out.println("X-Req-Content-Digest = " + headerFirst(ex, "X-Req-Content-Digest"));

        String sig = headerFirst(ex, "X-Req-Signature");
        if (sig == null) {
            System.out.println("X-Req-Signature      = null");
        } else {
            String shortSig = sig.length() <= 80 ? sig : sig.substring(0, 40) + " ... " + sig.substring(sig.length() - 24);
            System.out.println("X-Req-Signature      = " + shortSig + " (len=" + sig.length() + ")");
        }

        System.out.println("----------------------------------------------");
    }

    private static String verifyClientSignedRequestDetailed(HttpExchange ex, byte[] bodyBytes) {
        try {
            String kid = headerFirst(ex, "X-client-key-id");
            String created = headerFirst(ex, "X-req-created");
            String cd = headerFirst(ex, "X-req-content-digest");
            String sigB64 = headerFirst(ex, "X-req-signature");

            if (kid == null || kid.isBlank()) return "missing X-Client-Key-Id";
            if (created == null || created.isBlank()) return "missing X-Req-Created";
            if (cd == null || cd.isBlank()) return "missing X-Req-Content-Digest";
            if (sigB64 == null || sigB64.isBlank()) return "missing X-Req-Signature";

            long createdSec;
            try {
                createdSec = Long.parseLong(created);
            } catch (Exception e) {
                return "bad X-Req-Created";
            }

            long nowSec = System.currentTimeMillis() / 1000L;
            if (Math.abs(nowSec - createdSec) > 300) {
                return "X-Req-Created outside allowed window";
            }

            RSAPublicKey pub = CLIENT_REQ_PUBS.get(kid);
            if (pub == null) {
                return "unknown client key id: " + kid;
            }

            String expectedCd = "sha-256=:" + Base64.getEncoder().encodeToString(sha256(bodyBytes)) + ":";
            if (!expectedCd.equals(cd)) {
                return "content digest mismatch";
            }

            String method = ex.getRequestMethod().toLowerCase(Locale.ROOT);
            String target = ex.getRequestURI().toString();

            String base =
                    "\"@method\": \"" + method + "\"\n" +
                            "\"@target-uri\": \"" + target + "\"\n" +
                            "\"x-req-created\": " + created + "\n" +
                            "\"x-req-content-digest\": " + cd + "\n" +
                            "\"x-client-key-id\": " + kid;

            Signature s = Signature.getInstance("RSASSA-PSS");
            s.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
            s.initVerify(pub);
            s.update(base.getBytes(StandardCharsets.UTF_8));

            boolean ok = s.verify(Base64.getDecoder().decode(sigB64));
            return ok ? null : "signature verification failed";
        } catch (Exception e) {
            return "verification exception: " + e.getMessage();
        }
    }

    private static double verifyClientSignedRequestTimed(HttpExchange ex, byte[] bodyBytes, String endpoint) {
        long t0 = System.nanoTime();

        String err = verifyClientSignedRequestDetailed(ex, bodyBytes);
        boolean ok = (err == null);

        double ms = (System.nanoTime() - t0) / 1_000_000.0;
        ex.getResponseHeaders().set("X-Metric-Req-Verify-Ms", formatMs(ms));

        if (ok) {
            System.out.println("[REQ-SIGN OK] endpoint=" + endpoint + " verifyMs=" + formatMs(ms));
        } else {
            System.out.println("[REQ-SIGN FAIL] endpoint=" + endpoint + " verifyMs=" + formatMs(ms) + " reason=" + err);
        }

        return ok ? ms : -1.0;
    }

    static class HandlerResult {
        int status;
        String contentType;
        byte[] body;

        static HandlerResult json(String body) {
            return new HandlerResult(200, "application/json; charset=utf-8", body.getBytes(StandardCharsets.UTF_8));
        }

        static HandlerResult text(int status, String msg) {
            return new HandlerResult(status, "text/plain; charset=utf-8", msg.getBytes(StandardCharsets.UTF_8));
        }

        static HandlerResult bytes(int status, String ct, byte[] b) {
            return new HandlerResult(status, ct, b);
        }

        static HandlerResult error(String msg) {
            return json("{\"error\":\"" + json(msg) + "\"}");
        }

        HandlerResult(int status, String contentType, byte[] body) {
            this.status = status;
            this.contentType = contentType;
            this.body = body;
        }
    }
}