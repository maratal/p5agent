// Hello World demo — Java 11+, JDK only (Maven builds it into app.jar; the
// installer runs it with the java type's default "java -jar app.jar").
//
// GET shows a name form; POST answers "Hello, <name>!" in the middle of the page.
// Listens on $HOST:$PORT (default 0.0.0.0:8080) and serves HTTPS when the
// installer has put TLS_CERT_PATH / TLS_KEY_PATH in the environment.
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.Executors;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

public class App {
    static final String RUNTIME = "Java";
    static final String FORM = "<h1>Hello World</h1><form method=\"post\">"
            + "<input name=\"name\" placeholder=\"Your name\" autofocus required>"
            + "<button type=\"submit\">Say hello</button></form>";
    static String template;

    static String escapeHtml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#x27;");
    }

    static String greeting(String name) {
        return "<h1>Hello, " + escapeHtml(name) + "!</h1><a href=\"/\">Say hello again</a>";
    }

    static String page(String content) {
        return template.replace("{{runtime}}", RUNTIME).replace("{{content}}", content);
    }

    static String formValue(String body, String field) {
        for (String pair : body.split("&")) {
            int eq = pair.indexOf('=');
            String k = eq < 0 ? pair : pair.substring(0, eq);
            if (URLDecoder.decode(k, StandardCharsets.UTF_8).equals(field)) {
                return eq < 0 ? "" : URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            }
        }
        return "";
    }

    static void handle(HttpExchange ex) throws IOException {
        String content = FORM;
        if ("POST".equals(ex.getRequestMethod())) {
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String name = formValue(body, "name").trim();
            content = greeting(name.isEmpty() ? "World" : name);
        }
        byte[] out = page(content).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        ex.sendResponseHeaders(200, out.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(out);
        }
    }

    // PEM certificate chain + PKCS#8 key (what both the installer's self-signed
    // certificate and Let's Encrypt produce) → an SSLContext.
    static SSLContext tlsContext(String certPath, String keyPath) throws Exception {
        Certificate[] chain = CertificateFactory.getInstance("X.509")
                .generateCertificates(new ByteArrayInputStream(Files.readAllBytes(Path.of(certPath))))
                .toArray(new Certificate[0]);
        String pem = Files.readString(Path.of(keyPath));
        if (!pem.contains("BEGIN PRIVATE KEY")) {
            throw new IllegalArgumentException(keyPath + " is not a PKCS#8 key (BEGIN PRIVATE KEY)");
        }
        byte[] der = Base64.getMimeDecoder().decode(pem
                .replaceAll("-----(BEGIN|END) PRIVATE KEY-----", "").replaceAll("\\s", ""));
        PrivateKey key;
        try {
            key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception notRsa) {
            key = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(der));
        }
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("app", key, new char[0], chain);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        return ctx;
    }

    static String env(String key, String fallback) {
        String v = System.getenv(key);
        return v == null || v.isEmpty() ? fallback : v;
    }

    public static void main(String[] args) throws Exception {
        template = Files.readString(Path.of("hello.html"));
        String host = env("HOST", "0.0.0.0");
        int port = Integer.parseInt(env("PORT", "8080"));
        String cert = env("TLS_CERT_PATH", ""), key = env("TLS_KEY_PATH", "");
        InetSocketAddress addr = new InetSocketAddress(host, port);
        HttpServer server;
        String scheme = "http";
        if (!cert.isEmpty() && !key.isEmpty()) {
            HttpsServer https = HttpsServer.create(addr, 0);
            https.setHttpsConfigurator(new HttpsConfigurator(tlsContext(cert, key)));
            server = https;
            scheme = "https";
        } else {
            server = HttpServer.create(addr, 0);
        }
        server.createContext("/", App::handle);
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println("Hello World (" + RUNTIME + ") listening on " + scheme + "://" + host + ":" + port);
    }
}
