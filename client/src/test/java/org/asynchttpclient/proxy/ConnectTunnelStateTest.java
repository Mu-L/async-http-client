/*
 *    Copyright (c) 2026 AsyncHttpClient Project. All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
package org.asynchttpclient.proxy;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.Realm;
import org.asynchttpclient.Response;
import org.eclipse.jetty.proxy.ConnectHandler;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static org.asynchttpclient.Dsl.asyncHttpClient;
import static org.asynchttpclient.Dsl.basicAuthRealm;
import static org.asynchttpclient.Dsl.config;
import static org.asynchttpclient.Dsl.ntlmAuthRealm;
import static org.asynchttpclient.Dsl.proxyServer;
import static org.asynchttpclient.Dsl.scramSha256AuthRealm;
import static org.asynchttpclient.test.TestUtils.addHttpConnector;
import static org.asynchttpclient.test.TestUtils.addHttpsConnector;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A CONNECT the proxy did not accept leaves the socket exactly as it was: plaintext, and pointed at the
 * proxy rather than the origin. The client used to infer "the tunnel is up" from the last request having
 * been a CONNECT, which is equally true of a rejected one, so a proxy that answered CONNECT with a 401 or a
 * redirect got the origin request — {@code Authorization} header and all — replayed to it in the clear on
 * that same socket.
 * <p>
 * The proxies here are raw sockets rather than a servlet container so the tests can assert on the exact
 * bytes that reached the proxy.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class ConnectTunnelStateTest {

    private static final String ORIGIN_USER = "origin-user";
    private static final String ORIGIN_PASSWORD = "origin-secret";
    private static final String PROXY_USER = "proxy-user";
    private static final String PROXY_PASSWORD = "proxy-secret";

    private static final String CONNECT_401 = "HTTP/1.1 401 Unauthorized\r\n"
            + "WWW-Authenticate: Basic realm=\"origin\"\r\n"
            + "Content-Length: 0\r\n"
            + "Connection: keep-alive\r\n\r\n";

    private static final String CONNECT_302 = "HTTP/1.1 302 Found\r\n"
            + "Location: /elsewhere\r\n"
            + "Content-Length: 0\r\n"
            + "Connection: keep-alive\r\n\r\n";

    // Anything the proxy is asked for after the rejected CONNECT. Terminates the exchange promptly so a
    // leaked follow-up request is observed rather than waited out.
    private static final String ANYTHING_ELSE = "HTTP/1.1 403 Forbidden\r\n"
            + "Content-Length: 0\r\n"
            + "Connection: keep-alive\r\n\r\n";

    private static String origin407(String challenge) {
        return "HTTP/1.1 407 Proxy Authentication Required\r\n"
                + "Proxy-Authenticate: " + challenge + "\r\n"
                + "Content-Length: 0\r\n"
                + "Connection: keep-alive\r\n\r\n";
    }

    private static String basic(String user, String password) {
        return "Basic " + Base64.getEncoder().encodeToString((user + ':' + password).getBytes(ISO_8859_1));
    }

    // ---------------------------------------------------------------------------------------------------
    // (i) and (ii): a rejected CONNECT must not be mistaken for an established tunnel
    // ---------------------------------------------------------------------------------------------------

    @Test
    public void proxyAnswering401ToConnectNeverSeesTheOriginAuthorization() throws Exception {
        try (RecordingProxy proxy = RecordingProxy.rejectingConnectWith(CONNECT_401);
             // A non-preemptive realm is the default: the 401 interceptor is what turns it preemptive, and
             // it does so believing it is answering the ORIGIN.
             AsyncHttpClient client = asyncHttpClient(config()
                     .setRealm(basicAuthRealm(ORIGIN_USER, ORIGIN_PASSWORD))
                     .setProxyServer(proxyServer("localhost", proxy.port()).build())
                     .setRequestTimeout(Duration.ofSeconds(15)))) {

            Response response = client.prepareGet("https://origin.example.com/secret").execute().get(30, TimeUnit.SECONDS);

            proxy.assertNeverSaw("authorization");
            assertEquals(401, response.getStatusCode(), "the rejected CONNECT must be delivered as-is");
            assertEquals(1, proxy.requestHeads().size(),
                    "nothing may be replayed onto a socket the proxy refused to tunnel: " + proxy.requestHeads());
            assertTrue(proxy.requestHeads().get(0).startsWith("CONNECT "), proxy.requestHeads().get(0));
        }
    }

    @Test
    public void proxyAnswering302ToConnectNeverSeesTheOriginAuthorization() throws Exception {
        try (RecordingProxy proxy = RecordingProxy.rejectingConnectWith(CONNECT_302);
             AsyncHttpClient client = asyncHttpClient(config()
                     .setFollowRedirect(true)
                     // Preemptive: the credentials are on every origin request from the start, so a replay
                     // onto the plaintext hop exposes them without needing a challenge first.
                     .setRealm(basicAuthRealm(ORIGIN_USER, ORIGIN_PASSWORD).setUsePreemptiveAuth(true))
                     .setProxyServer(proxyServer("localhost", proxy.port()).build())
                     .setRequestTimeout(Duration.ofSeconds(15)))) {

            Response response = client.prepareGet("https://origin.example.com/secret").execute().get(30, TimeUnit.SECONDS);

            proxy.assertNeverSaw("authorization");
            assertEquals(302, response.getStatusCode(), "the rejected CONNECT must be delivered as-is");
            assertEquals(1, proxy.requestHeads().size(),
                    "a redirect a proxy attached to its CONNECT refusal must not be followed on the untunnelled "
                            + "socket: " + proxy.requestHeads());
        }
    }

    // ---------------------------------------------------------------------------------------------------
    // (iii): a 407 on a SOCKS connection came from the origin, not from a proxy
    // ---------------------------------------------------------------------------------------------------

    static Stream<Arguments> socksProxyRealms() {
        // The schemes whose 407 handling writes Proxy-Authorization straight onto the Request, which
        // newNettyRequest then copies verbatim -- downstream of the proxy-type gate that gates the header
        // it generates itself. NTLM hands the peer a handshake it gets to choose the challenge for; SCRAM
        // puts the username on the wire in the clear inside the client-first message.
        return Stream.of(
                Arguments.of("NTLM", "NTLM", ntlmAuthRealm(PROXY_USER, PROXY_PASSWORD)),
                Arguments.of("SCRAM-SHA-256", "SCRAM-SHA-256 realm=\"pretending-to-be-a-proxy\"",
                        scramSha256AuthRealm(PROXY_USER, PROXY_PASSWORD)));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("socksProxyRealms")
    public void socks407FromTheOriginDoesNotMintProxyCredentials(String name, String challenge, Realm.Builder proxyRealm)
            throws Exception {
        try (Socks5Origin socks = new Socks5Origin(origin407(challenge));
             AsyncHttpClient client = asyncHttpClient(config()
                     .setProxyServer(proxyServer("localhost", socks.port())
                             .setProxyType(ProxyType.SOCKS_V5)
                             .setRealm(proxyRealm))
                     .setRequestTimeout(Duration.ofSeconds(15)))) {

            // The SOCKS proxy tunnels at the transport layer, so this request is answered by the origin.
            Response response = client.prepareGet("http://localhost:1/resource").execute().get(30, TimeUnit.SECONDS);

            socks.assertNeverSaw("proxy-authorization");
            assertEquals(407, response.getStatusCode(), "a 407 from the origin must be delivered as-is");
            assertEquals(1, socks.requestHeads().size(),
                    "the origin must not be answered with proxy credentials: " + socks.requestHeads());
        }
    }

    // ---------------------------------------------------------------------------------------------------
    // (iv): an accepted CONNECT must still tunnel, and still carry the right credentials on each hop
    // ---------------------------------------------------------------------------------------------------

    private Server tunnellingProxy;
    private Server httpsOrigin;
    private int tunnellingProxyPort;
    private int httpsOriginPort;
    private final AtomicReference<String> connectProxyAuthorization = new AtomicReference<>();

    @BeforeAll
    public void startTunnellingServers() throws Exception {
        httpsOrigin = new Server();
        ServerConnector originConnector = addHttpsConnector(httpsOrigin);
        httpsOrigin.setHandler(new AuthEchoHandler());
        httpsOrigin.start();
        httpsOriginPort = originConnector.getLocalPort();

        tunnellingProxy = new Server();
        ServerConnector proxyConnector = addHttpConnector(tunnellingProxy);
        tunnellingProxy.setHandler(new RecordingConnectHandler());
        tunnellingProxy.start();
        tunnellingProxyPort = proxyConnector.getLocalPort();
    }

    @AfterAll
    public void stopTunnellingServers() throws Exception {
        if (tunnellingProxy != null) {
            tunnellingProxy.stop();
        }
        if (httpsOrigin != null) {
            httpsOrigin.stop();
        }
    }

    @Test
    public void acceptedConnectStillTunnelsWithTheRightCredentialsOnEachHop() throws Exception {
        connectProxyAuthorization.set(null);

        try (AsyncHttpClient client = asyncHttpClient(config()
                .setUseInsecureTrustManager(true)
                .setRealm(basicAuthRealm(ORIGIN_USER, ORIGIN_PASSWORD).setUsePreemptiveAuth(true))
                .setProxyServer(proxyServer("localhost", tunnellingProxyPort)
                        .setRealm(basicAuthRealm(PROXY_USER, PROXY_PASSWORD).setUsePreemptiveAuth(true)))
                .setRequestTimeout(Duration.ofSeconds(20)))) {

            Response response = client.prepareGet("https://localhost:" + httpsOriginPort + "/secret")
                    .execute().get(30, TimeUnit.SECONDS);

            assertEquals(200, response.getStatusCode());
            // The tunnelled request reached the origin carrying the origin credentials...
            assertEquals(basic(ORIGIN_USER, ORIGIN_PASSWORD), response.getHeader("X-Saw-Authorization"));
            // ...and not the proxy's, which stayed on the CONNECT that the proxy itself received.
            assertNull(response.getHeader("X-Saw-Proxy-Authorization"));
            assertEquals(basic(PROXY_USER, PROXY_PASSWORD), connectProxyAuthorization.get());
        }
    }

    private class RecordingConnectHandler extends ConnectHandler {
        @Override
        public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response)
                throws ServletException, IOException {
            if ("CONNECT".equalsIgnoreCase(request.getMethod())) {
                connectProxyAuthorization.set(request.getHeader("Proxy-Authorization"));
            }
            super.handle(target, baseRequest, request, response);
        }
    }

    /**
     * Echoes the credential headers it received back as response headers, so a test can see what came out
     * of the far end of the tunnel.
     */
    private static class AuthEchoHandler extends AbstractHandler {
        @Override
        public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response)
                throws IOException {
            String authorization = request.getHeader("Authorization");
            if (authorization != null) {
                response.setHeader("X-Saw-Authorization", authorization);
            }
            String proxyAuthorization = request.getHeader("Proxy-Authorization");
            if (proxyAuthorization != null) {
                response.setHeader("X-Saw-Proxy-Authorization", proxyAuthorization);
            }
            response.setStatus(HttpServletResponse.SC_OK);
            baseRequest.setHandled(true);
            response.getOutputStream().close();
        }
    }

    // ---------------------------------------------------------------------------------------------------
    // Raw servers
    // ---------------------------------------------------------------------------------------------------

    /**
     * Base for the raw-socket servers: accepts connections, records the head of every HTTP request it is
     * sent, and lets the subclass decide what to answer.
     */
    private abstract static class RawServer implements AutoCloseable {

        private final ServerSocket serverSocket;
        private final List<String> requestHeads = Collections.synchronizedList(new ArrayList<>());
        private final Thread acceptor;
        private volatile boolean stopped;

        RawServer() throws IOException {
            serverSocket = new ServerSocket(0, 0, InetAddress.getLoopbackAddress());
            acceptor = new Thread(this::acceptLoop, getClass().getSimpleName());
            acceptor.setDaemon(true);
            acceptor.start();
        }

        int port() {
            return serverSocket.getLocalPort();
        }

        List<String> requestHeads() {
            synchronized (requestHeads) {
                return new ArrayList<>(requestHeads);
            }
        }

        void assertNeverSaw(String headerName) {
            String prefix = headerName.toLowerCase(Locale.ROOT) + ':';
            for (String head : requestHeads()) {
                for (String line : head.split("\r\n")) {
                    assertFalse(line.toLowerCase(Locale.ROOT).startsWith(prefix),
                            "the server was sent a " + headerName + " header it must never see: " + head);
                }
            }
        }

        private void acceptLoop() {
            while (!stopped) {
                try {
                    Socket socket = serverSocket.accept();
                    Thread worker = new Thread(() -> serve(socket), getClass().getSimpleName() + "-conn");
                    worker.setDaemon(true);
                    worker.start();
                } catch (IOException e) {
                    return; // closed
                }
            }
        }

        private void serve(Socket socket) {
            try (Socket s = socket) {
                InputStream in = s.getInputStream();
                OutputStream out = s.getOutputStream();
                if (!handshake(in, out)) {
                    return;
                }
                String head;
                while ((head = readRequestHead(in)) != null) {
                    requestHeads.add(head);
                    out.write(respondTo(requestHeads.size(), head).getBytes(ISO_8859_1));
                    out.flush();
                }
            } catch (IOException e) {
                // client went away; whatever was recorded is what the test asserts on
            }
        }

        /**
         * Anything that precedes HTTP on the wire. {@code false} abandons the connection.
         */
        boolean handshake(InputStream in, OutputStream out) throws IOException {
            return true;
        }

        abstract String respondTo(int requestNumber, String head);

        /**
         * Reads one request head, up to and including the blank line. Every request these servers are sent
         * is bodiless, so nothing has to be drained after it.
         */
        private static String readRequestHead(InputStream in) throws IOException {
            ByteArrayOutputStream head = new ByteArrayOutputStream();
            int matched = 0;
            int b;
            while ((b = in.read()) != -1) {
                head.write(b);
                // Track the CRLFCRLF terminator.
                if (b == '\r' && (matched == 0 || matched == 2) || b == '\n' && (matched == 1 || matched == 3)) {
                    matched++;
                    if (matched == 4) {
                        return head.toString("ISO-8859-1");
                    }
                } else {
                    matched = 0;
                }
            }
            return head.size() == 0 ? null : head.toString("ISO-8859-1");
        }

        @Override
        public void close() throws IOException {
            stopped = true;
            serverSocket.close();
        }
    }

    /** An HTTP proxy that refuses to tunnel, then records everything the client sends anyway. */
    private static final class RecordingProxy extends RawServer {

        private final String rejection;

        private RecordingProxy(String rejection) throws IOException {
            this.rejection = rejection;
        }

        static RecordingProxy rejectingConnectWith(String rejection) throws IOException {
            return new RecordingProxy(rejection);
        }

        @Override
        String respondTo(int requestNumber, String head) {
            return requestNumber == 1 ? rejection : ANYTHING_ELSE;
        }
    }

    /**
     * A SOCKS5 endpoint that completes the handshake, reports the connection as established without making
     * one, and then answers the tunnelled HTTP itself — i.e. it stands in for the origin, which is exactly
     * who a 407 on a SOCKS connection can only have come from.
     */
    private static final class Socks5Origin extends RawServer {

        private final String response;

        Socks5Origin(String response) throws IOException {
            this.response = response;
        }

        @Override
        boolean handshake(InputStream in, OutputStream out) throws IOException {
            // Greeting: VER NMETHODS METHODS...
            if (in.read() != 0x05) {
                return false;
            }
            int methodCount = in.read();
            readFully(in, methodCount);
            out.write(new byte[]{0x05, 0x00}); // no authentication required
            out.flush();

            // Request: VER CMD RSV ATYP DST.ADDR DST.PORT
            byte[] header = readFully(in, 4);
            int addressType = header[3] & 0xFF;
            switch (addressType) {
                case 0x01:
                    readFully(in, 4);
                    break;
                case 0x03:
                    readFully(in, in.read());
                    break;
                case 0x04:
                    readFully(in, 16);
                    break;
                default:
                    return false;
            }
            readFully(in, 2); // port

            // Succeeded, bound to 0.0.0.0:0 — no onward connection is made, this server is the far end.
            out.write(new byte[]{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
            out.flush();
            return true;
        }

        @Override
        String respondTo(int requestNumber, String head) {
            return requestNumber == 1 ? response : ANYTHING_ELSE;
        }

        private static byte[] readFully(InputStream in, int length) throws IOException {
            byte[] bytes = new byte[length];
            int read = 0;
            while (read < length) {
                int n = in.read(bytes, read, length - read);
                if (n < 0) {
                    throw new IOException("truncated SOCKS5 message");
                }
                read += n;
            }
            return bytes;
        }
    }
}
