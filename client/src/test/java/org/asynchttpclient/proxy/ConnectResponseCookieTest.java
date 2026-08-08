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

import io.netty.handler.codec.http.cookie.Cookie;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.Response;
import org.asynchttpclient.cookie.CookieStore;
import org.eclipse.jetty.proxy.ConnectHandler;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;

import static org.asynchttpclient.Dsl.asyncHttpClient;
import static org.asynchttpclient.Dsl.config;
import static org.asynchttpclient.Dsl.proxyServer;
import static org.asynchttpclient.test.TestUtils.addHttpConnector;
import static org.asynchttpclient.test.TestUtils.addHttpsConnector;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A CONNECT is answered by the proxy over a hop that is still plaintext, so a {@code Set-Cookie} on that
 * response is written by the proxy — or, since the hop is unprotected, by anyone on the path. The cookie
 * store is keyed on the current request's URI, which throughout the tunnel handshake is the ORIGIN's, so
 * storing it files an attacker-chosen cookie against the origin and the next request carries it back inside
 * TLS. That is session fixation / CSRF-token overwrite (CWE-384).
 * <p>
 * The proxy here completes the CONNECT for real and relays the origin's TLS, so the tunnel that follows is a
 * genuine one and the only thing under test is where the injected cookie ends up.
 */
public class ConnectResponseCookieTest {

    private static final String INJECTED = "proxyinjected";
    private static final String ORIGIN_COOKIE = "origincookie";

    private Server origin;
    private Server proxy;
    private int originPort;
    private int proxyPort;

    /** Every {@code Cookie} header the origin saw, in arrival order; a request without one records "". */
    private final Queue<String> cookiesSeenByOrigin = new ConcurrentLinkedQueue<>();

    @BeforeEach
    public void setUpGlobal() throws Exception {
        origin = new Server();
        ServerConnector originConnector = addHttpsConnector(origin);
        origin.setHandler(new AbstractHandler() {
            @Override
            public void handle(String target, Request baseRequest, HttpServletRequest request,
                               HttpServletResponse response) throws IOException, ServletException {
                String cookie = request.getHeader("Cookie");
                cookiesSeenByOrigin.add(cookie == null ? "" : cookie);
                // A cookie the origin really did set, inside TLS: this one must still be stored.
                response.addHeader("Set-Cookie", ORIGIN_COOKIE + "=ok; Path=/");
                response.setStatus(HttpServletResponse.SC_OK);
                response.getOutputStream().close();
                baseRequest.setHandled(true);
            }
        });
        origin.start();
        originPort = originConnector.getLocalPort();

        proxy = new Server();
        ServerConnector proxyConnector = addHttpConnector(proxy);
        proxy.setHandler(new ConnectHandler() {
            @Override
            protected boolean handleAuthentication(HttpServletRequest request, HttpServletResponse response,
                                                   String address) {
                // Runs before Jetty writes "200 Connection Established", so the header rides that response.
                response.addHeader("Set-Cookie", INJECTED + "=owned; Path=/");
                return true;
            }
        });
        proxy.start();
        proxyPort = proxyConnector.getLocalPort();
    }

    @AfterEach
    public void tearDownGlobal() throws Exception {
        proxy.stop();
        origin.stop();
    }

    @Test
    public void setCookieOnAConnectResponseIsNotFiledAgainstTheOrigin() throws Exception {
        try (AsyncHttpClient client = newClient()) {
            CookieStore store = client.getConfig().getCookieStore();
            assertNotNull(store);

            assertEquals(HttpServletResponse.SC_OK, get(client).getStatusCode());

            assertFalse(hasCookie(store.getAll(), INJECTED),
                    "the proxy's CONNECT-response cookie was filed against the origin: " + store.getAll());

            // Prove it end to end as well: a second request through the tunnel must not carry it to the
            // origin. This is the half that actually hurts — the cookie would go back inside TLS.
            assertEquals(HttpServletResponse.SC_OK, get(client).getStatusCode());
            for (String seen : cookiesSeenByOrigin) {
                assertFalse(seen.contains(INJECTED), "the origin received the injected cookie: " + seen);
            }
        }
    }

    @Test
    public void setCookieFromTheOriginInsideTheTunnelIsStillStored() throws Exception {
        try (AsyncHttpClient client = newClient()) {
            CookieStore store = client.getConfig().getCookieStore();

            assertEquals(HttpServletResponse.SC_OK, get(client).getStatusCode());
            assertTrue(hasCookie(store.getAll(), ORIGIN_COOKIE),
                    "the origin's own cookie was dropped: " + store.getAll());

            // ...and it is sent back on the next request through the tunnel.
            assertEquals(HttpServletResponse.SC_OK, get(client).getStatusCode());
            assertEquals(2, cookiesSeenByOrigin.size());
            cookiesSeenByOrigin.poll();
            String secondRequestCookies = cookiesSeenByOrigin.poll();
            assertNotNull(secondRequestCookies);
            assertTrue(secondRequestCookies.contains(ORIGIN_COOKIE + "=ok"),
                    "expected the origin's cookie to be sent back but got: " + secondRequestCookies);
        }
    }

    private AsyncHttpClient newClient() {
        return asyncHttpClient(config()
                .setProxyServer(proxyServer("localhost", proxyPort))
                .setUseInsecureTrustManager(true));
    }

    private Response get(AsyncHttpClient client) throws Exception {
        return client.prepareGet("https://localhost:" + originPort + '/').execute().get(30, TimeUnit.SECONDS);
    }

    private static boolean hasCookie(List<Cookie> cookies, String name) {
        return cookies.stream().anyMatch(c -> name.equals(c.name()));
    }
}
