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
package org.asynchttpclient;

import io.github.artsok.RepeatedIfExceptionsTest;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.asynchttpclient.test.ExtendedDigestAuthenticator;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.junit.jupiter.api.BeforeEach;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.asynchttpclient.Dsl.asyncHttpClient;
import static org.asynchttpclient.Dsl.digestAuthRealm;
import static org.asynchttpclient.test.TestUtils.ADMIN;
import static org.asynchttpclient.test.TestUtils.USER;
import static org.asynchttpclient.test.TestUtils.addHttpConnector;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * RFC 7616 §3.5 mutual authentication: the {@code Authentication-Info: rspauth} value proves the server
 * knows the shared secret. A present-but-invalid {@code rspauth} means the server failed mutual auth, so
 * the client must not deliver the response as an authenticated success — it aborts (mirrors the SCRAM
 * ServerSignature enforcement in #2235). An absent header stays warn-only.
 */
public class DigestMutualAuthTest extends AbstractBasicTest {

    @Override
    @BeforeEach
    public void setUpGlobal() throws Exception {
        server = new Server();
        ServerConnector connector = addHttpConnector(server);
        server.setHandler(new RspAuthHandler(false));
        server.start();
        port1 = connector.getLocalPort();
        logger.info("Local HTTP server started successfully");
    }

    @Override
    public AbstractHandler configureHandler() throws Exception {
        return new RspAuthHandler(false);
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void validRspAuthIsAccepted() throws Exception {
        try (AsyncHttpClient client = asyncHttpClient()) {
            Future<Response> f = client.prepareGet("http://localhost:" + port1 + '/')
                    .setRealm(digestAuthRealm(USER, ADMIN).setRealmName("MyRealm").build())
                    .execute();
            Response resp = f.get(60, TimeUnit.SECONDS);
            assertNotNull(resp);
            assertEquals(HttpServletResponse.SC_OK, resp.getStatusCode());
            assertNotNull(resp.getHeader("X-Auth"));
        }
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void invalidRspAuthIsRejected() throws Exception {
        // Server completes the digest handshake but returns an rspauth it could not have computed without the
        // shared secret. RFC 7616 §3.5 requires the client to consider the exchange unsuccessful.
        server.stop();
        server = new Server();
        ServerConnector connector = addHttpConnector(server);
        server.setHandler(new RspAuthHandler(true));
        server.start();
        port1 = connector.getLocalPort();

        try (AsyncHttpClient client = asyncHttpClient()) {
            Future<Response> f = client.prepareGet("http://localhost:" + port1 + '/')
                    .setRealm(digestAuthRealm(USER, ADMIN).setRealmName("MyRealm").build())
                    .execute();
            ExecutionException ex = assertThrows(ExecutionException.class, () -> f.get(20, TimeUnit.SECONDS));
            assertNotNull(ex.getCause());
            assertTrue(ex.getCause().getMessage() != null && ex.getCause().getMessage().contains("rspauth"),
                    "expected an rspauth verification failure but got: " + ex.getCause());
        }
    }

    /**
     * Digest handler that, on a successful exchange, returns an {@code Authentication-Info} header carrying
     * either a correctly computed {@code rspauth} or a corrupted one.
     */
    private static class RspAuthHandler extends AbstractHandler {
        private final String realm = "MyRealm";
        private final ExtendedDigestAuthenticator authenticator = new ExtendedDigestAuthenticator();
        private final String nonce = ExtendedDigestAuthenticator.newNonce();
        private final boolean corruptRspAuth;

        RspAuthHandler(boolean corruptRspAuth) {
            this.corruptRspAuth = corruptRspAuth;
        }

        @Override
        public void handle(String s, Request r, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
            String authz = request.getHeader("Authorization");
            if (authz == null || !authz.startsWith("Digest ")) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setHeader("WWW-Authenticate", authenticator.createAuthenticateHeader(realm, nonce, false));
                response.getOutputStream().close();
                return;
            }

            String credentials = authz.substring("Digest ".length());
            Map<String, String> params = ExtendedDigestAuthenticator.parseCredentials(credentials);
            if (!USER.equals(params.get("username"))
                    || !ExtendedDigestAuthenticator.validateDigest(request.getMethod(), credentials, ADMIN)) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setHeader("WWW-Authenticate", authenticator.createAuthenticateHeader(realm, nonce, false));
                response.getOutputStream().close();
                return;
            }

            String rspauth;
            try {
                rspauth = computeRspAuth(params, ADMIN);
            } catch (Exception e) {
                throw new ServletException(e);
            }
            if (corruptRspAuth) {
                rspauth = mangle(rspauth);
            }

            response.addHeader("Authentication-Info", "rspauth=\"" + rspauth + '"');
            response.addHeader("X-Auth", authz);
            response.setStatus(HttpServletResponse.SC_OK);
            response.getOutputStream().flush();
            response.getOutputStream().close();
        }

        /**
         * Server-side rspauth per RFC 7616 §3.5: H(HA1 : nonce : nc : cnonce : qop : H(":" + uri)) using MD5,
         * mirroring {@code AuthenticatorUtils.computeRspAuth} (HA2 has no method, only the URI).
         */
        private static String computeRspAuth(Map<String, String> p, String password) throws Exception {
            MessageDigest md = MessageDigest.getInstance("MD5");
            String ha1 = hex(md.digest((p.get("username") + ':' + p.get("realm") + ':' + password)
                    .getBytes(StandardCharsets.ISO_8859_1)));
            md.reset();
            String ha2 = hex(md.digest((':' + p.get("uri")).getBytes(StandardCharsets.ISO_8859_1)));
            md.reset();
            String qop = p.get("qop");
            String kd = qop != null
                    ? ha1 + ':' + p.get("nonce") + ':' + p.get("nc") + ':' + p.get("cnonce") + ':' + qop + ':' + ha2
                    : ha1 + ':' + p.get("nonce") + ':' + ha2;
            return hex(md.digest(kd.getBytes(StandardCharsets.ISO_8859_1)));
        }

        private static String mangle(String rspauth) {
            // Flip the first hex nibble so the value is present, well-formed, but wrong.
            char first = rspauth.charAt(0);
            char replacement = first == '0' ? '1' : '0';
            return replacement + rspauth.substring(1);
        }

        private static String hex(byte[] bytes) {
            StringBuilder sb = new StringBuilder(bytes.length * 2);
            for (byte b : bytes) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        }
    }
}
