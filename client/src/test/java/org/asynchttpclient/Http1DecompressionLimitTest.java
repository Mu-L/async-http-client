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

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import io.netty.handler.codec.compression.DecompressionException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that HTTP/1.1 automatic response decompression honours the configured decompressed-size ceiling
 * ({@link AsyncHttpClientConfig#getHttp2MaxDecompressedResponseSize()}), so a highly compressible body
 * cannot inflate without bound (a "decompression bomb"). Before the fix both {@code HttpContentDecompressor}
 * construction sites used the no-arg constructor (maxAllocation=0 = unbounded), unlike the already-bounded
 * HTTP/2 path. See {@code ChannelManager#newHttpContentDecompressor}.
 */
public class Http1DecompressionLimitTest {

    // 4 MiB of a single repeated byte: gzips to a few KiB but inflates to 4 MiB.
    private static final byte[] LARGE_PAYLOAD = "a".repeat(4 * 1024 * 1024).getBytes(StandardCharsets.UTF_8);

    private static HttpServer HTTP_SERVER;

    @BeforeAll
    static void setupServer() throws Exception {
        HTTP_SERVER = HttpServer.create(new InetSocketAddress(0), 0);
        HTTP_SERVER.createContext("/gzip-bomb").setHandler(new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                exchange.getResponseHeaders().set("Content-Encoding", "gzip");
                exchange.sendResponseHeaders(200, 0);
                try (OutputStream out = exchange.getResponseBody();
                     GZIPOutputStream gzip = new GZIPOutputStream(out)) {
                    gzip.write(LARGE_PAYLOAD);
                    gzip.finish();
                }
            }
        });
        HTTP_SERVER.start();
    }

    @AfterAll
    static void stopServer() {
        if (HTTP_SERVER != null) {
            HTTP_SERVER.stop(0);
        }
    }

    private static AsyncHttpClient clientWithLimit(long maxDecompressedResponseSize) {
        AsyncHttpClientConfig config = new DefaultAsyncHttpClientConfig.Builder()
                .setEnableAutomaticDecompression(true)
                .setCompressionEnforced(true)
                .setHttp2MaxDecompressedResponseSize(maxDecompressedResponseSize)
                .build();
        return new DefaultAsyncHttpClient(config);
    }

    private static String url() {
        return "http://localhost:" + HTTP_SERVER.getAddress().getPort() + "/gzip-bomb";
    }

    private static boolean hasDecompressionCause(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c instanceof DecompressionException) {
                return true;
            }
        }
        return false;
    }

    @Test
    void decompressionBeyondLimitFails() throws Exception {
        // 256 KiB ceiling, but the body inflates to 4 MiB -> Netty must abort with a DecompressionException
        // rather than allocating the full 4 MiB.
        try (AsyncHttpClient client = clientWithLimit(256 * 1024)) {
            ExecutionException ex = assertThrows(ExecutionException.class,
                    () -> client.prepareGet(url()).execute().get(30, TimeUnit.SECONDS));
            assertTrue(hasDecompressionCause(ex),
                    "expected a Netty DecompressionException in the cause chain but got: " + ex.getCause());
        }
    }

    @Test
    void decompressionWithinLimitSucceeds() throws Exception {
        // A generous ceiling comfortably above the 4 MiB inflated size lets the same body through unchanged.
        try (AsyncHttpClient client = clientWithLimit(64 * 1024 * 1024)) {
            Response response = client.prepareGet(url()).execute().get(30, TimeUnit.SECONDS);
            assertEquals(200, response.getStatusCode());
            assertEquals(LARGE_PAYLOAD.length, response.getResponseBodyAsBytes().length);
        }
    }
}
