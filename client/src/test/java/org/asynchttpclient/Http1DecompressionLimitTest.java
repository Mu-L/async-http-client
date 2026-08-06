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
import com.sun.net.httpserver.HttpServer;
import io.netty.handler.codec.compression.DecompressionException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * HTTP/1.1 automatic response decompression must honour
 * {@link AsyncHttpClientConfig#getMaxDecompressedResponseSize()} <em>cumulatively</em>, so a highly
 * compressible body cannot inflate without bound (a "decompression bomb").
 * <p>
 * The bound has to span the whole response, not one decode call. AHC feeds the decompressor
 * {@code HttpContent} chunks of at most {@code httpClientCodecMaxChunkSize} (8 KiB) bytes, so a
 * per-call ceiling — such as the {@code maxAllocation} argument of Netty's {@code HttpContentDecompressor}
 * — can only fire on a body whose local inflation ratio approaches DEFLATE's ~1032:1 maximum, and never on
 * an ordinary bomb that simply keeps going. {@link #cumulativeDecompressionBeyondLimitIsRejected()} is the
 * case that separates the two: at ratio ~20 no single chunk comes near the ceiling, yet the response as a
 * whole blows straight through it.
 *
 * @see org.asynchttpclient.netty.handler.Http1ContentDecompressor
 */
public class Http1DecompressionLimitTest {

    private static final int ONE_MIB = 1024 * 1024;

    /** 4 MiB of a single repeated byte: inflation ratio ~1028, i.e. close to DEFLATE's theoretical maximum. */
    private static final byte[] HIGH_RATIO_PAYLOAD = "a".repeat(4 * ONE_MIB).getBytes(StandardCharsets.UTF_8);

    /** 8 MiB inflating at ~20:1 — unremarkable for text, and nowhere near what a per-chunk cap can see. */
    private static final byte[] MODERATE_RATIO_PAYLOAD = moderateRatioPayload(8 * ONE_MIB);

    private static final byte[] HIGH_RATIO_GZIP = gzip(HIGH_RATIO_PAYLOAD);
    private static final byte[] MODERATE_RATIO_GZIP = gzip(MODERATE_RATIO_PAYLOAD);

    private static HttpServer HTTP_SERVER;

    /**
     * Mostly one repeated byte with a random letter dropped in every {@code 24} bytes. Deterministically
     * seeded so the inflation ratio — asserted in {@link #moderatePayloadStaysWellUnderThePerChunkCeiling()}
     * — does not drift between runs.
     */
    private static byte[] moderateRatioPayload(int length) {
        byte[] payload = new byte[length];
        Arrays.fill(payload, (byte) 'a');
        Random random = new Random(42);
        for (int i = 0; i < length; i += 24) {
            payload[i] = (byte) ('a' + random.nextInt(26));
        }
        return payload;
    }

    private static byte[] gzip(byte[] payload) {
        ByteArrayOutputStream compressed = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(compressed)) {
            gzip.write(payload);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return compressed.toByteArray();
    }

    @BeforeAll
    static void setupServer() throws Exception {
        HTTP_SERVER = HttpServer.create(new InetSocketAddress(0), 0);
        // Distinct first path segments: com.sun.net.httpserver dispatches on longest matching prefix, so
        // contexts that prefix one another would be ambiguous.
        HTTP_SERVER.createContext("/high-ratio").setHandler(exchange -> sendGzip(exchange, HIGH_RATIO_GZIP));
        HTTP_SERVER.createContext("/moderate-ratio").setHandler(exchange -> sendGzip(exchange, MODERATE_RATIO_GZIP));
        HTTP_SERVER.createContext("/plain").setHandler(exchange -> {
            exchange.sendResponseHeaders(200, MODERATE_RATIO_PAYLOAD.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(MODERATE_RATIO_PAYLOAD);
            }
        });
        HTTP_SERVER.start();
    }

    private static void sendGzip(HttpExchange exchange, byte[] body) throws IOException {
        exchange.getResponseHeaders().set("Content-Encoding", "gzip");
        exchange.sendResponseHeaders(200, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    @AfterAll
    static void stopServer() {
        if (HTTP_SERVER != null) {
            HTTP_SERVER.stop(0);
        }
    }

    private static DefaultAsyncHttpClientConfig.Builder configBuilder() {
        return new DefaultAsyncHttpClientConfig.Builder()
                .setEnableAutomaticDecompression(true)
                .setCompressionEnforced(true);
    }

    private static AsyncHttpClient clientWithLimit(long maxDecompressedResponseSize) {
        return new DefaultAsyncHttpClient(configBuilder()
                .setMaxDecompressedResponseSize(maxDecompressedResponseSize)
                .build());
    }

    private static String url(String path) {
        return "http://localhost:" + HTTP_SERVER.getAddress().getPort() + path;
    }

    private static void assertDecompressionRejected(AsyncHttpClient client, String path) {
        ExecutionException ex = assertThrows(ExecutionException.class,
                () -> client.prepareGet(url(path)).execute().get(60, TimeUnit.SECONDS));
        for (Throwable cause = ex; cause != null; cause = cause.getCause()) {
            if (cause instanceof DecompressionException) {
                return;
            }
        }
        throw new AssertionError("expected a DecompressionException in the cause chain but got: " + ex.getCause(), ex);
    }

    /**
     * Pins the property that makes {@link #cumulativeDecompressionBeyondLimitIsRejected()} meaningful: the
     * moderate payload's inflation ratio is low enough that no single 8 KiB {@code HttpContent} can inflate
     * to the 1 MiB limit on its own (that would take a 128:1 ratio), so only a cumulative counter can catch
     * it — while the response as a whole is eight times the limit.
     */
    @Test
    void moderatePayloadStaysWellUnderThePerChunkCeiling() {
        double ratio = (double) MODERATE_RATIO_PAYLOAD.length / MODERATE_RATIO_GZIP.length;
        assertTrue(ratio > 10 && ratio < 40, "unexpected inflation ratio " + ratio);
        assertTrue(MODERATE_RATIO_PAYLOAD.length > ONE_MIB, "payload must exceed the limit in total");
        assertTrue(8192 * ratio * 3 < ONE_MIB,
                "a single 8 KiB chunk must stay far below the limit, ratio was " + ratio);
    }

    @Test
    void cumulativeDecompressionBeyondLimitIsRejected() throws Exception {
        // 8 MiB of body against a 1 MiB ceiling, arriving in chunks that individually inflate to ~160 KiB.
        try (AsyncHttpClient client = clientWithLimit(ONE_MIB)) {
            assertDecompressionRejected(client, "/moderate-ratio");
        }
    }

    @Test
    void singleChunkDecompressionBeyondLimitIsRejected() throws Exception {
        try (AsyncHttpClient client = clientWithLimit(256 * 1024)) {
            assertDecompressionRejected(client, "/high-ratio");
        }
    }

    @Test
    void decompressionWithinLimitSucceeds() throws Exception {
        try (AsyncHttpClient client = clientWithLimit(64 * ONE_MIB)) {
            Response response = client.prepareGet(url("/high-ratio")).execute().get(60, TimeUnit.SECONDS);
            assertEquals(200, response.getStatusCode());
            assertEquals(HIGH_RATIO_PAYLOAD.length, response.getResponseBodyAsBytes().length);
        }
    }

    @Test
    void zeroDisablesTheLimit() throws Exception {
        try (AsyncHttpClient client = clientWithLimit(0)) {
            Response response = client.prepareGet(url("/moderate-ratio")).execute().get(60, TimeUnit.SECONDS);
            assertEquals(200, response.getStatusCode());
            assertEquals(MODERATE_RATIO_PAYLOAD.length, response.getResponseBodyAsBytes().length);
        }
    }

    /**
     * The ceiling bounds what decompression <em>produces</em>. A large response that was never compressed
     * is the caller's own choice and must still be delivered.
     */
    @Test
    void uncompressedResponsesAreNotBoundedByTheLimit() throws Exception {
        try (AsyncHttpClient client = clientWithLimit(ONE_MIB)) {
            Response response = client.prepareGet(url("/plain")).execute().get(60, TimeUnit.SECONDS);
            assertEquals(200, response.getStatusCode());
            assertEquals(MODERATE_RATIO_PAYLOAD.length, response.getResponseBodyAsBytes().length);
        }
    }

    @Test
    void keepEncodingHeaderStillEnforcesTheLimit() throws Exception {
        try (AsyncHttpClient client = new DefaultAsyncHttpClient(configBuilder()
                .setKeepEncodingHeader(true)
                .setMaxDecompressedResponseSize(ONE_MIB)
                .build())) {
            assertDecompressionRejected(client, "/moderate-ratio");
        }
    }

    @Test
    void keepEncodingHeaderRetainsContentEncodingAndStillDecompresses() throws Exception {
        try (AsyncHttpClient client = new DefaultAsyncHttpClient(configBuilder()
                .setKeepEncodingHeader(true)
                .setMaxDecompressedResponseSize(64 * ONE_MIB)
                .build())) {
            Response response = client.prepareGet(url("/high-ratio")).execute().get(60, TimeUnit.SECONDS);
            assertEquals(200, response.getStatusCode());
            assertEquals("gzip", response.getHeader("Content-Encoding"));
            assertEquals(HIGH_RATIO_PAYLOAD.length, response.getResponseBodyAsBytes().length);
        }
    }

    /**
     * HTTP/1.1 and HTTP/2 have separate ceilings. Sharing one knob was a footgun: disabling the HTTP/2
     * bound silently disabled HTTP/1.1 too, and bounding HTTP/1.1 required setting an {@code http2}-named
     * property.
     */
    @Test
    void http1LimitIsIndependentOfTheHttp2Limit() throws Exception {
        try (AsyncHttpClient client = new DefaultAsyncHttpClient(configBuilder()
                .setHttp2MaxDecompressedResponseSize(0)
                .setMaxDecompressedResponseSize(ONE_MIB)
                .build())) {
            assertDecompressionRejected(client, "/moderate-ratio");
        }

        try (AsyncHttpClient client = new DefaultAsyncHttpClient(configBuilder()
                .setHttp2MaxDecompressedResponseSize(1024)
                .setMaxDecompressedResponseSize(64 * ONE_MIB)
                .build())) {
            Response response = client.prepareGet(url("/high-ratio")).execute().get(60, TimeUnit.SECONDS);
            assertEquals(200, response.getStatusCode());
            assertEquals(HIGH_RATIO_PAYLOAD.length, response.getResponseBodyAsBytes().length);
        }
    }
}
