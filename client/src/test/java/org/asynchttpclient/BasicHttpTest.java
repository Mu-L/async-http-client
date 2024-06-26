/*
 *    Copyright (c) 2016-2023 AsyncHttpClient Project. All rights reserved.
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
import io.netty.handler.codec.http.DefaultHttpHeaders;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.cookie.Cookie;
import io.netty.handler.codec.http.cookie.DefaultCookie;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.asynchttpclient.handler.MaxRedirectException;
import org.asynchttpclient.request.body.generator.InputStreamBodyGenerator;
import org.asynchttpclient.request.body.multipart.StringPart;
import org.asynchttpclient.test.EventCollectingHandler;
import org.asynchttpclient.testserver.HttpServer;
import org.asynchttpclient.testserver.HttpServer.EchoHandler;
import org.asynchttpclient.testserver.HttpTest;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

import javax.net.ssl.SSLException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.URLDecoder;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static io.netty.handler.codec.http.HttpHeaderNames.CONTENT_LENGTH;
import static io.netty.handler.codec.http.HttpHeaderNames.CONTENT_TYPE;
import static io.netty.handler.codec.http.HttpHeaderNames.HOST;
import static io.netty.handler.codec.http.HttpHeaderNames.TRANSFER_ENCODING;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.asynchttpclient.Dsl.config;
import static org.asynchttpclient.Dsl.get;
import static org.asynchttpclient.Dsl.head;
import static org.asynchttpclient.Dsl.post;
import static org.asynchttpclient.test.TestUtils.AsyncCompletionHandlerAdapter;
import static org.asynchttpclient.test.TestUtils.TEXT_HTML_CONTENT_TYPE_WITH_UTF_8_CHARSET;
import static org.asynchttpclient.test.TestUtils.TIMEOUT;
import static org.asynchttpclient.test.TestUtils.assertContentTypesEquals;
import static org.asynchttpclient.test.TestUtils.findFreePort;
import static org.asynchttpclient.test.TestUtils.writeResponseBody;
import static org.asynchttpclient.util.DateUtils.unpreciseMillisTime;
import static org.asynchttpclient.util.ThrowableUtil.unknownStackTrace;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class BasicHttpTest extends HttpTest {

    public static final byte[] ACTUAL = {};
    private HttpServer server;

    @BeforeEach
    public void start() throws Throwable {
        server = new HttpServer();
        server.start();
    }

    @AfterEach
    public void stop() throws Throwable {
        server.close();
    }

    private String getTargetUrl() {
        return server.getHttpUrl() + "/foo/bar";
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void getRootUrl() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    String url = server.getHttpUrl();
                    server.enqueueOk();

                    Response response = client.executeRequest(get(url), new AsyncCompletionHandlerAdapter()).get(TIMEOUT, SECONDS);
                    assertEquals(response.getUri().toUrl(), url);
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void getUrlWithPathWithoutQuery() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    server.enqueueOk();

                    Response response = client.executeRequest(get(getTargetUrl()), new AsyncCompletionHandlerAdapter()).get(TIMEOUT, SECONDS);
                    assertEquals(response.getUri().toUrl(), getTargetUrl());
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void getUrlWithPathWithQuery() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    String targetUrl = getTargetUrl() + "?q=+%20x";
                    Request request = get(targetUrl).build();
                    assertEquals(request.getUrl(), targetUrl);
                    server.enqueueOk();

                    Response response = client.executeRequest(request, new AsyncCompletionHandlerAdapter()).get(TIMEOUT, SECONDS);
                    assertEquals(response.getUri().toUrl(), targetUrl);
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void getUrlWithPathWithQueryParams() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    server.enqueueOk();

                    Response response = client.executeRequest(get(getTargetUrl()).addQueryParam("q", "a b"), new AsyncCompletionHandlerAdapter()).get(TIMEOUT, SECONDS);
                    assertEquals(response.getUri().toUrl(), getTargetUrl() + "?q=a%20b");
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void getResponseBody() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    final String body = "Hello World";

                    server.enqueueResponse(response -> {
                        response.setStatus(200);
                        response.setContentType(TEXT_HTML_CONTENT_TYPE_WITH_UTF_8_CHARSET);
                        writeResponseBody(response, body);
                    });

                    client.executeRequest(get(getTargetUrl()), new AsyncCompletionHandlerAdapter() {

                        @Override
                        public Response onCompleted(Response response) {
                            assertEquals(response.getStatusCode(), 200);
                            String contentLengthHeader = response.getHeader(CONTENT_LENGTH);
                            assertNotNull(contentLengthHeader);
                            assertEquals(Integer.parseInt(contentLengthHeader), body.length());
                            assertContentTypesEquals(response.getContentType(), TEXT_HTML_CONTENT_TYPE_WITH_UTF_8_CHARSET);
                            assertEquals(response.getResponseBody(), body);
                            return response;
                        }
                    }).get(TIMEOUT, SECONDS);
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void getWithHeaders() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    HttpHeaders h = new DefaultHttpHeaders();
                    for (int i = 1; i < 5; i++) {
                        h.add("Test" + i, "Test" + i);
                    }

                    server.enqueueEcho();

                    client.executeRequest(get(getTargetUrl()).setHeaders(h), new AsyncCompletionHandlerAdapter() {

                        @Override
                        public Response onCompleted(Response response) {
                            assertEquals(response.getStatusCode(), 200);
                            for (int i = 1; i < 5; i++) {
                                assertEquals(response.getHeader("X-Test" + i), "Test" + i);
                            }
                            return response;
                        }
                    }).get(TIMEOUT, SECONDS);
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void postWithHeadersAndFormParams() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    HttpHeaders h = new DefaultHttpHeaders();
                    h.add(CONTENT_TYPE, HttpHeaderValues.APPLICATION_X_WWW_FORM_URLENCODED);

                    Map<String, List<String>> m = new HashMap<>();
                    for (int i = 0; i < 5; i++) {
                        m.put("param_" + i, Collections.singletonList("value_" + i));
                    }

                    Request request = post(getTargetUrl()).setHeaders(h).setFormParams(m).build();

                    server.enqueueEcho();

                    client.executeRequest(request, new AsyncCompletionHandlerAdapter() {

                        @Override
                        public Response onCompleted(Response response) {
                            assertEquals(response.getStatusCode(), 200);
                            for (int i = 1; i < 5; i++) {
                                assertEquals(response.getHeader("X-param_" + i), "value_" + i);
                            }
                            return response;
                        }
                    }).get(TIMEOUT, SECONDS);
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void postChineseChar() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    HttpHeaders h = new DefaultHttpHeaders();
                    h.add(CONTENT_TYPE, HttpHeaderValues.APPLICATION_X_WWW_FORM_URLENCODED);

                    String chineseChar = "是";

                    Map<String, List<String>> m = new HashMap<>();
                    m.put("param", Collections.singletonList(chineseChar));

                    Request request = post(getTargetUrl()).setHeaders(h).setFormParams(m).build();

                    server.enqueueEcho();

                    client.executeRequest(request, new AsyncCompletionHandlerAdapter() {
                        @Override
                        public Response onCompleted(Response response) {
                            assertEquals(response.getStatusCode(), 200);
                            String value;
                            // headers must be encoded
                            value = URLDecoder.decode(response.getHeader("X-param"), UTF_8);
                            assertEquals(value, chineseChar);
                            return response;
                        }
                    }).get(TIMEOUT, SECONDS);
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void headHasEmptyBody() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    server.enqueueOk();

                    Response response = client.executeRequest(head(getTargetUrl()), new AsyncCompletionHandlerAdapter() {
                        @Override
                        public Response onCompleted(Response response) {
                            assertEquals(response.getStatusCode(), 200);
                            return response;
                        }
                    }).get(TIMEOUT, SECONDS);

                    assertTrue(response.getResponseBody().isEmpty());
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void nullSchemeThrowsNPE() throws Throwable {
        assertThrows(IllegalArgumentException.class, () -> withClient().run(client -> client.prepareGet("gatling.io").execute()));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void jettyRespondsWithChunkedTransferEncoding() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    server.enqueueEcho();
                    client.prepareGet(getTargetUrl())
                            .execute(new AsyncCompletionHandlerAdapter() {
                                @Override
                                public Response onCompleted(Response response) {
                                    assertEquals(response.getStatusCode(), 200);
                                    assertEquals(response.getHeader(TRANSFER_ENCODING), HttpHeaderValues.CHUNKED.toString());
                                    return response;
                                }
                            }).get(TIMEOUT, SECONDS);
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void getWithCookies() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    final Cookie coo = new DefaultCookie("foo", "value");
                    coo.setDomain("/");
                    coo.setPath("/");
                    server.enqueueEcho();

                    client.prepareGet(getTargetUrl())
                            .addCookie(coo)
                            .execute(new AsyncCompletionHandlerAdapter() {
                                @Override
                                public Response onCompleted(Response response) {
                                    assertEquals(response.getStatusCode(), 200);
                                    List<Cookie> cookies = response.getCookies();
                                    assertEquals(cookies.size(), 1);
                                    assertEquals(cookies.get(0).toString(), "foo=value");
                                    return response;
                                }
                            }).get(TIMEOUT, SECONDS);
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void defaultRequestBodyEncodingIsUtf8() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    server.enqueueEcho();
                    Response response = client.preparePost(getTargetUrl())
                            .setBody("\u017D\u017D\u017D\u017D\u017D\u017D")
                            .execute().get();
                    assertArrayEquals(response.getResponseBodyAsBytes(), "\u017D\u017D\u017D\u017D\u017D\u017D".getBytes(UTF_8));
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void postFormParametersAsBodyString() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    HttpHeaders h = new DefaultHttpHeaders();
                    h.add(CONTENT_TYPE, HttpHeaderValues.APPLICATION_X_WWW_FORM_URLENCODED);

                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < 5; i++) {
                        sb.append("param_").append(i).append("=value_").append(i).append('&');
                    }
                    sb.setLength(sb.length() - 1);

                    server.enqueueEcho();
                    client.preparePost(getTargetUrl())
                            .setHeaders(h)
                            .setBody(sb.toString())
                            .execute(new AsyncCompletionHandlerAdapter() {

                                @Override
                                public Response onCompleted(Response response) {
                                    assertEquals(response.getStatusCode(), 200);
                                    for (int i = 1; i < 5; i++) {
                                        assertEquals(response.getHeader("X-param_" + i), "value_" + i);

                                    }
                                    return response;
                                }
                            }).get(TIMEOUT, SECONDS);
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void postFormParametersAsBodyStream() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    HttpHeaders h = new DefaultHttpHeaders();
                    h.add(CONTENT_TYPE, HttpHeaderValues.APPLICATION_X_WWW_FORM_URLENCODED);
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < 5; i++) {
                        sb.append("param_").append(i).append("=value_").append(i).append('&');
                    }
                    sb.setLength(sb.length() - 1);

                    server.enqueueEcho();
                    client.preparePost(getTargetUrl())
                            .setHeaders(h)
                            .setBody(new ByteArrayInputStream(sb.toString().getBytes(UTF_8)))
                            .execute(new AsyncCompletionHandlerAdapter() {

                                @Override
                                public Response onCompleted(Response response) {
                                    assertEquals(response.getStatusCode(), 200);
                                    for (int i = 1; i < 5; i++) {
                                        assertEquals(response.getHeader("X-param_" + i), "value_" + i);

                                    }
                                    return response;
                                }
                            }).get(TIMEOUT, SECONDS);
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void putFormParametersAsBodyStream() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    HttpHeaders h = new DefaultHttpHeaders();
                    h.add(CONTENT_TYPE, HttpHeaderValues.APPLICATION_X_WWW_FORM_URLENCODED);
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < 5; i++) {
                        sb.append("param_").append(i).append("=value_").append(i).append('&');
                    }
                    sb.setLength(sb.length() - 1);
                    ByteArrayInputStream is = new ByteArrayInputStream(sb.toString().getBytes());

                    server.enqueueEcho();
                    client.preparePut(getTargetUrl())
                            .setHeaders(h)
                            .setBody(is)
                            .execute(new AsyncCompletionHandlerAdapter() {

                                @Override
                                public Response onCompleted(Response response) {
                                    assertEquals(response.getStatusCode(), 200);
                                    for (int i = 1; i < 5; i++) {
                                        assertEquals(response.getHeader("X-param_" + i), "value_" + i);
                                    }
                                    return response;
                                }
                            }).get(TIMEOUT, SECONDS);
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void postSingleStringPart() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    server.enqueueEcho();
                    client.preparePost(getTargetUrl())
                            .addBodyPart(new StringPart("foo", "bar"))
                            .execute(new AsyncCompletionHandlerAdapter() {
                                @Override
                                public Response onCompleted(Response response) {
                                    String requestContentType = response.getHeader("X-" + CONTENT_TYPE);
                                    String boundary = requestContentType.substring(requestContentType.indexOf("boundary") + "boundary".length() + 1);
                                    assertTrue(response.getResponseBody().regionMatches(false, "--".length(), boundary, 0, boundary.length()));
                                    return response;
                                }
                            }).get(TIMEOUT, SECONDS);
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void postWithBody() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    server.enqueueEcho();
                    client.preparePost(getTargetUrl())
                            .execute(new AsyncCompletionHandlerAdapter() {
                                @Override
                                public Response onCompleted(Response response) {
                                    assertEquals(response.getHeader("X-" + CONTENT_LENGTH), "0");
                                    return response;
                                }
                            }).get(TIMEOUT, SECONDS);
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void getVirtualHost() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    String virtualHost = "localhost:" + server.getHttpPort();

                    server.enqueueEcho();
                    Response response = client.prepareGet(getTargetUrl())
                            .setVirtualHost(virtualHost)
                            .execute(new AsyncCompletionHandlerAdapter()).get(TIMEOUT, SECONDS);

                    assertEquals(response.getStatusCode(), 200);
                    if (response.getHeader("X-" + HOST) == null) {
                        System.err.println(response);
                    }
                    assertEquals(response.getHeader("X-" + HOST), virtualHost);
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void cancelledFutureThrowsCancellationException() throws Throwable {
        assertThrows(CancellationException.class, () -> {
            withClient().run(client ->
                    withServer(server).run(server -> {
                        HttpHeaders headers = new DefaultHttpHeaders();
                        headers.add("X-Delay", 5_000);
                        server.enqueueEcho();

                        Future<Response> future = client.prepareGet(getTargetUrl()).setHeaders(headers).execute(new AsyncCompletionHandlerAdapter() {
                            @Override
                            public void onThrowable(Throwable t) {
                            }
                        });
                        future.cancel(true);
                        future.get(TIMEOUT, SECONDS);
                    }));
        });
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void futureTimeOutThrowsTimeoutException() throws Throwable {
        assertThrows(TimeoutException.class, () -> {
            withClient().run(client ->
                    withServer(server).run(server -> {
                        HttpHeaders headers = new DefaultHttpHeaders();
                        headers.add("X-Delay", 5_000);

                        server.enqueueEcho();
                        Future<Response> future = client.prepareGet(getTargetUrl()).setHeaders(headers).execute(new AsyncCompletionHandlerAdapter() {
                            @Override
                            public void onThrowable(Throwable t) {
                            }
                        });

                        future.get(2, SECONDS);
                    }));
        });
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void connectFailureThrowsConnectException() throws Throwable {
        assertThrows(ConnectException.class, () -> {
            withClient().run(client -> {
                int dummyPort = findFreePort();
                try {
                    client.preparePost(String.format("http://localhost:%d/", dummyPort)).execute(new AsyncCompletionHandlerAdapter() {
                        @Override
                        public void onThrowable(Throwable t) {
                        }
                    }).get(TIMEOUT, SECONDS);
                } catch (ExecutionException ex) {
                    throw ex.getCause();
                }
            });
        });
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void connectFailureNotifiesHandlerWithConnectException() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    final CountDownLatch l = new CountDownLatch(1);
                    int port = findFreePort();

                    client.prepareGet(String.format("http://localhost:%d/", port)).execute(new AsyncCompletionHandlerAdapter() {
                        @Override
                        public void onThrowable(Throwable t) {
                            try {
                                assertInstanceOf(ConnectException.class, t);
                            } finally {
                                l.countDown();
                            }
                        }
                    });

                    if (!l.await(TIMEOUT, SECONDS)) {
                        fail("Timed out");
                    }
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void unknownHostThrowsUnknownHostException() throws Throwable {
        assertThrows(UnknownHostException.class, () -> {
            withClient().run(client ->
                    withServer(server).run(server -> {
                        try {
                            client.prepareGet("http://null.gatling.io").execute(new AsyncCompletionHandlerAdapter() {
                                @Override
                                public void onThrowable(Throwable t) {
                                }
                            }).get(TIMEOUT, SECONDS);
                        } catch (ExecutionException e) {
                            throw e.getCause();
                        }
                    }));
        });
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void getEmptyBody() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    server.enqueueOk();
                    Response response = client.prepareGet(getTargetUrl()).execute(new AsyncCompletionHandlerAdapter())
                            .get(TIMEOUT, SECONDS);
                    assertTrue(response.getResponseBody().isEmpty());
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void getEmptyBodyNotifiesHandler() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    final AtomicBoolean handlerWasNotified = new AtomicBoolean();

                    server.enqueueOk();
                    client.prepareGet(getTargetUrl()).execute(new AsyncCompletionHandlerAdapter() {

                        @Override
                        public Response onCompleted(Response response) {
                            assertEquals(response.getStatusCode(), 200);
                            handlerWasNotified.set(true);
                            return response;
                        }
                    }).get(TIMEOUT, SECONDS);
                    assertTrue(handlerWasNotified.get());
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void exceptionInOnCompletedGetNotifiedToOnThrowable() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    final CountDownLatch latch = new CountDownLatch(1);
                    final AtomicReference<String> message = new AtomicReference<>();

                    server.enqueueOk();
                    client.prepareGet(getTargetUrl()).execute(new AsyncCompletionHandlerAdapter() {
                        @Override
                        public Response onCompleted(Response response) {
                            throw unknownStackTrace(new IllegalStateException("FOO"), BasicHttpTest.class, "exceptionInOnCompletedGetNotifiedToOnThrowable");

                        }

                        @Override
                        public void onThrowable(Throwable t) {
                            message.set(t.getMessage());
                            latch.countDown();
                        }
                    });

                    if (!latch.await(TIMEOUT, SECONDS)) {
                        fail("Timed out");
                    }

                    assertEquals(message.get(), "FOO");
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void exceptionInOnCompletedGetNotifiedToFuture() throws Throwable {
        assertThrows(IllegalStateException.class, () -> {
            withClient().run(client ->
                    withServer(server).run(server -> {
                        server.enqueueOk();
                        Future<Response> whenResponse = client.prepareGet(getTargetUrl()).execute(new AsyncCompletionHandlerAdapter() {
                            @Override
                            public Response onCompleted(Response response) {
                                throw unknownStackTrace(new IllegalStateException("FOO"), BasicHttpTest.class, "exceptionInOnCompletedGetNotifiedToFuture");
                            }

                            @Override
                            public void onThrowable(Throwable t) {
                            }
                        });

                        try {
                            whenResponse.get(TIMEOUT, SECONDS);
                        } catch (ExecutionException e) {
                            throw e.getCause();
                        }
                    }));
        });
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void configTimeoutNotifiesOnThrowableAndFuture() throws Throwable {
        assertThrows(TimeoutException.class, () -> {
            withClient(config().setRequestTimeout(Duration.ofSeconds(1))).run(client ->
                    withServer(server).run(server -> {
                        HttpHeaders headers = new DefaultHttpHeaders();
                        headers.add("X-Delay", 5_000); // delay greater than timeout

                        final AtomicBoolean onCompletedWasNotified = new AtomicBoolean();
                        final AtomicBoolean onThrowableWasNotifiedWithTimeoutException = new AtomicBoolean();
                        final CountDownLatch latch = new CountDownLatch(1);

                        server.enqueueEcho();
                        Future<Response> whenResponse = client.prepareGet(getTargetUrl()).setHeaders(headers).execute(new AsyncCompletionHandlerAdapter() {

                            @Override
                            public Response onCompleted(Response response) {
                                onCompletedWasNotified.set(true);
                                latch.countDown();
                                return response;
                            }

                            @Override
                            public void onThrowable(Throwable t) {
                                onThrowableWasNotifiedWithTimeoutException.set(t instanceof TimeoutException);
                                latch.countDown();
                            }
                        });

                        if (!latch.await(TIMEOUT, SECONDS)) {
                            fail("Timed out");
                        }

                        assertFalse(onCompletedWasNotified.get());
                        assertTrue(onThrowableWasNotifiedWithTimeoutException.get());

                        try {
                            whenResponse.get(TIMEOUT, SECONDS);
                        } catch (ExecutionException e) {
                            throw e.getCause();
                        }
                    }));
        });
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void configRequestTimeoutHappensInDueTime() throws Throwable {
        assertThrows(TimeoutException.class, () -> {
            withClient(config().setRequestTimeout(Duration.ofSeconds(1))).run(client ->
                    withServer(server).run(server -> {
                        HttpHeaders h = new DefaultHttpHeaders();
                        h.add(CONTENT_TYPE, HttpHeaderValues.APPLICATION_X_WWW_FORM_URLENCODED);
                        h.add("X-Delay", 2_000);

                        server.enqueueEcho();
                        long start = unpreciseMillisTime();
                        try {
                            client.prepareGet(getTargetUrl()).setHeaders(h).setUrl(getTargetUrl()).execute().get();
                        } catch (Throwable ex) {
                            final long elapsedTime = unpreciseMillisTime() - start;
                            assertTrue(elapsedTime >= 1_000 && elapsedTime <= 1_500);
                            throw ex.getCause();
                        }
                    }));
        });
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void getProperPathAndQueryString() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    server.enqueueEcho();
                    client.prepareGet(getTargetUrl() + "?foo=bar").execute(new AsyncCompletionHandlerAdapter() {
                        @Override
                        public Response onCompleted(Response response) {
                            assertNotNull(response.getHeader("X-PathInfo"));
                            assertNotNull(response.getHeader("X-QueryString"));
                            return response;
                        }
                    }).get(TIMEOUT, SECONDS);
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void connectionIsReusedForSequentialRequests() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    final CountDownLatch l = new CountDownLatch(2);

                    AsyncCompletionHandler<Response> handler = new AsyncCompletionHandlerAdapter() {

                        volatile String clientPort;

                        @Override
                        public Response onCompleted(Response response) {
                            try {
                                assertEquals(response.getStatusCode(), 200);
                                if (clientPort == null) {
                                    clientPort = response.getHeader("X-ClientPort");
                                } else {
                                    // verify that the server saw the same client remote address/port
                                    // so the same connection was used
                                    assertEquals(response.getHeader("X-ClientPort"), clientPort);
                                }
                            } finally {
                                l.countDown();
                            }
                            return response;
                        }
                    };

                    server.enqueueEcho();
                    client.prepareGet(getTargetUrl()).execute(handler).get(TIMEOUT, SECONDS);
                    server.enqueueEcho();
                    client.prepareGet(getTargetUrl()).execute(handler);

                    if (!l.await(TIMEOUT, SECONDS)) {
                        fail("Timed out");
                    }
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void reachingMaxRedirectThrowsMaxRedirectException() throws Throwable {
        assertThrows(MaxRedirectException.class, () -> {
            withClient(config().setMaxRedirects(1).setFollowRedirect(true)).run(client ->
                    withServer(server).run(server -> {
                        try {
                            // max redirect is 1, so second redirect will fail
                            server.enqueueRedirect(301, getTargetUrl());
                            server.enqueueRedirect(301, getTargetUrl());
                            client.prepareGet(getTargetUrl()).execute(new AsyncCompletionHandlerAdapter() {
                                @Override
                                public Response onCompleted(Response response) {
                                    fail("Should not be here");
                                    return response;
                                }

                                @Override
                                public void onThrowable(Throwable t) {
                                }
                            }).get(TIMEOUT, SECONDS);
                        } catch (ExecutionException e) {
                            throw e.getCause();
                        }
                    }));
        });
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void nonBlockingNestedRequestsFromIoThreadAreFine() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    final int maxNested = 5;
                    final CountDownLatch latch = new CountDownLatch(2);

                    final AsyncCompletionHandlerAdapter handler = new AsyncCompletionHandlerAdapter() {
                        private final AtomicInteger nestedCount = new AtomicInteger(0);

                        @Override
                        public Response onCompleted(Response response) {
                            try {
                                if (nestedCount.getAndIncrement() < maxNested) {
                                    client.prepareGet(getTargetUrl()).execute(this);
                                }
                            } finally {
                                latch.countDown();
                            }
                            return response;
                        }
                    };

                    for (int i = 0; i < maxNested + 1; i++) {
                        server.enqueueOk();
                    }

                    client.prepareGet(getTargetUrl()).execute(handler);

                    if (!latch.await(TIMEOUT, SECONDS)) {
                        fail("Timed out");
                    }
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void optionsIsSupported() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    server.enqueueEcho();
                    Response response = client.prepareOptions(getTargetUrl()).execute().get();
                    assertEquals(response.getStatusCode(), 200);
                    assertEquals(response.getHeader("Allow"), "GET,HEAD,POST,OPTIONS,TRACE");
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void cancellingFutureNotifiesOnThrowableWithCancellationException() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    HttpHeaders h = new DefaultHttpHeaders();
                    h.add(CONTENT_TYPE, HttpHeaderValues.APPLICATION_X_WWW_FORM_URLENCODED);
                    h.add("X-Delay", 2_000);

                    CountDownLatch latch = new CountDownLatch(1);

                    Future<Response> future = client.preparePost(getTargetUrl()).setHeaders(h).setBody("Body").execute(new AsyncCompletionHandlerAdapter() {

                        @Override
                        public void onThrowable(Throwable t) {
                            if (t instanceof CancellationException) {
                                latch.countDown();
                            }
                        }
                    });

                    future.cancel(true);
                    if (!latch.await(TIMEOUT, SECONDS)) {
                        fail("Timed out");
                    }
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void getShouldAllowBody() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server ->
                        client.prepareGet(getTargetUrl()).setBody("Boo!").execute()));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void malformedUriThrowsException() throws Throwable {
        assertThrows(IllegalArgumentException.class, () -> {
            withClient().run(client ->
                    withServer(server).run(server -> client.prepareGet(String.format("http:localhost:%d/foo/test", server.getHttpPort())).build()));
        });
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void emptyResponseBodyBytesAreEmpty() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    server.enqueueEcho();
                    Response response = client.prepareGet(getTargetUrl()).execute().get();
                    assertEquals(response.getStatusCode(), 200);
                    assertArrayEquals(response.getResponseBodyAsBytes(), ACTUAL);
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void newConnectionEventsAreFired() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {

                    Request request = get(getTargetUrl()).build();

                    EventCollectingHandler handler = new EventCollectingHandler();
                    client.executeRequest(request, handler).get(3, SECONDS);
                    handler.waitForCompletion(3, SECONDS);

                    Object[] expectedEvents = {
                            CONNECTION_POOL_EVENT,
                            HOSTNAME_RESOLUTION_EVENT,
                            HOSTNAME_RESOLUTION_SUCCESS_EVENT,
                            CONNECTION_OPEN_EVENT,
                            CONNECTION_SUCCESS_EVENT,
                            REQUEST_SEND_EVENT,
                            HEADERS_WRITTEN_EVENT,
                            STATUS_RECEIVED_EVENT,
                            HEADERS_RECEIVED_EVENT,
                            CONNECTION_OFFER_EVENT,
                            COMPLETED_EVENT};

                    assertArrayEquals(handler.firedEvents.toArray(), expectedEvents, "Got " + Arrays.toString(handler.firedEvents.toArray()));
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void requestingPlainHttpEndpointOverHttpsThrowsSslException() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    server.enqueueEcho();
                    try {
                        client.prepareGet(getTargetUrl().replace("http", "https")).execute().get();
                        fail("Request shouldn't succeed");
                    } catch (ExecutionException e) {
                        assertInstanceOf(ConnectException.class, e.getCause(), "Cause should be a ConnectException");
                        assertInstanceOf(SSLException.class, e.getCause().getCause(), "Root cause should be a SslException");
                    }
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void postUnboundedInputStreamAsBodyStream() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    HttpHeaders h = new DefaultHttpHeaders();
                    h.add(CONTENT_TYPE, HttpHeaderValues.APPLICATION_JSON);
                    server.enqueue(new AbstractHandler() {
                        final EchoHandler chain = new EchoHandler();

                        @Override
                        public void handle(String target, org.eclipse.jetty.server.Request request, HttpServletRequest httpServletRequest,
                                           HttpServletResponse httpServletResponse) throws IOException, ServletException {

                            assertEquals(request.getHeader(TRANSFER_ENCODING.toString()), HttpHeaderValues.CHUNKED.toString());
                            assertNull(request.getHeader(CONTENT_LENGTH.toString()));
                            chain.handle(target, request, httpServletRequest, httpServletResponse);
                        }
                    });
                    server.enqueueEcho();

                    client.preparePost(getTargetUrl())
                            .setHeaders(h)
                            .setBody(new ByteArrayInputStream("{}".getBytes(StandardCharsets.ISO_8859_1)))
                            .execute(new AsyncCompletionHandlerAdapter() {
                                @Override
                                public Response onCompleted(Response response) {
                                    assertEquals(response.getStatusCode(), 200);
                                    assertEquals(response.getResponseBody(), "{}");
                                    return response;
                                }
                            }).get(TIMEOUT, SECONDS);
                }));
    }

    @RepeatedIfExceptionsTest(repeats = 5)
    public void postInputStreamWithContentLengthAsBodyGenerator() throws Throwable {
        withClient().run(client ->
                withServer(server).run(server -> {
                    HttpHeaders h = new DefaultHttpHeaders();
                    h.add(CONTENT_TYPE, HttpHeaderValues.APPLICATION_JSON);
                    server.enqueue(new AbstractHandler() {
                        final EchoHandler chain = new EchoHandler();

                        @Override
                        public void handle(String target, org.eclipse.jetty.server.Request request, HttpServletRequest httpServletRequest,
                                           HttpServletResponse httpServletResponse) throws IOException, ServletException {

                            assertNull(request.getHeader(TRANSFER_ENCODING.toString()));
                            assertEquals(request.getHeader(CONTENT_LENGTH.toString()),
                                    Integer.toString("{}".getBytes(StandardCharsets.ISO_8859_1).length));
                            chain.handle(target, request, httpServletRequest, httpServletResponse);
                        }
                    });

                    byte[] bodyBytes = "{}".getBytes(StandardCharsets.ISO_8859_1);
                    InputStream bodyStream = new ByteArrayInputStream(bodyBytes);

                    client.preparePost(getTargetUrl())
                            .setHeaders(h)
                            .setBody(new InputStreamBodyGenerator(bodyStream, bodyBytes.length))
                            .execute(new AsyncCompletionHandlerAdapter() {

                                @Override
                                public Response onCompleted(Response response) {
                                    assertEquals(response.getStatusCode(), 200);
                                    assertEquals(response.getResponseBody(), "{}");
                                    return response;
                                }
                            }).get(TIMEOUT, SECONDS);
                }));
    }
}
