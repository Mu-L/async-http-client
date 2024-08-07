/*
 *    Copyright (c) 2014-2024 AsyncHttpClient Project. All rights reserved.
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
package org.asynchttpclient.ws;

import io.netty.util.internal.ThreadLocalRandom;

import java.util.Base64;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.asynchttpclient.util.MessageDigestUtils.pooledSha1MessageDigest;

public final class WebSocketUtils {
    private static final String MAGIC_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    private WebSocketUtils() {
        // Prevent outside initialization
    }

    public static String getWebSocketKey() {
        byte[] nonce = new byte[16];
        ThreadLocalRandom random = ThreadLocalRandom.current();
        for (int i = 0; i < nonce.length; i++) {
            nonce[i] = (byte) random.nextInt(256);
        }
        return Base64.getEncoder().encodeToString(nonce);
    }

    public static String getAcceptKey(String key) {
        return Base64.getEncoder().encodeToString(pooledSha1MessageDigest().digest((key + MAGIC_GUID).getBytes(US_ASCII)));
    }
}
