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

import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;

import static org.asynchttpclient.Dsl.digestAuthRealm;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * RFC 7616 Section 3.3 requires the client nonce to be unpredictable: it is what stops a hostile or
 * compromised server from choosing the whole digest input and precomputing responses. A non-cryptographic
 * PRNG such as {@link java.util.concurrent.ThreadLocalRandom} does not provide that, so the cnonce must be
 * drawn from a {@link SecureRandom}.
 */
public class DigestCnonceTest {

    /**
     * Structural check: whatever generator {@link Realm.Builder} holds for the cnonce, it must be a
     * {@link SecureRandom}. Deliberately does not hard-code the field name so a rename does not break it.
     */
    @Test
    public void cnonceIsDrawnFromASecureRandom() throws Exception {
        SecureRandom found = null;
        for (Field field : Realm.Builder.class.getDeclaredFields()) {
            if (!Modifier.isStatic(field.getModifiers())) {
                continue;
            }
            field.setAccessible(true);
            Object value = field.get(null);
            if (value instanceof SecureRandom) {
                found = (SecureRandom) value;
            } else if (value instanceof ThreadLocal) {
                Object supplied = ((ThreadLocal<?>) value).get();
                if (supplied instanceof SecureRandom) {
                    found = (SecureRandom) supplied;
                }
            }
        }

        assertNotNull(found, "Realm.Builder must draw the Digest cnonce from a SecureRandom (RFC 7616 Section 3.3)");
    }

    @Test
    public void everyDigestRealmGetsItsOwnCnonce() {
        Set<String> cnonces = new HashSet<>();
        for (int i = 0; i < 64; i++) {
            Realm realm = digestAuthRealm("user", "password")
                    .setRealmName("realm")
                    .setNonce("aabbccddeeff")
                    .setQop("auth")
                    .build();
            assertNotNull(realm.getCnonce(), "a Digest realm built against a server nonce must carry a cnonce");
            cnonces.add(realm.getCnonce());
        }

        assertEquals(64, cnonces.size(), "each Digest realm must get a fresh cnonce");
    }
}
