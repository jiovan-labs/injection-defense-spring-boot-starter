/*
 * Copyright (c) 2026 Jiovan Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.jiovan.spring.starter.injectiondefense.util;


import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import com.jiovan.spring.starter.injectiondefense.composer.InjectionDetector;
import com.jiovan.spring.starter.injectiondefense.composer.impl.HybridInjectionDetector;
import com.jiovan.spring.starter.injectiondefense.composer.impl.LibInjectionDetector;
import com.jiovan.spring.starter.injectiondefense.composer.impl.SimpleInjectionDetector;
import lombok.extern.slf4j.Slf4j;


/**
 * Tests for {@link HybridInjectionDetector}, the strategy behind
 * {@code InjectionDefenderType.HYBRID}.
 * <p>
 * The hybrid strategy intercepts when either underlying detector fires, so it must catch both the
 * obfuscated payloads only libinjection sees and the regex-only payloads libinjection misses.
 *
 * @author David Hsing
 *
 * @see LibInjectionDetectorTest
 * @see InjectionDefenseUtilsTest
 */
@Slf4j
class HybridInjectionDetectorTest {
    private final HybridInjectionDetector detector = new HybridInjectionDetector();

    @Test
    void detectsPayloadMissedByLibInjection() {
        // simple catches this, libinjection does not (per LibInjectionDetectorTest.regexOnlyPayload)
        String payload = "admin-777' or drop table --";
        Assertions.assertFalse(new LibInjectionDetector().maybeSqlInjection(payload));
        Assertions.assertTrue(new SimpleInjectionDetector().maybeSqlInjection(payload));
        Assertions.assertTrue(detector.maybeSqlInjection(payload));
    }

    @Test
    void detectsPayloadMissedByRegex() {
        // libinjection catches these, the regex heuristics do not
        String[] payloads = {"1 OR 1=1", "1; DROP TABLE users"};
        for (String payload : payloads) {
            Assertions.assertFalse(InjectionDefenseUtils.maybeSqlInjection(payload));
            Assertions.assertTrue(detector.maybeSqlInjection(payload), "Hybrid should detect: " + payload);
        }
    }

    @Test
    void detectsXssPayloads() {
        String[] payloads = {
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<a href=\"javascript:alert(1)\">x</a>"
        };
        for (String payload : payloads) {
            Assertions.assertTrue(detector.maybeXssInjection(payload), "Hybrid should detect XSS: " + payload);
        }
    }

    @Test
    void benignValuesAreNotFlagged() {
        String[] values = {"hello world", "admin", "normal text with spaces", "<b>hello</b>"};
        for (String value : values) {
            Assertions.assertFalse(detector.maybeSqlInjection(value), "Should not flag SQL: " + value);
            Assertions.assertFalse(detector.maybeXssInjection(value), "Should not flag XSS: " + value);
        }
    }

    @Test
    void varargsAndNullSafety() {
        Assertions.assertTrue(detector.maybeSqlInjection("hello", "1 OR 1=1"));
        Assertions.assertTrue(detector.maybeXssInjection("hello", "<img src=x onerror=alert(1)>"));
        Assertions.assertFalse(detector.maybeSqlInjection((CharSequence) null));
        Assertions.assertFalse(detector.maybeXssInjection((CharSequence) null));
        Assertions.assertFalse(detector.maybeSqlInjection((CharSequence[]) null));
        Assertions.assertFalse(detector.maybeXssInjection((CharSequence[]) null));
    }

    @Test
    void customDelegatesAreUsed() {
        InjectionDetector sqlTrue = new InjectionDetector() {
            @Override public boolean maybeSqlInjection(CharSequence s) { return true; }
            @Override public boolean maybeSqlInjection(CharSequence... s) { return true; }
            @Override public boolean maybeXssInjection(CharSequence s) { return false; }
            @Override public boolean maybeXssInjection(CharSequence... s) { return false; }
        };
        HybridInjectionDetector custom = new HybridInjectionDetector(sqlTrue, sqlTrue);
        Assertions.assertTrue(custom.maybeSqlInjection("anything"));
        Assertions.assertFalse(custom.maybeXssInjection("anything"));
    }
}
