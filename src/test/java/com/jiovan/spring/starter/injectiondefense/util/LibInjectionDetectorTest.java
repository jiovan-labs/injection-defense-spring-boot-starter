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
import com.jiovan.plexus.common.toolkit.util.StackTraceWraps;
import com.jiovan.spring.starter.injectiondefense.composer.impl.LibInjectionDetector;
import lombok.extern.slf4j.Slf4j;


/**
 * Tests for {@link LibInjectionDetector}, the strategy behind
 * {@code InjectionDefenderType.LIBINJECTION}.
 * <p>
 * Compared with the built-in regex heuristics ({@link InjectionDefenseUtils}), libinjection uses
 * lexical analysis and can detect obfuscated payloads such as {@code 1 OR 1=1} or multi-statement
 * injection that the regex strategy misses. Its behaviour is not identical, however — see
 * {@link #regexOnlyPayload()} for a payload the regex strategy catches but libinjection does not.
 *
 * @author David Hsing
 *
 * @see com.jiovan.spring.starter.injectiondefense.composer.InjectionDetector
 * @see com.cloud.apim.libinjection.LibInjection
 */
@Slf4j
class LibInjectionDetectorTest {
    private final LibInjectionDetector detector = new LibInjectionDetector();

    @Test
    void sqlInjectionPayloads() {
        String[] payloads = {
            "-1' union select 1,2,3 --+",
            "1' or show database();",
            "admin' or create table --",
            "1' UNION SELECT password FROM users--",
            "' or '1'='1"
        };
        for (String payload : payloads) {
            log.info("{} = {}", StackTraceWraps.getExecutingMethodName(), detector.maybeSqlInjection(payload));
            Assertions.assertTrue(detector.maybeSqlInjection(payload), "Should detect SQL injection: " + payload);
        }
    }

    @Test
    void obfuscatedSqlPayloadsMissedByRegex() {
        String[] payloads = {
            "1 OR 1=1",           // no quote — regex strategy misses this
            "1; DROP TABLE users" // statement separator — regex strategy misses this
        };
        for (String payload : payloads) {
            log.info("{} = {}", StackTraceWraps.getExecutingMethodName(), detector.maybeSqlInjection(payload));
            Assertions.assertTrue(detector.maybeSqlInjection(payload), "Should detect obfuscated SQL: " + payload);
            Assertions.assertFalse(InjectionDefenseUtils.maybeSqlInjection(payload), "Regex strategy is expected to miss: " + payload);
        }
    }

    @Test
    void regexOnlyPayload() {
        // Documents a behavioural difference: the regex strategy catches this, libinjection does not.
        String payload = "admin-777' or drop table --";
        Assertions.assertTrue(InjectionDefenseUtils.maybeSqlInjection(payload));
        Assertions.assertFalse(detector.maybeSqlInjection(payload));
    }

    @Test
    void xssPayloads() {
        String[] payloads = {
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<a href=\"javascript:alert(1)\">x</a>",
            "<iframe src=javascript:alert(1)>"
        };
        for (String payload : payloads) {
            log.info("{} = {}", StackTraceWraps.getExecutingMethodName(), detector.maybeXssInjection(payload));
            Assertions.assertTrue(detector.maybeXssInjection(payload), "Should detect XSS: " + payload);
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
}
