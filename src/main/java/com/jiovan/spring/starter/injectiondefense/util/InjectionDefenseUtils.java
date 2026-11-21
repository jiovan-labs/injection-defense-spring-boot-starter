/*
 * Copyright (c) 2022 Jiovan Ltd. All rights reserved.
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


import java.util.Collection;
import java.util.regex.Pattern;
import jakarta.annotation.Nullable;
import org.apache.commons.lang3.StringUtils;
import org.springframework.util.CollectionUtils;
import com.jiovan.plexus.common.toolkit.util.ArrayUtilsWraps;
import com.jiovan.plexus.common.toolkit.util.RegexUtilsWraps;


/**
 * Heuristic pattern-matching utilities for detecting SQL injection and XSS attempts.
 * <p>
 * <b>Important limitations:</b> detection here is based on a small set of regular expressions
 * and is intentionally conservative. It catches only common, obvious payloads and can be
 * bypassed by obfuscation or less common vectors. It is meant as a lightweight early-warning
 * and coarse filtering layer, <b>not</b> as a security boundary:
 * <ul>
 *     <li>SQL injection must be prevented at the data-access layer with parameterized queries
 *         or an ORM — never by relying on request filtering.</li>
 *     <li>XSS must be prevented with context-aware output escaping (and ideally a Content
 *         Security Policy) — input cleaning alone is not sufficient.</li>
 * </ul>
 * Consider replacing these heuristics with a lexical/fingerprint-based composer (for example
 * libinjection) when stronger detection is required.
 *
 * @author David Hsing
 *
 * @see com.jiovan.spring.starter.injectiondefense.filter.InjectionDefenseFilter
 */
@SuppressWarnings({"unused", "BooleanMethodIsAlwaysInverted", "UnusedReturnValue"})
public abstract class InjectionDefenseUtils {
    private static final Pattern SQL_QUOTE = Pattern.compile("^\\s*\\S*(['\"])+\\)*\\s*(and\\b|or\\b|union\\b|select\\b|insert\\b|update\\b|delete\\b|create\\b|drop\\b|truncate\\b|grant\\b|alter\\b|execute\\b|exec\\b|declare\\b|order\\b|show\\b|#|--|}\\)|/\\*)+", Pattern.CASE_INSENSITIVE);    // $NON-NLS-1$
    private static final Pattern XSS_BRACKET = Pattern.compile("<(iframe|script)\\b", Pattern.CASE_INSENSITIVE);    // $NON-NLS-1$

    /**
     * Returns whether the {@code sequence} may contain an SQL injection pattern
     *
     * @param sequence the character sequence to check, may be {@code null}
     *
     * @return whether the {@code sequence} may contain an SQL injection pattern
     */
    public static boolean maybeSqlInjection(@Nullable CharSequence sequence) {
        return StringUtils.isNotBlank(sequence) && RegexUtilsWraps.find(sequence, SQL_QUOTE);
    }

    /**
     * Returns whether any of the {@code sequences} may contain an SQL injection pattern
     *
     * @param sequences the character sequences to check, may be {@code null}
     *
     * @return whether any of the {@code sequences} may contain an SQL injection pattern
     */
    public static boolean maybeSqlInjection(@Nullable CharSequence... sequences) {
        return maybeSqlInjection(ArrayUtilsWraps.asList(sequences));
    }

    /**
     * Returns whether any sequence in {@code sequences} may contain an SQL injection pattern
     *
     * @param sequences the collection of character sequences to check, may be {@code null}
     *
     * @return whether any sequence in {@code sequences} may contain an SQL injection pattern
     */
    public static boolean maybeSqlInjection(@Nullable Collection<? extends CharSequence> sequences) {
        return !CollectionUtils.isEmpty(sequences) && sequences.stream().anyMatch(InjectionDefenseUtils::maybeSqlInjection);
    }

    /**
     * Returns whether the {@code sequence} may contain an XSS injection pattern
     *
     * @param sequence the character sequence to check, may be {@code null}
     *
     * @return whether the {@code sequence} may contain an XSS injection pattern
     */
    public static boolean maybeXssInjection(@Nullable CharSequence sequence) {
        return StringUtils.isNotBlank(sequence) && RegexUtilsWraps.find(sequence, XSS_BRACKET);
    }

    /**
     * Returns whether any of the {@code sequences} may contain an XSS injection pattern
     *
     * @param sequences the character sequences to check, may be {@code null}
     *
     * @return whether any of the {@code sequences} may contain an XSS injection pattern
     */
    public static boolean maybeXssInjection(@Nullable CharSequence... sequences) {
        return maybeXssInjection(ArrayUtilsWraps.asList(sequences));
    }

    /**
     * Returns whether any sequence in {@code sequences} may contain an XSS injection pattern
     *
     * @param sequences the collection of character sequences to check, may be {@code null}
     *
     * @return whether any sequence in {@code sequences} may contain an XSS injection pattern
     */
    public static boolean maybeXssInjection(@Nullable Collection<? extends CharSequence> sequences) {
        return !CollectionUtils.isEmpty(sequences) && sequences.stream().anyMatch(InjectionDefenseUtils::maybeXssInjection);
    }
}
