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

package com.jiovan.spring.starter.injectiondefense.composer;


import jakarta.annotation.Nullable;


/**
 * Strategy for detecting SQL injection and XSS attempts in request values.
 *
 * @author David Hsing
 *
 * @see com.jiovan.spring.starter.injectiondefense.enumeration.InjectionDefenderType
 */
public interface InjectionDetector {
    /**
     * Returns whether the given value may contain an SQL injection pattern
     *
     * @param sequence the value to check, may be {@code null}
     *
     * @return whether an SQL injection pattern is detected
     */
    boolean maybeSqlInjection(@Nullable CharSequence sequence);

    /**
     * Returns whether any of the given values may contain an SQL injection pattern
     *
     * @param sequences the values to check, may be {@code null}
     *
     * @return whether an SQL injection pattern is detected
     */
    boolean maybeSqlInjection(@Nullable CharSequence... sequences);

    /**
     * Returns whether the given value may contain an XSS injection pattern
     *
     * @param sequence the value to check, may be {@code null}
     *
     * @return whether an XSS injection pattern is detected
     */
    boolean maybeXssInjection(@Nullable CharSequence sequence);

    /**
     * Returns whether any of the given values may contain an XSS injection pattern
     *
     * @param sequences the values to check, may be {@code null}
     *
     * @return whether an XSS injection pattern is detected
     */
    boolean maybeXssInjection(@Nullable CharSequence... sequences);
}
