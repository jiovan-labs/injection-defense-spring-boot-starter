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

package com.jiovan.spring.starter.injectiondefense.enumeration;


import com.jiovan.plexus.common.toolkit.enumeration.ValueEnum;
import com.jiovan.spring.starter.injectiondefense.util.InjectionDefenseUtils;
import lombok.AllArgsConstructor;
import lombok.Getter;


/**
 * Enumeration of injection detection strategies
 *
 * @author David Hsing
 *
 * @see com.jiovan.spring.starter.injectiondefense.composer.InjectionDetector
 */
@AllArgsConstructor
@Getter
@SuppressWarnings("unused")
public enum InjectionDefenderType implements ValueEnum<String> {
    /**
     * Use both the regex heuristics and libinjection, intercepting when either detects a threat
     * <p>
     * This is the default strategy as it covers the blind spots of both individual strategies.
     */
    HYBRID("hybrid"),    // $NON-NLS-1$

    /**
     * Use the built-in regular-expression heuristics in {@link InjectionDefenseUtils}
     */
    SIMPLE("simple"),    // $NON-NLS-1$

    /**
     * Use libinjection-jvm lexical and fingerprint based detection
     */
    LIBINJECTION("libinjection");    // $NON-NLS-1$

    private final String value;
}
