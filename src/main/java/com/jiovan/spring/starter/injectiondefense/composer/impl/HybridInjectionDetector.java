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

package com.jiovan.spring.starter.injectiondefense.composer.impl;


import jakarta.annotation.Nullable;
import com.jiovan.spring.starter.injectiondefense.composer.InjectionDetector;


/**
 * {@link InjectionDetector} that combines two strategies, intercepting when either one detects a
 * threat.
 * <p>
 * This covers the blind spots of each individual strategy: the regex heuristics catch patterns
 * libinjection misses, and libinjection catches obfuscated payloads the regex misses.
 *
 * @author David Hsing
 *
 * @see SimpleInjectionDetector
 * @see LibInjectionDetector
 */
public class HybridInjectionDetector implements InjectionDetector {
    private final InjectionDetector simple;
    private final InjectionDetector libInjection;

    public HybridInjectionDetector() {
        this(new SimpleInjectionDetector(), new LibInjectionDetector());
    }

    public HybridInjectionDetector(@Nullable InjectionDetector simple, @Nullable InjectionDetector libInjection) {
        this.simple = simple != null ? simple : new SimpleInjectionDetector();
        this.libInjection = libInjection != null ? libInjection : new LibInjectionDetector();
    }

    @Override
    public boolean maybeSqlInjection(@Nullable CharSequence sequence) {
        return simple.maybeSqlInjection(sequence) || libInjection.maybeSqlInjection(sequence);
    }

    @Override
    public boolean maybeSqlInjection(@Nullable CharSequence... sequences) {
        return simple.maybeSqlInjection(sequences) || libInjection.maybeSqlInjection(sequences);
    }

    @Override
    public boolean maybeXssInjection(@Nullable CharSequence sequence) {
        return simple.maybeXssInjection(sequence) || libInjection.maybeXssInjection(sequence);
    }

    @Override
    public boolean maybeXssInjection(@Nullable CharSequence... sequences) {
        return simple.maybeXssInjection(sequences) || libInjection.maybeXssInjection(sequences);
    }
}
