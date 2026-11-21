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


import java.util.Arrays;
import jakarta.annotation.Nullable;
import com.cloud.apim.libinjection.LibInjection;
import com.jiovan.spring.starter.injectiondefense.composer.InjectionDetector;


/**
 * {@link com.jiovan.spring.starter.injectiondefense.composer.InjectionDetector} backed by libinjection-jvm lexical and fingerprint analysis
 *
 * @author David Hsing
 *
 * @see LibInjection
 */
public class LibInjectionDetector implements InjectionDetector {
    @Override
    public boolean maybeSqlInjection(@Nullable CharSequence sequence) {
        return sequence != null && LibInjection.isSQLi(sequence.toString());
    }

    @Override
    public boolean maybeSqlInjection(@Nullable CharSequence... sequences) {
        return sequences != null && Arrays.stream(sequences).anyMatch(this::maybeSqlInjection);
    }

    @Override
    public boolean maybeXssInjection(@Nullable CharSequence sequence) {
        return sequence != null && LibInjection.isXSS(sequence.toString());
    }

    @Override
    public boolean maybeXssInjection(@Nullable CharSequence... sequences) {
        return sequences != null && Arrays.stream(sequences).anyMatch(this::maybeXssInjection);
    }
}
