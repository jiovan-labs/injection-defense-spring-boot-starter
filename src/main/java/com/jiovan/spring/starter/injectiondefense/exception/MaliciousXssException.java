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

package com.jiovan.spring.starter.injectiondefense.exception;


import jakarta.annotation.Nullable;
import com.jiovan.plexus.common.toolkit.exception.MaliciousAccessException;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.experimental.StandardException;


/**
 * Unchecked exception thrown when a request parameter may contain an XSS injection attempt.
 * <p>
 * This is raised by the heuristic detection layer of this starter and is <b>not</b> a substitute
 * for context-aware output escaping. See {@link com.jiovan.spring.starter.injectiondefense.filter.InjectionDefenseFilter}.
 *
 * @author David Hsing
 *
 * @see com.jiovan.spring.starter.injectiondefense.util.InjectionDefenseUtils
 */
@NoArgsConstructor
@Getter
@StandardException
@SuppressWarnings("unused")
public class MaliciousXssException extends MaliciousAccessException {
    private String paramName;
    private Object paramValue;

    public MaliciousXssException(@Nullable String message, @Nullable String paramName, @Nullable Object paramValue) {
        super(message);
        this.paramName = paramName;
        this.paramValue = paramValue;
    }

    public MaliciousXssException(@Nullable String message, @Nullable Throwable cause, @Nullable String paramName, @Nullable Object paramValue) {
        super(message, cause);
        this.paramName = paramName;
        this.paramValue = paramValue;
    }

    public MaliciousXssException(@Nullable Throwable cause, @Nullable String paramName, @Nullable Object paramValue) {
        super(cause);
        this.paramName = paramName;
        this.paramValue = paramValue;
    }
}
