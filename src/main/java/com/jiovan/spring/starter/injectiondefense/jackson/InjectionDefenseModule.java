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

package com.jiovan.spring.starter.injectiondefense.jackson;


import jakarta.annotation.Nonnull;
import org.springframework.context.ApplicationEventPublisher;
import com.jiovan.spring.starter.injectiondefense.property.InjectionDefenseProperties;
import tools.jackson.databind.module.SimpleModule;


/**
 * Jackson module that registers the {@link InjectionDefenseDeserializer} for {@link String}
 *
 * @author David Hsing
 */
public class InjectionDefenseModule extends SimpleModule {
    public InjectionDefenseModule(@Nonnull InjectionDefenseProperties properties, @Nonnull ApplicationEventPublisher publisher) {
        super("InjectionDefenseModule");
        addDeserializer(String.class, new InjectionDefenseDeserializer(properties, publisher));
    }
}
