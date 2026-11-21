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

package com.jiovan.spring.starter.injectiondefense.config;


import java.util.Optional;
import jakarta.annotation.Nonnull;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.jiovan.plexus.common.toolkit.util.CollectionPlainWraps;
import com.jiovan.plexus.common.toolkit.util.MapPlainWraps;
import com.jiovan.plexus.spring.condition.annotation.ConditionalOnAnyBooleanProperties;
import com.jiovan.spring.starter.injectiondefense.composer.InjectionDetector;
import com.jiovan.spring.starter.injectiondefense.composer.impl.HybridInjectionDetector;
import com.jiovan.spring.starter.injectiondefense.composer.impl.LibInjectionDetector;
import com.jiovan.spring.starter.injectiondefense.composer.impl.SimpleInjectionDetector;
import com.jiovan.spring.starter.injectiondefense.enumeration.InjectionDefenderType;
import com.jiovan.spring.starter.injectiondefense.filter.InjectionDefenseFilter;
import com.jiovan.spring.starter.injectiondefense.jackson.InjectionDefenseModule;
import com.jiovan.spring.starter.injectiondefense.property.InjectionDefenseProperties;
import tools.jackson.databind.ObjectMapper;


/**
 * Configuration of injection defense
 *
 * @author David Hsing
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnBooleanProperty(prefix = InjectionDefenseAutoConfiguration.PROPERTIES_PREFIX, name = "enabled", matchIfMissing = true)
@ConditionalOnWebApplication
@EnableConfigurationProperties(value = InjectionDefenseProperties.class)
public class InjectionDefenseAutoConfiguration {
    public static final String PROPERTIES_PREFIX = "jiovan.injection-defense";    // $NON-NLS-1$
    public static final String JACKSON_MODULE = "jacksonInjectionDefenseModule";    // $NON-NLS-1$

    /**
     * Returns the {@link InjectionDetector} selected by {@code defenderType}.
     *
     * @param properties the injection defense properties
     *
     * @return the configured composer strategy
     */
    @Bean
    @ConditionalOnMissingBean(value = InjectionDetector.class)
    public InjectionDetector injectionDetector(@Nonnull InjectionDefenseProperties properties) {
        return switch (properties.getDefenderType() != null ? properties.getDefenderType() : InjectionDefenderType.HYBRID) {
            case SIMPLE -> new SimpleInjectionDetector();
            case LIBINJECTION -> new LibInjectionDetector();
            default -> new HybridInjectionDetector();
        };
    }

    /**
     * Returns a {@link org.springframework.boot.web.servlet.FilterRegistrationBean} that registers the {@link com.jiovan.spring.starter.injectiondefense.filter.InjectionDefenseFilter}
     *
     * @param properties the injection defense properties used to configure the filter order, URL patterns and init parameters
     * @param publisher the application event publisher passed to the filter
     * @param detector the injection composer strategy
     *
     * @return the registration bean for the {@link com.jiovan.spring.starter.injectiondefense.filter.InjectionDefenseFilter}
     */
    @Bean
    @ConditionalOnMissingBean(value = InjectionDefenseFilter.class, parameterizedContainer = FilterRegistrationBean.class)
    public FilterRegistrationBean<InjectionDefenseFilter> injectionDefenderFilterRegistration(@Nonnull InjectionDefenseProperties properties, @Nonnull ApplicationEventPublisher publisher, @Nonnull InjectionDetector detector) {
        InjectionDefenseFilter filter = new InjectionDefenseFilter(properties, detector, publisher);
        FilterRegistrationBean<InjectionDefenseFilter> result = new FilterRegistrationBean<>(filter);
        InjectionDefenseProperties.DefenderFilter props = properties.getDefenderFilter();
        Optional.ofNullable(props.getFilerOrder()).ifPresent(result::setOrder);
        CollectionPlainWraps.ifNotEmpty(props.getFilterPaths(), result::setUrlPatterns);
        MapPlainWraps.ifNotEmpty(props.getFilterParams(), result::setInitParameters);
        return result;
    }

    /**
     * Returns a Jackson Module that registers the injection defense deserializer
     *
     * @param properties the injection defense properties used to configure the deserializer
     * @param publisher the application event publisher passed to the deserializer
     * @param detector the injection composer strategy
     *
     * @return a module that registers the deserializer for {@link java.lang.String}
     */
    @Bean(name = JACKSON_MODULE)
    @ConditionalOnAnyBooleanProperties(value = {
        @ConditionalOnBooleanProperty(prefix = InjectionDefenseAutoConfiguration.PROPERTIES_PREFIX + ".sql-protection", name = "enabled", matchIfMissing = true),
        @ConditionalOnBooleanProperty(prefix = InjectionDefenseAutoConfiguration.PROPERTIES_PREFIX + ".xss-protection", name = "enabled", matchIfMissing = true)
    })
    @ConditionalOnClass(value = ObjectMapper.class)
    @ConditionalOnMissingBean(name = JACKSON_MODULE)
    public InjectionDefenseModule jacksonInjectionDefenseModule(@Nonnull InjectionDefenseProperties properties, @Nonnull ApplicationEventPublisher publisher, @Nonnull InjectionDetector detector) {
        return new InjectionDefenseModule(properties, publisher, detector);
    }
}
