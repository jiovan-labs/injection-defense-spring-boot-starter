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
    public static final String JACKSON_INJECTION_DEFENDER_CUSTOMIZER = "jacksonInjectionDefenseCustomizer";    // $NON-NLS-1$

    /**
     * Returns a {@link org.springframework.boot.web.servlet.FilterRegistrationBean} that registers the {@link com.jiovan.spring.starter.injectiondefense.filter.InjectionDefenseFilter}
     *
     * @param properties the injection defense properties used to configure the filter order, URL patterns and init parameters
     * @param publisher the application event publisher passed to the filter
     *
     * @return the registration bean for the {@link com.jiovan.spring.starter.injectiondefense.filter.InjectionDefenseFilter}
     */

    @Bean
    @ConditionalOnMissingBean(value = InjectionDefenseFilter.class, parameterizedContainer = FilterRegistrationBean.class)
    public FilterRegistrationBean<InjectionDefenseFilter> injectionDefenderFilterRegistration(@Nonnull InjectionDefenseProperties properties, @Nonnull ApplicationEventPublisher publisher) {
        InjectionDefenseFilter filter = new InjectionDefenseFilter(properties, publisher);
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
     *
     * @return a module that registers the deserializer for {@link java.lang.String}
     */

    @Bean(name = JACKSON_INJECTION_DEFENDER_CUSTOMIZER)
    @ConditionalOnAnyBooleanProperties(value = {
        @ConditionalOnBooleanProperty(prefix = InjectionDefenseAutoConfiguration.PROPERTIES_PREFIX + ".sql-protection", name = "enabled", matchIfMissing = true),
        @ConditionalOnBooleanProperty(prefix = InjectionDefenseAutoConfiguration.PROPERTIES_PREFIX + ".xss-protection", name = "enabled", matchIfMissing = true)
    })
    @ConditionalOnClass(value = ObjectMapper.class)
    @ConditionalOnMissingBean(name = JACKSON_INJECTION_DEFENDER_CUSTOMIZER)
    public InjectionDefenseModule jacksonInjectionDefenseCustomizer(@Nonnull InjectionDefenseProperties properties, @Nonnull ApplicationEventPublisher publisher) {
        return new InjectionDefenseModule(properties, publisher);
    }
}
