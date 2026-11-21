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


import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.util.CollectionUtils;
import com.jiovan.plexus.common.toolkit.constant.CharVariantConst;
import com.jiovan.plexus.common.toolkit.util.BooleanUtilsWraps;
import com.jiovan.plexus.common.toolkit.util.JsoupParserWraps;
import com.jiovan.plexus.spring.toolkit.util.AntPathWraps;
import com.jiovan.plexus.spring.toolkit.util.UriUtilsWraps;
import com.jiovan.plexus.spring.toolkit.util.WebUtilsWraps;
import com.jiovan.spring.starter.injectiondefense.event.MaliciousSqlEvent;
import com.jiovan.spring.starter.injectiondefense.event.MaliciousXssEvent;
import com.jiovan.spring.starter.injectiondefense.exception.MaliciousSqlException;
import com.jiovan.spring.starter.injectiondefense.exception.MaliciousXssException;
import com.jiovan.spring.starter.injectiondefense.property.InjectionDefenseProperties;
import com.jiovan.spring.starter.injectiondefense.util.InjectionDefenseUtils;
import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.ValueDeserializer;


/**
 * {@link tools.jackson.databind.ValueDeserializer} for injection defense
 *
 * @author David Hsing
 */
@SuppressWarnings("unused")
public class InjectionDefenseDeserializer extends ValueDeserializer<String> {
    private final InjectionDefenseProperties properties;
    private final ApplicationEventPublisher publisher;

    public InjectionDefenseDeserializer(InjectionDefenseProperties properties, ApplicationEventPublisher publisher) {
        this.properties = properties;
        this.publisher = publisher;
    }

    @Override
    public String deserialize(@Nullable JsonParser parser, @Nullable DeserializationContext context) throws JacksonException {
        if (parser == null) {
            return null;
        }
        String fieldValue = parser.getString();
        if (StringUtils.isBlank(fieldValue)) {
            return fieldValue;
        }
        HttpServletRequest request = WebUtilsWraps.getContextServletRequest();
        InjectionDefenseProperties.DefenderFilter filterProps = properties.getDefenderFilter();
        InjectionDefenseProperties.SqlProtection sqlProps = properties.getSqlProtection();
        InjectionDefenseProperties.XssProtection xssProps = properties.getXssProtection();
        if (request == null || BooleanUtilsWraps.allNotTrue(sqlProps.getEnabled(), xssProps.getEnabled())) {
            return fieldValue;
        }
        String servletPath = UriUtilsWraps.getServletPath(request);
        boolean sqlValidate = BooleanUtils.isTrue(sqlProps.getEnabled()) && (CollectionUtils.isEmpty(filterProps.getExcludePaths()) || !AntPathWraps.matchAnyPatterns(servletPath, filterProps.getExcludePaths()));
        boolean xssValidate = BooleanUtils.isTrue(xssProps.getEnabled()) && (CollectionUtils.isEmpty(filterProps.getExcludePaths()) || !AntPathWraps.matchAnyPatterns(servletPath, filterProps.getExcludePaths()));
        if (!sqlValidate && !xssValidate) {
            return fieldValue;
        }
        String fieldName = parser.currentName();
        if (sqlValidate && InjectionDefenseUtils.maybeSqlInjection(fieldValue)) {
            if (publisher != null) {
                publisher.publishEvent(new MaliciousSqlEvent(request, fieldName, fieldValue));
            }
            if (BooleanUtils.isTrue(sqlProps.getThrowsException())) {
                throw new MaliciousSqlException("Request may be a malicious access", fieldName, fieldValue);
            }
        }
        if (xssValidate) {
            if (InjectionDefenseUtils.maybeXssInjection(fieldValue)) {
                if (publisher != null) {
                    publisher.publishEvent(new MaliciousXssEvent(request, fieldName, fieldValue));
                }
                if (BooleanUtils.isTrue(xssProps.getThrowsException())) {
                    throw new MaliciousXssException("Request may be a malicious access", fieldName, fieldValue);
                }
            }
            if (BooleanUtils.isTrue(xssProps.getCleanParams()) && StringUtils.containsAny(fieldValue, CharVariantConst.ANGLE_BRACKET_LEFT, CharVariantConst.ANGLE_BRACKET_RIGHT)) {
                fieldValue = JsoupParserWraps.cleanWith(fieldValue, xssProps.getWhitelistType());
            }
        }
        return fieldValue;
    }
}
