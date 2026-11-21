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

package com.jiovan.spring.starter.injectiondefense.filter;


import java.io.IOException;
import java.util.Map;
import jakarta.annotation.Nonnull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.BooleanUtils;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.util.CollectionUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import com.jiovan.plexus.common.toolkit.util.BooleanUtilsWraps;
import com.jiovan.plexus.common.toolkit.util.JsoupParserWraps;
import com.jiovan.plexus.spring.toolkit.util.AntPathWraps;
import com.jiovan.plexus.spring.toolkit.util.UriUtilsWraps;
import com.jiovan.spring.starter.injectiondefense.composer.InjectionDetector;
import com.jiovan.spring.starter.injectiondefense.event.MaliciousSqlEvent;
import com.jiovan.spring.starter.injectiondefense.event.MaliciousXssEvent;
import com.jiovan.spring.starter.injectiondefense.exception.MaliciousSqlException;
import com.jiovan.spring.starter.injectiondefense.exception.MaliciousXssException;
import com.jiovan.spring.starter.injectiondefense.property.InjectionDefenseProperties;
import com.jiovan.spring.starter.injectiondefense.support.InjectionDefenseRequestWrapper;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.Setter;


/**
 * {@link jakarta.servlet.Filter} that performs heuristic SQL injection and XSS checks on
 * request parameters, and optionally cleans parameter values with Jsoup.
 * <p>
 * <b>Scope and limitations:</b>
 * <ul>
 *     <li>Detection inspects {@code request.getParameterMap()} only. Request headers, cookies,
 *         path variables and request bodies are not scanned here.</li>
 *     <li>Detection is pattern-based and can be bypassed; it is an auxiliary early-warning layer,
 *         not a security boundary. It does not replace parameterized queries or output escaping.</li>
 *     <li>XSS cleaning is applied to values read through {@link InjectionDefenseRequestWrapper};
 *         code that reads the original request directly bypasses it.</li>
 * </ul>
 *
 * @author David Hsing
 *
 * @see org.springframework.web.filter.OncePerRequestFilter
 * @see com.jiovan.spring.starter.injectiondefense.composer.InjectionDetector
 * @see com.jiovan.spring.starter.injectiondefense.support.InjectionDefenseRequestWrapper
 */
@RequiredArgsConstructor
@AllArgsConstructor
@SuppressWarnings("unused")
public class InjectionDefenseFilter extends OncePerRequestFilter implements ApplicationEventPublisherAware {
    private final InjectionDefenseProperties properties;
    private final InjectionDetector detector;

    @Setter
    private ApplicationEventPublisher applicationEventPublisher;

    @Override
    protected void doFilterInternal(@Nonnull HttpServletRequest request, @Nonnull HttpServletResponse response, @Nonnull FilterChain chain) throws ServletException, IOException {
        InjectionDefenseProperties.SqlProtection sqlProps = properties.getSqlProtection();
        InjectionDefenseProperties.XssProtection xssProps = properties.getXssProtection();
        boolean sqlValidate = BooleanUtils.isTrue(sqlProps.getEnabled()), xssValidate = BooleanUtils.isTrue(xssProps.getEnabled());
        Map<String, String[]> parameters = request.getParameterMap();
        if (!CollectionUtils.isEmpty(parameters)) {
            for (Map.Entry<String, String[]> entry : parameters.entrySet()) {
                if (sqlValidate && detector.maybeSqlInjection(entry.getValue())) {
                    if (applicationEventPublisher != null) {
                        applicationEventPublisher.publishEvent(new MaliciousSqlEvent(request, entry.getKey(), entry.getValue()));
                    }
                    if (BooleanUtils.isTrue(sqlProps.getThrowsException())) {
                        throw new MaliciousSqlException("Request may be a malicious access", entry.getKey(), entry.getValue());
                    }
                }
                if (xssValidate && detector.maybeXssInjection(entry.getValue())) {
                    if (applicationEventPublisher != null) {
                        applicationEventPublisher.publishEvent(new MaliciousXssEvent(request, entry.getKey(), entry.getValue()));
                    }
                    if (BooleanUtils.isTrue(xssProps.getThrowsException())) {
                        throw new MaliciousXssException("Request may be a malicious access", entry.getKey(), entry.getValue());
                    }
                }
            }
        }
        if (xssValidate && BooleanUtils.isTrue(xssProps.getCleanParams())) {
            InjectionDefenseRequestWrapper wrapper = new InjectionDefenseRequestWrapper(request, true, JsoupParserWraps.getSafelist(xssProps.getWhitelistType()));
            chain.doFilter(wrapper, response);
            return;
        }
        chain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(@Nonnull HttpServletRequest request) throws ServletException {
        InjectionDefenseProperties.DefenderFilter filterProps = properties.getDefenderFilter();
        if (!CollectionUtils.isEmpty(filterProps.getExcludePaths())) {
            String servletPath = UriUtilsWraps.getServletPath(request);
            return AntPathWraps.matchAnyPatterns(servletPath, filterProps.getExcludePaths());
        }
        InjectionDefenseProperties.SqlProtection sqlProps = properties.getSqlProtection();
        InjectionDefenseProperties.XssProtection xssProps = properties.getXssProtection();
        if (BooleanUtilsWraps.allNotTrue(sqlProps.getEnabled(), xssProps.getEnabled())) {
            return true;
        }
        return super.shouldNotFilter(request);
    }
}
