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

package com.jiovan.spring.starter.injectiondefense.support;


import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;
import org.springframework.web.util.ContentCachingRequestWrapper;
import com.jiovan.plexus.common.toolkit.util.MapPlainWraps;
import lombok.Getter;
import lombok.Setter;


/**
 * {@link org.springframework.web.util.ContentCachingRequestWrapper} for injection defense
 *
 * @author David Hsing
 */
@Getter
@Setter
@SuppressWarnings("unused")
public class InjectionDefenseRequestWrapper extends ContentCachingRequestWrapper {
    private boolean xssClean = true;
    private Safelist xssWhitelist;

    public InjectionDefenseRequestWrapper(@Nonnull HttpServletRequest request) {
        super(request, -1);
    }

    public InjectionDefenseRequestWrapper(@Nonnull HttpServletRequest request, int contentCacheLimit) {
        super(request, contentCacheLimit);
    }

    public InjectionDefenseRequestWrapper(@Nonnull HttpServletRequest request, boolean xssClean, @Nullable Safelist xssWhitelist) {
        super(request, -1);
        this.xssClean = xssClean;
        this.xssWhitelist = xssWhitelist;
    }

    @Override
    @SuppressWarnings({"NullableProblems", "DataFlowIssue"})
    public String getParameter(@Nullable String name) {
        if (StringUtils.isBlank(name)) {
            return null;
        }
        String result = super.getParameter(name);
        return (StringUtils.isBlank(result) || !xssClean || xssWhitelist == null) ? result : Jsoup.clean(result, xssWhitelist);
    }

    @Override
    @SuppressWarnings("NullableProblems")
    public Map<String, String[]> getParameterMap() {
        Map<String, String[]> origin = super.getParameterMap();
        if (MapPlainWraps.isEmpty(origin) || !xssClean || xssWhitelist == null) {
            return origin;
        }
        Map<String, String[]> result = new LinkedHashMap<>(origin.size());
        for (Map.Entry<String, String[]> entry : origin.entrySet()) {
            String[] values;
            if (ArrayUtils.isEmpty(entry.getValue()) || !xssClean || xssWhitelist == null) {
                values = entry.getValue();
            } else {
                values = Arrays.stream(entry.getValue()).map(element -> StringUtils.isBlank(element) ? element : Jsoup.clean(element, xssWhitelist)).toArray(String[]::new);
            }
            result.put(entry.getKey(), values);
        }
        return result;
    }

    @Override
    @SuppressWarnings({"NullableProblems", "DataFlowIssue"})
    public String[] getParameterValues(@Nullable String name) {
        if (StringUtils.isBlank(name)) {
            return null;
        }
        String[] result = super.getParameterValues(name);
        if (ArrayUtils.isEmpty(result) || !xssClean || xssWhitelist == null) {
            return result;
        }
        return Arrays.stream(result).map(element -> StringUtils.isBlank(element) ? element : Jsoup.clean(element, xssWhitelist)).toArray(String[]::new);
    }

    /**
     * Returns cookies whose values are cleaned in place when XSS cleaning is active.
     * <p>
     * <b>Caveat:</b> this mutates the {@link Cookie} instances returned by the underlying request
     * and only affects code that reads cookies through this wrapper. Code holding a reference to
     * the original request, or reading cookies before this wrapper is applied, is not affected.
     * Do not treat this as a reliable cookie sanitization boundary.
     *
     * @return the cookies, with cleaned values when applicable
     */
    @Override
    public Cookie[] getCookies() {
        Cookie[] result = super.getCookies();
        if (ArrayUtils.isNotEmpty(result)) {
            for (Cookie cookie : result) {
                String value = (StringUtils.isBlank(cookie.getValue()) || !xssClean || xssWhitelist == null) ? cookie.getValue() : Jsoup.clean(cookie.getValue(), xssWhitelist);
                cookie.setValue(value);
            }
        }
        return result;
    }

    @Override
    public String getHeader(@Nullable String name) {
        if (StringUtils.isBlank(name)) {
            return null;
        }
        String result = super.getHeader(name);
        return (StringUtils.isBlank(result) || !xssClean || xssWhitelist == null) ? result : Jsoup.clean(result, xssWhitelist);
    }

    /**
     * Returns the raw value of the request parameter with the given {@code name} bypassing injection defense processing
     *
     * @param name the name of the parameter, may be {@code null} or blank
     *
     * @return the raw parameter value, or {@code null} if {@code name} is blank
     */

    public String getRawParameter(@Nullable String name) {
        return StringUtils.isBlank(name) ? null : super.getParameter(name);
    }

    /**
     * Returns the raw parameter map of the wrapped request bypassing injection defense processing
     *
     * @return the raw map of request parameter names to their values
     */

    public Map<String, String[]> getRawParameterMap() {
        return super.getParameterMap();
    }

    /**
     * Returns all raw values of the request parameter with the given {@code name} bypassing injection defense processing
     *
     * @param name the name of the parameter, may be {@code null} or blank
     *
     * @return the raw parameter values, or {@code null} if {@code name} is blank
     */

    public String[] getRawParameterValues(@Nullable String name) {
        return StringUtils.isBlank(name) ? null : super.getParameterValues(name);
    }

    /**
     * Returns the raw cookies of the wrapped request bypassing injection defense processing
     *
     * @return the raw cookies, or {@code null} if the request contains no cookies
     */

    public Cookie[] getRawCookies() {
        return super.getCookies();
    }

    /**
     * Returns the raw value of the request header with the given {@code name} bypassing injection defense processing
     *
     * @param name the name of the header, may be {@code null} or blank
     *
     * @return the raw header value, or {@code null} if {@code name} is blank
     */

    public String getRawHeader(@Nullable String name) {
        return StringUtils.isBlank(name) ? null : super.getHeader(name);
    }
}
