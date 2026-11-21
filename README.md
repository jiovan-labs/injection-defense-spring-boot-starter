[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md)

# Injection Defense Spring Boot Starter

Spring Boot application enables a simple injection defense, to prevent SQL injections and XSS injections.

## ⚠️ Security Scope — Read First

> **This starter is an auxiliary, heuristic defense layer — not a security boundary.**

Detection is heuristic and intentionally lightweight. The default `hybrid` strategy combines
regular-expression heuristics with libinjection's lexical and fingerprint analysis for maximum
coverage; `simple` and `libinjection` are available individually. Any strategy publishes alert
events (or throws exceptions), but detection **can still be bypassed by uncommon attack vectors**.
It must never be your only line of defense:

- **SQL injection** must be prevented with **parameterized queries / PreparedStatement / ORM**.
  No amount of request filtering can replace this.
- **XSS** must be prevented with **context-aware output escaping** on the server/template side
  (and ideally a **Content Security Policy**). Input cleaning alone is insufficient.
- Detection scans **request parameters only** (form/URL). Request headers, cookies, path variables
  and JSON bodies are **not** inspected by the filter.
- XSS cleaning is applied only to values read through the provided request wrapper; code reading
  the raw request directly bypasses it.

Use this starter as an **early-warning and coarse filtering mechanism** that complements — and
never replaces — sound application-level security practices.

## Quickstart

- Import dependencies

```xml
    <dependency>
        <groupId>com.jiovan.spring.starter</groupId>
        <artifactId>injection-defense-spring-boot-starter</artifactId>
        <version>LATEST</version>
    </dependency>
```

> By default, this starter will auto take effect, you can turn it off by `jiovan.injection-defense.enabled = false`

- Configure Spring Boot `application.yml` with prefix `jiovan.injection-defense` (**Optional**)

```yml
jiovan:
    injection-defense:
        defender-type: hybrid        # detection strategy: hybrid (default) | simple | libinjection
        defender-filter:
            filter-paths:
                - '/**'
            exclude-paths:
                - '/foo/**'
                - '/bar/**'
        sql-protection:
            throws-exception: true
        xss-protection:
            throws-exception: true
```

### Detection strategies (`defender-type`)

The detection strategy is pluggable via the `InjectionDetector` strategy interface. Select it with
`jiovan.injection-defense.defender-type`:

| Value              | Strategy                  | Notes                                                                                                                                                                                                                                    |
|--------------------|---------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `hybrid` (default) | `HybridInjectionDetector` | Combines both strategies: intercepts when **either** detects a threat, covering each other's blind spots at the cost of a slightly higher false-positive rate. Recommended when detection coverage matters most.                         |
| `simple`           | `SimpleInjectionDetector` | Built-in regular-expression heuristics. Zero extra cost, catches common obvious payloads, but easy to bypass.                                                                                                                            |
| `libinjection`     | `LibInjectionDetector`    | Uses [libinjection-jvm](https://github.com/cloud-apim/libinjection-jvm) lexical + fingerprint analysis. Detects obfuscated payloads (comments, `1 OR 1=1`, multi-statements) that `simple` misses, but misses a few regex-only patterns. |

```yml
jiovan:
    injection-defense:
        defender-type: simple        # opt out of the default hybrid strategy if needed
```

You can also supply your own detector by declaring an `InjectionDetector` bean; the autoconfigured
one backs off when a custom bean is present (`@ConditionalOnMissingBean`).

> Note: switching strategy changes detection behaviour (detection rate and false-positive rate).
> Validate it against your own payload set before changing the default.

## Document

- Github: https://github.com/jiovan-labs/injection-defense-spring-boot-starter

## Requirement

- jdk 17+

## License

This project is under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)

See the `NOTICE.txt` file for required notices and attributions.

## Donation

You like this package? Then [donate to us](https://jiovan.com/donation) to support the development.

## Copyright

Beijing Jiovan Technology Ltd.

## Website

- Jiovan: https://jiovan.com
