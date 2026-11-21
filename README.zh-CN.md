[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md)

# 注入防御 Spring Boot Starter

为 Spring Boot 应用提供简单的注入防御，用于防范 SQL 注入与 XSS 注入。

## ⚠️ 安全范围 — 请先阅读

> **此 starter 只是一个辅助性的启发式防御层，并非安全边界。**

检测采用启发式且刻意保持轻量。默认的 `hybrid` 策略结合了
正则表达式启发式方法与 libinjection 的词法及指纹分析，以获得最大的
覆盖范围；也可单独使用 `simple` 与 `libinjection`。任何策略都会发布告警
事件（或抛出异常），但检测**仍可能被非常规攻击手段绕过**。
它绝不能成为你唯一的防线：

- **SQL 注入**必须通过**参数化查询 / PreparedStatement / ORM** 来防范。
  任何请求过滤都无法替代这一点。
- **XSS** 必须在服务端/模板层通过**上下文相关的输出转义**来防范
  （理想情况下还应配置**内容安全策略 Content Security Policy**）。仅对输入进行清理是不够的。
- 检测仅扫描**请求参数**（表单/URL）。请求头、Cookie、路径变量
  以及 JSON 请求体**不在**过滤器的检查范围内。
- XSS 清理仅作用于通过所提供的请求包装器读取的值；直接读取
  原始请求的代码会绕过该清理。

请将此 starter 用作**预警与粗粒度过滤机制**，它是补充而非
替代——完善的应用层安全实践。

## 快速开始

- 导入依赖

```xml
    <dependency>
        <groupId>com.jiovan.spring.starter</groupId>
        <artifactId>injection-defense-spring-boot-starter</artifactId>
        <version>LATEST</version>
    </dependency>
```

> 默认情况下，此 starter 会自动生效，你可以通过 `jiovan.injection-defense.enabled = false` 关闭它。

- 使用前缀 `jiovan.injection-defense` 配置 Spring Boot 的 `application.yml`（**可选**）

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

### 检测策略（`defender-type`）

检测策略可通过 `InjectionDetector` 策略接口进行插拔。使用以下配置选择：
`jiovan.injection-defense.defender-type`:

| 取值 | 策略 | 说明 |
|--------------------|---------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `hybrid`（默认） | `HybridInjectionDetector` | 结合两种策略：**任一**策略检测到威胁即进行拦截，可互补盲区，代价是误报率略高。当最看重检测覆盖率时推荐使用。 |
| `simple` | `SimpleInjectionDetector` | 内置正则表达式启发式检测。无额外成本，可捕获常见明显载荷，但容易被绕过。 |
| `libinjection` | `LibInjectionDetector` | 使用 [libinjection-jvm](https://github.com/cloud-apim/libinjection-jvm) 的词法与指纹分析。可检测 `simple` 遗漏的混淆载荷（注释、`1 OR 1=1`、多语句），但会漏掉少数仅靠正则识别的模式。 |

```yml
jiovan:
    injection-defense:
        defender-type: simple        # opt out of the default hybrid strategy if needed
```

你也可以通过声明一个 `InjectionDetector` Bean 来提供自己的检测器；当存在自定义 Bean 时，自动配置的
检测器会让位（`@ConditionalOnMissingBean`）。

> 注意：切换策略会改变检测行为（检出率与误报率）。
> 在更改默认策略前，请用你自己的攻击载荷集进行验证。

## 文档

- GitHub：https://github.com/jiovan-labs/injection-defense-spring-boot-starter

## 环境要求

- jdk 17+

## 许可证

本项目采用 [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) 许可证。

请参阅 `NOTICE.txt` 文件了解所需的声明与归属信息。

## 捐赠

喜欢这个工具包吗？欢迎[向我们捐赠](https://jiovan.com/donation)以支持开发。

## 版权

北京玖漫科技有限公司

## 网站

- 玖漫：https://jiovan.com
