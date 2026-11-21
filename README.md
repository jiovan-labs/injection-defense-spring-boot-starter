# Injection Defense Spring Boot Starter

Spring Boot application enables a simple injection defense, to prevent SQL injections and XSS injections.

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
