[English](README.md) | [簡體中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md)

# 注入防禦 Spring Boot Starter

為 Spring Boot 應用提供簡單的注入防禦，用於防範 SQL 注入與 XSS 注入。

## ⚠️ 安全範圍 — 請先閱讀

> **此 starter 只是一個輔助性的啟發式防禦層，並非安全邊界。**

檢測採用啟發式且刻意保持輕量。預設的 `hybrid` 策略結合了
正規表示式啟發式方法與 libinjection 的詞法及指紋分析，以獲得最大的
覆蓋範圍；也可單獨使用 `simple` 與 `libinjection`。任何策略都會釋出告警
事件（或丟擲異常），但檢測**仍可能被非常規攻擊手段繞過**。
它絕不能成為你唯一的防線：

- **SQL 注入**必須透過**引數化查詢 / PreparedStatement / ORM** 來防範。
  任何請求過濾都無法替代這一點。
- **XSS** 必須在服務端/模板層透過**上下文相關的輸出轉義**來防範
  （理想情況下還應設定**內容安全策略 Content Security Policy**）。僅對輸入進行清理是不夠的。
- 檢測僅掃描**請求引數**（表單/URL）。請求頭、Cookie、路徑變數
  以及 JSON 請求體**不在**過濾器的檢查範圍內。
- XSS 清理僅作用於透過所提供的請求包裝器讀取的值；直接讀取
  原始請求的程式碼會繞過該清理。

請將此 starter 用作**預警與粗粒度過濾機制**，它是補充而非
替代——完善的應用層安全實踐。

## 快速開始

- 匯入相依性

```xml
    <dependency>
        <groupId>com.jiovan.spring.starter</groupId>
        <artifactId>injection-defense-spring-boot-starter</artifactId>
        <version>LATEST</version>
    </dependency>
```

> 預設情況下，此 starter 會自動生效，你可以透過 `jiovan.injection-defense.enabled = false` 關閉它。

- 使用字首 `jiovan.injection-defense` 設定 Spring Boot 的 `application.yml`（**可選**）

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

### 檢測策略（`defender-type`）

檢測策略可透過 `InjectionDetector` 策略介面進行插拔。使用以下設定選擇：
`jiovan.injection-defense.defender-type`:

| 取值 | 策略 | 說明 |
|--------------------|---------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `hybrid`（預設） | `HybridInjectionDetector` | 結合兩種策略：**任一**策略檢測到威脅即進行攔截，可互補盲區，代價是誤報率略高。當最看重檢測覆蓋率時推薦使用。 |
| `simple` | `SimpleInjectionDetector` | 內建正規表示式啟發式檢測。無額外成本，可捕獲常見明顯載荷，但容易被繞過。 |
| `libinjection` | `LibInjectionDetector` | 使用 [libinjection-jvm](https://github.com/cloud-apim/libinjection-jvm) 的詞法與指紋分析。可檢測 `simple` 遺漏的混淆載荷（註釋、`1 OR 1=1`、多語句），但會漏掉少數僅靠正則識別的模式。 |

```yml
jiovan:
    injection-defense:
        defender-type: simple        # opt out of the default hybrid strategy if needed
```

你也可以透過宣告一個 `InjectionDetector` Bean 來提供自己的檢測器；當存在自定義 Bean 時，自動設定的
檢測器會讓位（`@ConditionalOnMissingBean`）。

> 注意：切換策略會改變檢測行為（檢出率與誤報率）。
> 在更改預設策略前，請用你自己的攻擊載荷集進行驗證。

## 文件

- GitHub：https://github.com/jiovan-labs/injection-defense-spring-boot-starter

## 環境要求

- jdk 17+

## 許可證

本專案採用 [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) 許可證。

請參閱 `NOTICE.txt` 檔案瞭解所需的宣告與歸屬資訊。

## 捐贈

喜歡這個工具包嗎？歡迎[向我們捐贈](https://jiovan.com/donation)以支援開發。

## 版權

北京玖漫科技有限公司

## 網站

- 玖漫：https://jiovan.com
