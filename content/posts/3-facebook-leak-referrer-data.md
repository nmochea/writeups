---
date: "2025-11-16T23:17:09+08:00"
draft: false
title: "Referrer Data Leakage in Facebook via Unvalidated data_uri Parameter"
summary: "An open redirect vulnerability was discovered in Facebook’s Privacy Checkup endpoint due to the ?back_uri= parameter being processed without any security filtering, allowing attackers to redirect users to malicious website."

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
An open redirect vulnerability was discovered in Facebook’s Privacy Checkup endpoint due to the `back_uri` parameter being processed without any security filtering, allowing attackers to redirect users to malicious website.

```
https://www.facebook.com/privacy/checking/blocking/
```

The issue occurred due to improper validation of the `back_uri` parameter. Because this endpoint did **not** pass outbound URLs through Facebook’s **Linkshim** protection mechanism, supplying an external URL such as `https://evil.com` resulted in an immediate redirect without any security checks. This allowed attackers to redirect Facebook users to arbitrary websites, facilitating phishing, malware distribution, and other social‑engineering attacks.

### **Root Cause Analysis**

While reviewing the source code of the Privacy Checkup page, it became clear that the `back_uri` parameter controlled the final redirect destination after users completed or exited the page.

Normally, Facebook enforces strict outbound‑link checks using **Linkshim**, which evaluates URLs against internal and external threat intelligence systems (McAfee, Google Safe Browsing, Websense, WOT, etc.).
However, this specific endpoint **did not route the `back_uri` value through Linkshim**, allowing any absolute URL to be accepted and used directly.

This means:

* The parameter received a full, attacker‑controlled external URL
* No sanitization or normalization was applied
* No Linkshim interstitial or warning was triggered
* The browser performed a direct redirect to the attacker’s site

This effectively created a **Linkshim bypass** via an unvalidated redirect parameter.

### **Attack Flow**

1. Attacker crafts a URL using the vulnerable endpoint with a malicious domain in `back_uri`.
2. Victim clicks the crafted Facebook link.
3. Facebook loads the Privacy Checkup page normally.
4. Once the page processes the `back_uri` parameter, the victim is redirected to the attacker’s domain.
5. Since Linkshim is bypassed, **no security warning or interstitial page appears**, increasing the effectiveness of phishing or malware attacks.

### **Proof of Concept (PoC)**

Directly injecting an external URL into the `back_uri` parameter triggers an immediate redirect:

```
https://www.facebook.com/privacy/checking/blocking/?back_uri=https://evil.com
```

Loading this URL results in:

* No Linkshim warning
* No sanitization
* A direct redirect to:

```
https://evil.com
```

### **Reproduction Steps**

1. Visit the target endpoint in a browser:

   ```
   https://www.facebook.com/privacy/checking/blocking/
   ```

2. Inspect the page source and locate the logic handling `back_uri`.

3. Append an external domain:

   ```
   ?back_uri=https://evil.com
   ```

4. Open the full URL:

   ```
   https://www.facebook.com/privacy/checking/blocking/?back_uri=https://evil.com
   ```

5. Observe that Facebook immediately redirects to the attacker‑controlled domain **without Linkshim** or any warning.

### **Disclosure Timeline**

* **October 13, 2020** — Vulnerability reported to Facebook Whitehat.
* **October 13, 2020** — Facebook team reproduced and began investigating.
* **October 16, 2020** — Patch deployed; Linkshim added to the endpoint.
* **October 22, 2020** — Bounty awarded.