---
title: Cobalt Strike C2 Memory Evasion
date: 2024-08-04 10:40:00 +0300
categories: [Maldev, Evasion]
tags: [Evasion]     # TAG names should always be lowercase
---

# Cobalt Strike C2 Memory Evasion


## Intro

Cobalt Strike is a popular tool among red teams for simulating advanced threats and conducting penetration testing. However, its widespread use has made it a common target for detection by security solutions. In particular, memory-based detection methods can identify Cobalt Strike's presence during an engagement. This write-up explores techniques to evade memory-based detection, focusing on avoiding detection by YARA rules.

## Understanding the Detection Mechanism

![image](https://github.com/user-attachments/assets/a74298ea-c11e-4857-b38c-6f7e088497eb)


YARA rules are used to identify and classify malware based on patterns and strings within files and memory. A typical YARA rule for detecting Cobalt Strike might look for specific strings or behaviors indicative of the tool. For instance, the following rule targets specific strings:

```javascript
rule Windows_Trojan_CobaltStrike_3dc22d14 {
    meta:
        author = "Elastic Security"
        id = "3dc22d14-a2f4-49cd-a3a8-3f071eddf028"
        fingerprint = "0e029fac50ffe8ea3fc5bc22290af69e672895eaa8a1b9f3e9953094c133392c"
        creation_date = "2023-05-09"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "7898194ae0244611117ec948eb0b0a5acbc15cd1419b1ecc553404e63bc519f9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "%02d/%02d/%02d %02d:%02d:%02d" fullword
        $a2 = "%s as %s\\%s: %d" fullword
    condition:
        all of them
}
```
This rule looks for specific date/time and path formatting strings. To evade detection, we need to modify these strings in our payload.


