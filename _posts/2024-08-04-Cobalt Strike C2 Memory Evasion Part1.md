---
title: Cobalt Strike C2 Memory Evasion Part 1
date: 2024-08-04 02:34:00 +0300
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


## Identifying and Modifying Strings

The first step is to locate the strings in your payload that match the YARA rule. If using a tool like strings doesn't show any results, the strings might be obfuscated or dynamically generated.

### Static Analysis

Start by reviewing the source code or binary to identify where these strings are created. Look for functions that format strings, such as _snprintf, sprintf, or printf.

![image](https://github.com/user-attachments/assets/b46c13cb-830a-4386-8406-0dd183e00a4f)

### Dynamic Analysis

create a memory dump while the payload is running 

![image](https://github.com/user-attachments/assets/9c698dc1-3873-4611-b077-af0d69c5ace4)

and search for the strings within the dump using tools like volatility:

![image](https://github.com/user-attachments/assets/cf972f25-7726-4ece-85a7-2a81585c9c5e)

![image](https://github.com/user-attachments/assets/167c29b7-5d00-4a91-b049-6ef5da8740e6)

we found the bad paces that have been flagged, although this method is simple and effective, from a practical point of view, we should not do this all the time, because we cannot determine the rules used by other security controls. 

If you modify the judgment rules to 3 and you only modify one of them, it will definitely not work. 

In addition, some format strings should not be modified directly, otherwise it may bring unexpected results to the program. 

For example, same as our case format strings are also detected in Windows_Trojan_CobaltStrike_3dc22d14 that we showen up. 


## The solution

The Sleep Mask Kit is a more sophisticated approach to evading memory-based detection.
It works by encrypting or obfuscating sensitive parts of the payload in memory, making it harder for detection mechanisms to identify them.

### How Sleep Mask Kit Works

The Sleep Mask Kit employs several techniques to evade memory-based detection:

- Encryption: The kit encrypts certain sections of the payload in memory. This ensures that the plaintext strings or patterns are not visible to detection mechanisms.

- Obfuscation: It obfuscates strings and patterns that might be detected by security solutions. Obfuscation involves altering the appearance of the data without changing its functionality.

- Dynamic Decryption: The encrypted sections are only decrypted at runtime when needed. This minimizes the window of opportunity for detection, as the sensitive data is only in its decrypted form for a short period.

- Polymorphism: The kit can generate different variants of the same payload, each with different encrypted strings or obfuscated patterns. This makes it harder for signature-based detection mechanisms to identify the payload.

![image](https://github.com/user-attachments/assets/d82df3db-7b2e-4489-8e8c-5842f5f981f3)

#### USERWX Configuration 

Before enabling Sleep Mask we need to understand the userwx

Whether to set the memory to readable, writable and executable during reflective loading. 
The default is RWX. so we need to set to it to false in our profile. 

```javascript
################################################
## Memory Indicators
################################################
stage {
    set userwx         "false";
    }
```

then we need to set the sleep_mask to true in our profile.

```javascript
################################################
## Memory Indicators
################################################
stage {
    set userwx         "false";
    set sleep_mask     "true";
    }
```

NOTE: you may need to edit the sleep mask src file.

In my case i just wrote this function in the sleep_mask.c in the original artifact kit


```c
void my_mask_section(SLEEPMASKP *parms, DWORD start, DWORD end) {
    char key[] = "a1b2c3d4e5f6g7h8";
    size_t key_length = sizeof(key) - 1;  
    for (DWORD i = start; i < end; i++) {
        parms->beacon_ptr[i] ^= key[i % key_length];  
    }
}
```

Then we should change the old function name.

![image](https://github.com/user-attachments/assets/4d619ee6-95d1-4bf9-8ad6-5c522a700ef4)

If you used the defult function, your beacon will be flagged by Windows_Trojan_CobaltStrike_b54b94ac

```javascript
rule Windows_Trojan_CobaltStrike_b54b94ac {
    meta:
        author = "Elastic Security"
        id = "b54b94ac-6ef8-4ee9-a8a6-f7324c1974ca"
        fingerprint = "2344dd7820656f18cfb774a89d89f5ab65d46cc7761c1f16b7e768df66aa41c8"
        creation_date = "2021-10-21"
        last_modified = "2022-01-13"
        description = "Rule for beacon sleep obfuscation routine"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a_x64 = { 4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03 }
        $a_x64_smbtcp = { 4C 8B 07 B8 4F EC C4 4E 41 F7 E1 41 8B C1 C1 EA 02 41 FF C1 6B D2 0D 2B C2 8A 4C 38 10 42 30 0C 06 48 }
        $a_x86 = { 8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2 }
        $a_x86_2 = { 8B 06 8D 3C 08 33 D2 6A 0D 8B C1 5B F7 F3 8A 44 32 08 30 07 41 3B 4D 08 72 E6 8B 45 FC EB C7 }
        $a_x86_smbtcp = { 8B 07 8D 34 08 33 D2 6A 0D 8B C1 5B F7 F3 8A 44 3A 08 30 06 41 3B 4D 08 72 E6 8B 45 FC EB }
    condition:
        any of them
}
```

![image](https://github.com/user-attachments/assets/9b068987-67a1-4351-a627-a5472f94f1b7)

### Transform Blocks Explanation
In the profile, we have utilized the transform blocks to obfuscate specific strings and replace known patterns that are commonly detected by YARA rules. This ensures that our payloads are less likely to be identified by signature-based detection systems.

Now after understanding the Transform we need to add this to our profile file

```javascript
################################################
## Memory Indicators
################################################
stage {
    transform-x86 {
        strrep "%s as %s\\%s: %d" "%s - %s\\%s: %d";
        strrep "%02d/%02d/%02d %02d:%02d:%02d" "%02d-%02d-%02d %02d:%02d:%02d";

    }
    transform-x64 {
        strrep "%s as %s\\%s: %d" "%s - %s\\%s: %d";
        strrep "%02d/%02d/%02d %02d:%02d:%02d" "%02d-%02d-%02d %02d:%02d:%02d";
    }
}
```
The streep is change the values in the memory. 

Old value : `%s as %s\\%s: %d` > New Value: `%s - %s\\%s: %d` 

Old value : `%02d/%02d/%02d %02d:%02d:%02d` > New Value: `%02d-%02d-%02d %02d:%02d:%02d` 


### The Results

After that our beacon will be clean and will not detected by this rule again.

![image](https://github.com/user-attachments/assets/f6128e04-b1ab-43cb-8448-0023689dccf1)







