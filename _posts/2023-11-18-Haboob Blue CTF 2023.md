---
title: Haboob Blue CTF 2023
date: 2023-11-18 12:13:00 +0300
categories: [Writeup, CTF]
tags: [writeup]     # TAG names should always be lowercase
---

# HABBOB BLUE CTF

## Difficulty:

`HARD`


## Windows 10 Notifications

I discovered this information within the browser history. The user accessed Telegram, so we need to examine the messages. To do this, navigate to the Windows Notification artifacts.

Upon investigation, we found the following information:

In the path `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`, you can locate the database `appdb.dat` (before Windows Anniversary) or `wpndatabase.db` (after Windows Anniversary).

Within this SQLite database, there is a Notification table containing all the notifications in XML format. These notifications may contain interesting data.


![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/962c0b58-96a3-4af5-9311-efa8d6b33688)


![image](https://github.com/MazX0p/MazX0p.github.io/assets/54814433/5b1d13fb-36d6-4a63-800b-91489f36cf8a)


Reference: [Windows Forensics - HackTricks](https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/windows-forensics)


### Secret Notification

[Link to Pastebin](https://pastes.io/yucntygf4l)

Hey Pinky,

Let's do the same thing we do every night,... try to take over the world! Since your birthday is 14/11/1995, isn't it, Pinky!!

So, we will execute the plan in November this year at the festival using the three keys.

By the way, I noticed that you have connected to my PC and encrypted one of the keys there. Did you save it on your machine?

Narf, Yours in world domination...

`Note: The entire notification serves as a hint, indicating a connection to the RDP.`


# RDP

In our investigation, we discovered that Pinky is connected to the Windows box. To analyze this remote connection, we need to examine Remote Desktop Protocol (RDP) and other tools such as AnyDesk.

## Investigation Details

Our discovery is based on the presence of this connection in both the browser history and TeamViewer logs. Additionally, it is recommended to analyze the RDP "bitmap cache" located in the following path :

`C:\Users<USER>\AppData\Local\Microsoft\Terminal Server Client\Cache\`

![image](https://github.com/MazX0p/MazX0p.github.io/assets/54814433/073e1a5b-477e-47f1-9ae7-ec22619d666e)


### Analyze RDP

To extract images from the RDP Bitmap Cache, we can utilize the `bmc-tool.py`. This tool proves useful in extracting valuable information.


![image](https://github.com/MazX0p/MazX0p.github.io/assets/54814433/1d5cb6da-6723-4ac6-bf24-06edbbcdd4e9)


Reference: [Blind Forensics with the RDP Bitmap Cache](https://medium.com/@ronald.craft/blind-forensics-with-the-rdp-bitmap-cache-16e0c202f91c)


#### Collect the Pieces

We utilized RDPieces to rebuild the images.


Unfortunately, the libraries used were subpar.


![image](https://github.com/MazX0p/MazX0p.github.io/assets/54814433/4aef78b4-0b0a-47c5-9d44-5e2563a5cfa8)


![image](https://github.com/MazX0p/MazX0p.github.io/assets/54814433/86cd9190-b154-4ce6-96ca-31c3b4fdf065)

![image](https://github.com/MazX0p/MazX0p.github.io/assets/54814433/7a8ee40c-ba3e-4d4d-bd0c-f0dadd775bb1)


No looking back, let's do it manually.


![image](https://github.com/MazX0p/MazX0p.github.io/assets/54814433/31c4280e-d043-46c9-86f9-30edd3a765ae)


1st Flag: `Haboob{y0u_r_m4a5ter_in_b1tm4p5}`


# Suspected Container

## Investigation

During our investigation, we discovered a container file that appears suspicious and is encrypted. The file is located in the path `/img_PinkyPC.e01/Users/Desktop`.

![image](https://github.com/MazX0p/MazX0p.github.io/assets/54814433/2eb8be59-ec86-4165-8588-2b19ce2b145d)


![image](https://github.com/MazX0p/MazX0p.github.io/assets/54814433/7efd7140-13ac-4af1-b3c7-dbe3d77c3894)


It contains the following directory structure:

- [current folder]
- [parent folder]
- `Container`
- desktop.ini
- firstOneFromBrain.txt

### Bruteforce

We generated a custom wordlist using the `Cupp tool`, incorporating information obtained from the first message. Subsequently, we utilized ``hashcat`` to crack the generated wordlist.

![image](https://github.com/MazX0p/MazX0p.github.io/assets/54814433/4bb9148f-cccc-41c6-a6cf-e1f3fa3ce4c9)


- Cupp tool information was obtained from [HackGPT](https://hackgpt.com).

![image](https://github.com/MazX0p/MazX0p.github.io/assets/54814433/5996eb60-7d05-4d10-bfd1-139831d9d6d9)

![image](https://github.com/MazX0p/MazX0p.github.io/assets/54814433/268e72c8-cc09-451d-a0cd-651eddba170f)


**Command for hashcat: hashcat -w 4 -m 13721 Container pinky.txt**

Password Cracked: `yknip_954`

#### Mount the image


* Mount the image using VeraCrypt

![image](https://github.com/MazX0p/MazX0p.github.io/assets/54814433/f71e45be-2a9e-488e-93db-003cfa60575d)


# Zip File Exploration

## Discovery

After mounting the disk, an encrypted zip file was found.

![image](https://github.com/MazX0p/MazX0p.github.io/assets/54814433/10971949-a8d8-4dee-bc46-f60fb5e831ae)


## SAM Dump Attempt 

Attempts to dump the Security Account Manager (SAM) for the password.

![image](https://github.com/MazX0p/MazX0p.github.io/assets/54814433/54a2d657-0df1-48bd-a0de-94c910bf2bff)

![image](https://github.com/MazX0p/MazX0p.github.io/assets/54814433/e0ed98d2-777e-4a70-934a-9d153834a3c4)


### Red Teaming Mindset

Despite unsuccessful attempts to unzip the file, a red teaming mindset was employed.

#### Chrome Credentials Investigation

Two login attempts in Chrome were identified, leading to the use of Mimikatz 


![image](https://github.com/MazX0p/MazX0p.github.io/assets/54814433/ed336708-a463-4911-bbe2-7e9bc72864db)


    - Reference: [Reading DPAPI Encrypted Secrets with Mimikatz and C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++)
    
##### Master Key Retrieval

To proceed, the master key was needed. The Security Identifier (SID) was downloaded from `appdata\Roaming\Microsoft\Protect` using the cracked user password.

![image](https://github.com/MazX0p/MazX0p.github.io/assets/54814433/81f65817-c3e4-44f6-b3d2-40dbe8cde4fc)

![image](https://github.com/MazX0p/MazX0p.github.io/assets/54814433/ceefbdbf-7ed6-4446-be8a-851edac930ad)



##### Dump Attempt

Attempts to dump passwords of two users using the obtained master key were unsuccessful.

![image](https://github.com/MazX0p/MazX0p.github.io/assets/54814433/1cda6e99-e2ae-4f43-95c4-889bb2ce5ce0)

##### SQLite Exploration

Considering alternative approaches (https://ctftime.org/writeup/33938), SQLite was explored based on research and a similar scenario.

![image](https://github.com/MazX0p/MazX0p.github.io/assets/54814433/adfb066d-bfef-417f-b808-67030f7f194e)

![image](https://github.com/MazX0p/MazX0p.github.io/assets/54814433/385fea8f-6511-4976-a89e-ad27941be662)


##### SQLite and DPAPI

Exploration of SQLite revealed the calling of DPAPI, providing promising insights.
(https://nandynarwhals.org/sieberrsec-ctf-3.0-digginginthedump/)

![image](https://github.com/MazX0p/MazX0p.github.io/assets/54814433/6066b63d-50b7-465f-95f7-01599b1c3d5e)

![image](https://github.com/MazX0p/MazX0p.github.io/assets/54814433/5f666b4c-e819-4e4e-96bf-3f81089001c6)

![image](https://github.com/MazX0p/MazX0p.github.io/assets/54814433/7d889db5-2b19-4fc2-b8a7-43c61dd300ad)

##### Blob Extraction

Advancing to the next level, the blob from Mimikatz was utilized.

![image](https://github.com/MazX0p/MazX0p.github.io/assets/54814433/578fc4c7-a878-4e9a-ba3f-04669d28151f)


##### Python Script Modification

Extensive debugging led to the realization that the provided Python script needed modification. (decrypt_chrome_password.py)
    - Reference: [Decode Chrome 80 Cookies](https://stackoverflow.com/questions/60416350/chrome-80-how-to-decode-cookies/60423699#60423699)
    
##### Password Decoding
After fixing the Python script, the password was successfully decoded:

![image](https://github.com/MazX0p/MazX0p.github.io/assets/54814433/827380c1-47fc-4369-bf42-923cb84f8293)


    `
    Pinky1020@1234+=+=+=++
    `

##### Important Commands:

###### Command 1:

```bash
cat 'AppData/Local/Google/Chrome/User Data/Local State' | jq -r .os_crypt.encrypted_key | base64 -d | xxd```

This command decodes the encrypted key from the 'Local State' file in the Chrome directory using jq, base64, and xxd.

```

```bash
cat DPAP_extractor.py


import json, base64

x = json.load(open('AppData/Local/Google/Chrome/User Data/Local State', 'rb'))['os_script']['encrypted_key']
x = base64.b64decode(x)
open("blob", 'wb').write(x[5:])

```



###### flag

Haboob{Bru73_F0rc3d_7h3_c0N741n3R}


# js


## Investigation

Tool - Autopsy

During the investigation, a suspicious JavaScript file was found in recently accessed files. 

* Data Sources >> PinkyPC.e01_1Host
* File Path: /img_PinkyPC.e01/Users/Pinky/AppData/Local/Google/Chrome/User Data/Default/Extensions/x9mhkkegcca9sldgd9medpiccmgmlc

Directory Structure:
------
* [current folder]
* [parent folder]
* images
* background.js
* manifest.json
* popup.html


> The code was obfuscated, so it was deobfuscated to reveal the following:


```javascript
chrome.runtime.onInstalled.addListener(function () {
    console.log('Clipboard Manager');
});

function base64Encode(C) {
    return btoa(C);
}

function base64Decode(C) {
    return atob(C);
}

chrome.runtime.onMessage.addListener(function (C, k, K) {
    if (C.action === 'copy') {
        const s = base64Encode(C.text);
        if (s === base64Encode('bG9s')) {
            // List of decimal values assigned to variables d1, d2, ..., d35
            const d1 = 41.5, d2 = 35.5, d3 = 35 * 2, d4 = 52.5, d5 = 49, d6 = 25, d7 = 28.5, d8 = 52.5, d9 = 50.5,
                d10 = 25, d11 = 43, d12 = 44.5, d13 = 39, d14 = 25, d15 = 43, d16 = 58.5, d17 = 37, d18 = 35.5,
                d19 = 53.5, d20 = 59.5, d21 = 49, d22 = 54, d23 = 28.5, d24 = 60.5, d25 = 38.5, d26 = 25.5,
                d27 = 44.5, d28 = 61, d29 = 49.5, d30 = 53, d31 = 42.5, d32 = 61, d33 = 49.5, d34 = 55, d35 = 24;

            const V = [d1 * 2, d2 * 2, d3 * 2, d4 * 2],
                r = [d5 * 2, d6 * 2, d7 * 2],
                n = [d8 * 2, d9 * 2, d10 * 2],
                M = [d11 * 2, d12 * 2, d13 * 2],
                P = [d14 * 2, d15 * 2, d16 * 2, d17 * 2],
                U = [d18 * 2, d19 * 2, d20 * 2],
                A = [d21 * 2, d22 * 2, d23 * 2],
                a = [d24 * 2, d25 * 2, d26 * 2],
                z = [d27 * 2, d28 * 2, d29 * 2],
                v = [d30 * 2, d31 * 2, d32 * 2],
                q = [d33 * 2, d34 * 2, d35 * 2];

            let J = '';
            for (let i = 0; i < V.length; i++) {
                J += String.fromCharCode(V[i]);
            }

            const Y = document.createElement('textarea');
            Y.value = base64Decode(J);

            document.body.appendChild(Y);
            Y.select();
            document.execCommand('copy');
            document.body.removeChild(Y);
        }
    }
});
```

so i wrote python script to solve it :

```
import re
from decimal import Decimal
d31 = 42.5
d15 = 43
d13 = 39
d6 = 25
d35 = 24
d24 = 60.5
d18 = 35.5
d8 = 52.5
d2 = 35.5
d25 = 38.5
d1 = 41.5
d16 = 58.5
d9 = 50.5
d21 = 49
d5 = 49
d11 = 43
d32 = 61
d10 = 25
d12 = 44.5
d20 = 59.5
d28 = 61
d4 = 52.5
d14 = 25
d7 = 28.5
d3 = 35
d27 = 44.5
d19 = 53.5
d33 = 49.5
d26 = 25.5
d34 = 55
d23 = 28.5
d29 = 49.5
d22 = 54
d30 = 53
d17 = 37

list = [d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13, d14, d15, d16,d17, d18, d19, d20, d21, d22, d23, d24,
d25, d26, d27, d28, d29, d30, d31, d32, d33, d34, d35]

for i in list:
x = i * 2
z = int(float(x))
y = int(Decimal(z))
h = chr(y)
print (h,end="")
```
### Flag Decoding Process

After running the script, the output was `SGFib29ie2VYN2VuJGkwbl9yM3YzcjUzcn0`.

1. Base64 Decoding: The output was decoded using Base64, revealing `Haboob{eX7en..l..}`.

2. Undefined Variable: It was noticed that `d17` was not defined.

3. Decimal Value Discovery: A Python script was written to find the decimal value of `d17`. The script provided the initial digits of the flag.

4. Defining `d17`: To obtain the full flag, it was necessary to define `d17` with the correct value.

5. Bruteforce Approach: A bruteforce approach on `d17` revealed that the correct value was 37.

6. Base64 Decoding (Again): With the correct value for `d17`, the output was base64-decoded again, resulting in `Haboob{eX7en$i0n_r3v3r53r}`.

7. ASCII Table Conversion: Utilizing the ASCII table, it was confirmed that every number corresponds to a character value, aiding in finding the complete flag.

Special thanks to Baha Uni for providing valuable courses on converters, facilitating the decoding process.

Final Flag:

Haboob{eX7en$i0n_r3v3r53r}
and i got the flag :D


