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


![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/5c598357-90e8-424e-8f4c-4a1915b23845)



![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/0e0eca81-33a4-4f4c-a414-bdda30bf3c99)



Reference: [Windows Forensics - HackTricks](https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/windows-forensics)


### Secret Notification

[Link to Pastebin](https://pastes.io/yucntygf4l)

Hey Pinky,

Let's do the same thing we do every night,... try to take over the world! Since your birthday is 14/11/1995, isn't it, Pinky!!

So, we will execute the plan in November this year at the festival using the three keys.

By the way, I noticed that you have connected to my PC and encrypted one of the keys there. Did you save it on your machine?

Narf, Yours in world domination...

`Note: The entire notification serves as a hint, indicating a connection to the RDP And for the encrypted file. `


# RDP

In our investigation, we discovered that Pinky is connected to the Windows box. To analyze this remote connection, we need to examine Remote Desktop Protocol (RDP) and other tools such as AnyDesk.

## Flag1 Investigation

Our discovery is based on the presence of this connection in both the browser history and TeamViewer logs. Additionally, it is recommended to analyze the RDP "bitmap cache" located in the following path :

`C:\Users<USER>\AppData\Local\Microsoft\Terminal Server Client\Cache\`

![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/815e8fdc-86ec-45fd-8bbf-aa8557fb44d5)



### Analyze RDP

To extract images from the RDP Bitmap Cache, we can utilize the `bmc-tool.py`. This tool proves useful in extracting valuable information.


![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/64a1c3a9-3ddd-49c2-aeb0-a05550c00c69)



Reference: [Blind Forensics with the RDP Bitmap Cache](https://medium.com/@ronald.craft/blind-forensics-with-the-rdp-bitmap-cache-16e0c202f91c)


#### Collect the Pieces

We utilized RDPieces to rebuild the images.


Unfortunately, the libraries used were subpar.


![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/5162cc00-ea52-40f0-933f-20ea2ec7e4a5)


![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/fef1a89a-7c96-42a7-9448-6b5fbe0313f0)


![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/21400b19-d7f5-4cc8-a0a3-23a74bfe735f)



No looking back, let's do it manually.


![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/70645c97-5058-4b7b-9592-7fdc3e41d061)



1st Flag: `Haboob{y0u_r_m4a5ter_in_b1tm4p5}`


# Suspected Container

## Flag2 Investigation

During our investigation, we discovered a container file that appears suspicious and is encrypted as autopsy module show us. The file is located in the path `/img_PinkyPC.e01/Users/Desktop`.

![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/dc9f0a6b-a2ea-4f64-880c-131384624fc1)



![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/bc873460-b551-445d-98cc-cb5b6f17fd18)


It contains the following directory structure:

- [current folder]
- [parent folder]
- `Container`
- desktop.ini
- firstOneFromBrain.txt

* By looking into appsearch.exe globalitems we can found there was search for 'veracrypt' that help us to know the type of encryption was used.


### Bruteforce

We generated a custom wordlist using the `Cupp tool`, incorporating information obtained from the first message. Subsequently, we utilized ``hashcat`` to crack the generated wordlist.

![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/a338f558-4b58-4580-a20e-e32fa92f7c19)


- Cupp tool information was obtained from [HackGPT](https://hackgpt.com).

![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/afc6b819-2441-4057-a6f9-30a73776249c)


![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/06144268-0260-470a-a526-1a4b5ed21b05)



**Command for hashcat: hashcat -w 4 -m 13721 Container pinky.txt**

Password Cracked: `yknip_954`

#### Mount the image


* Mount the image using VeraCrypt

![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/30f2792b-23ed-46dd-a87f-17dc24fbdcdb)




# Zip File Exploration

## Discovery

After mounting the disk, an encrypted zip file was found.

![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/ec3b5091-6dbd-439e-ad16-2842864f3248)



## SAM Dump Attempt 

Attempts to dump the Security Account Manager (SAM) for the password, tried to used cracked passowrd to unzip the zip folder but no lock.

![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/aba4bdb2-f13e-4ce7-9252-f9faa3b78f5b)


![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/5a5adf01-1c33-4474-b945-ce41dce05d77)



### Red Teaming Mindset

Despite unsuccessful attempts to unzip the file, a red teaming mindset was employed.

#### Chrome Credentials Investigation

Two login attempts in Chrome were identified, leading to the use of Mimikatz 


![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/07ecaa31-02ff-41cc-be2f-7035b2e8f963)



    - Reference: [Reading DPAPI Encrypted Secrets with Mimikatz and C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++)
    
##### Master Key Retrieval

To proceed, the master key was needed. The Security Identifier (SID) was downloaded from `appdata\Roaming\Microsoft\Protect` using the cracked user password.



![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/607464f2-e016-43c1-8d3b-018b243b62e0)

![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/791e98c5-f8ef-48c6-9537-d2629c424cdd)


##### Dump Attempt

Attempts to dump passwords of two users using the obtained master key were unsuccessful.

![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/c70bc896-f700-4881-b10c-2be1ccb30d81)


##### SQLite Exploration

Considering alternative approaches (https://ctftime.org/writeup/33938), SQLite was explored based on research and a similar scenario.

![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/e56a9023-c367-4c06-b7c3-3d8260f963de)


![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/39bc4211-f293-465f-8771-44a573c17790)



##### SQLite and DPAPI

Exploration of SQLite revealed the calling of DPAPI, providing promising insights.
(https://nandynarwhals.org/sieberrsec-ctf-3.0-digginginthedump/)

![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/1ebd41b1-81e0-4fc4-861c-7f91ed4d5d0d)


![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/251a2051-962d-418f-ba15-e324c5eb1464)


![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/0c7466b2-9916-4cec-a2f6-fa80859f2595)


##### Blob Extraction

Advancing to the next level, the blob from Mimikatz was utilized.

![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/18defb16-6781-44a3-b721-62b2b0021dd5)



##### Python Script Modification

Extensive debugging led to the realization that the provided Python script needed modification. (decrypt_chrome_password.py)
    - Reference: [Decode Chrome 80 Cookies](https://stackoverflow.com/questions/60416350/chrome-80-how-to-decode-cookies/60423699#60423699)
    
##### Password Decoding
After fixing the Python script, the password was successfully decoded:


![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/34283300-fc8e-4b57-a9a8-7412e468035b)


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


# JS


## Flag3 Investigation

Tool - Autopsy

During the investigation, a suspicious JavaScript file was found in recently accessed files. 

![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/62ddf509-666d-4fa8-95e5-a0215b1f7adc)

* Data Sources >> PinkyPC.e01_1Host
* File Path: /img_PinkyPC.e01/Users/Pinky/AppData/Local/Google/Chrome/User Data/Default/Extensions/x9mhkkegcca9sldgd9medpiccmgmlc

![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/4a40a431-d14c-4b3a-987f-6248615ff8de)


Directory Structure:
------
* [current folder]
* [parent folder]
* images
* background.js
* manifest.json
* popup.html

![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/c1adba16-64cb-461a-98e2-8f070cd6351d)


The code was obfuscated, so it was deobfuscated to reveal the following:


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


#### Undefined Variable

It was noticed that `d17` was not defined.

![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/337cd60a-b7a7-4fa6-92dc-3fd8ef89fa10)

So we defined 'd17' as 1 to test, after running the script, the output was `SGFib29ie2VYN2VuJGkwbl9yM3YzcjUzcn0`.

![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/04f90834-f0db-4597-9018-c2a5d7961361)


##### Base64 Decoding

The output was decoded using Base64, revealing `Haboob{eX7en..l..}`.

![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/e6f5c352-e37e-4ded-8193-edf7c69d651f)


#### Decimal Value Discovery

ASCII Table Conversion: Utilizing the ASCII table, it was confirmed that every number corresponds to a character value, aiding in finding the complete flag

![image](https://github.com/MazX0p/MazX0p2.github.io/assets/54814433/94544c9b-32a6-4963-8414-5a0b9ee6a2b4)

A Python script was written to find the decimal value of `d17`. The script provided the initial digits of the flag.
To obtain the full flag, it was necessary to define `d17` with the correct value.
A bruteforce approach on `d17` revealed that the correct value was 37.
With the correct value for `d17`, the output was base64-decoded again, resulting in `Haboob{eX7en$i0n_r3v3r53r}`.

and i got the flag :D

Final Flag:

Haboob{eX7en$i0n_r3v3r53r}



