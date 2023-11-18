---
title: PicklySituations
date: 2021-12-01 19:55:00 +0300
categories: [Writeup, AtHackCTF]
tags: [AtHackCTF]     # TAG names should always be lowercase
---






 



### Description:

Reverse 

### Difficulty:

`easy`

### Flag:

Flag: `AtHackCTF{w0wza_p1ckl3s_4r3_c3w1!}`


# Solve:

After taking a look at the code. I tried to decode it by base64 and base64 URL and i found something interesting

![image](https://user-images.githubusercontent.com/54814433/144289391-0e909f49-db30-4224-af06-87c0afaee823.png)

first time for me to see marshal module so I googled it and found some interesting information about marshal module that says that it contains functions that can read and write Python values in binary format. The format is specific to Python. and then I had the idea, we needed to decrypt the base64 and loads the marshal code by using pickle and then we disassembled it. I wrote python script to automate this task.



```
import base64
import pickletools
import pickle
import dis
import types
import marshal, base64


mar = base64.urlsafe_b64decode(b'gANjYnVpbHRpbnMKZXZhbApxAELRAgAAZXhlYyhfX2ltcG9ydF9fKCdtYXJzaGFsJykubG9hZHMoX19pbXBvcnRfXygnYmFzZTY0JykudXJsc2FmZV9iNjRkZWNvZGUoIjR3QUFBQUFBQUFBQUJBQUFBQ0lBQUFCREFBQUFjNm9BQUFCMEFHUUJnd0Y5QUdRQ1pBTmtCR1FGWkFaa0IyUUlaQWxrQ21RTFpBTmtER1FOWkF0a0JXUU9aQTFrRDJRR1pBZGtFR1FSWkJKa0UyUVVaQlZrRm1RWFpBMWtHR1FaWkE5a0dtUWJaeUo5QVdRY2ZRSjRTSFFCZEFKOEFJTUJnd0ZFQUYwNGZRTjBBM3dBZkFNWkFJTUJkQU44QW53RGRBSjhBb01CRmdBWkFJTUJRUUI4QVh3REdRQnJBM0ppZEFSa0hZTUJBUUJrSGxNQWNXSlhBSFFFWkItREFRRUFaQ0JUQUNraFR2b1JWMmhoZENCcGN5QjBhR1VnWm14aFp6X3BBQUFBQU9rMkFBQUE2Um9BQUFEcElBQUFBT2s3QUFBQTZUNEFBQURwRUFBQUFPa1ZBQUFBNlFRQUFBRHBLUUFBQU9sb0FBQUE2U0lBQUFEcEhRQUFBT2x3QUFBQTZUOEFBQURwY2dBQUFPa3hBQUFBNlEwQUFBRHBkUUFBQU9rcUFBQUE2V1lBQUFEcERBQUFBT2x4QUFBQTZTVUFBQURwZVFBQUFPa29BQUFBMmdkQlFsSkJXRlZUMmdsSmJtTnZjbkpsWTNSRzJnZERiM0p5WldOMFZDa0YyZ1ZwYm5CMWROb0ZjbUZ1WjJYYUEyeGxidG9EYjNKazJnVndjbWx1ZENrRTJnRjQyZ1JtYkdGbjJnTnJaWG5hQVdtcEFISW9BQUFBLWdwd2FXTnJiR1Y1TG5CNTJnTm1iMjhTQUFBQWN4SUFBQUFBQVFnQ1NBSUVBaElCS0FFSUFRZ0JDQUU9IikpKXEBhXECUnEDLg==')
pickletools.dis(mar, annotate=30)
```


![image](https://user-images.githubusercontent.com/54814433/144293775-0c7a95ac-2ff6-4627-ba91-26a298dab500.png)

and I got the output with another marshal code, I wrote another script to load the marshal code and disassemble it 

```
import base64
import pickletools
import pickle
import dis
import types
import marshal, base64

haha = '''4wAAAAAAAAAABAAAACIAAABDAAAAc6oAAAB0AGQBgwF9AGQCZANkBGQFZAZkB2QIZAlkCmQLZANkDGQNZAtkBWQOZA1kD2QGZAdkEGQRZBJkE2QUZBVkFmQXZA1kGGQZZA9kGmQbZyJ9AWQcfQJ4SHQBdAJ8AIMBgwFEAF04fQN0A3wAfAMZAIMBdAN8AnwDdAJ8AoMBFgAZAIMBQQB8AXwDGQBrA3JidARkHYMBAQBkHlMAcWJXAHQEZB-DAQEAZCBTACkhTvoRV2hhdCBpcyB0aGUgZmxhZz_pAAAAAOk2AAAA6RoAAADpIAAAAOk7AAAA6T4AAADpEAAAAOkVAAAA6QQAAADpKQAAAOloAAAA6SIAAADpHQAAAOlwAAAA6T8AAADpcgAAAOkxAAAA6Q0AAADpdQAAAOkqAAAA6WYAAADpDAAAAOlxAAAA6SUAAADpeQAAAOkoAAAA2gdBQlJBWFVT2glJbmNvcnJlY3RG2gdDb3JyZWN0VCkF2gVpbnB1dNoFcmFuZ2XaA2xlbtoDb3Jk2gVwcmludCkE2gF42gRmbGFn2gNrZXnaAWmpAHIoAAAA-gpwaWNrbGV5LnB52gNmb28SAAAAcxIAAAAAAQgCSAIEAhIBKAEIAQgBCAE='''
nope = base64.urlsafe_b64decode(haha)
gotIt = marshal.loads(nope)
dis.dis(gotIt)
```
and this script disassembles the code as follows

```
             10 LOAD_CONST               3 (54)
             12 LOAD_CONST               4 (26)
             14 LOAD_CONST               5 (32)
             16 LOAD_CONST               6 (59)
             18 LOAD_CONST               7 (62)
             20 LOAD_CONST               8 (16)
             22 LOAD_CONST               9 (21)
             24 LOAD_CONST              10 (4)
             26 LOAD_CONST              11 (41)
             28 LOAD_CONST               3 (54)
             30 LOAD_CONST              12 (104)
             32 LOAD_CONST              13 (34)
             34 LOAD_CONST              11 (41)
             36 LOAD_CONST               5 (32)
             38 LOAD_CONST              14 (29)
             40 LOAD_CONST              13 (34)
             42 LOAD_CONST              15 (112)
             44 LOAD_CONST               6 (59)
             46 LOAD_CONST               7 (62)
             48 LOAD_CONST              16 (63)
             50 LOAD_CONST              17 (114)
             52 LOAD_CONST              18 (49)
             54 LOAD_CONST              19 (13)
             56 LOAD_CONST              20 (117)
             58 LOAD_CONST              21 (42)
             60 LOAD_CONST              22 (102)
             62 LOAD_CONST              23 (12)
             64 LOAD_CONST              13 (34)
             66 LOAD_CONST              24 (113)
             68 LOAD_CONST              25 (37)
             70 LOAD_CONST              15 (112)
             72 LOAD_CONST              26 (121)
             74 LOAD_CONST              27 (40)
             76 BUILD_LIST              34
             78 STORE_FAST               1 (flag)

             80 LOAD_CONST              28 ('ABRAXUS')
             82 STORE_FAST               2 (key)
```

there is an LOAD_CONST(key) so we need to xor the key with they LOAD_CONST(flag)

again i wrote another python script to do this task for me :)

```
arr = [0,54,26,32,59,62,16,21,4,41,54,104,34,41,32,29,34,112,59,62,63,114,49,13,117,42,102,12,34,113,37,112,121,40]
key = b"ABRAXUS"
flag = ""
for i in range(len(arr)):
       hahah += chr(key[i%len(key)] ^ arr[i])
print (hahah)
```

and we will got the flag :D

![image](https://user-images.githubusercontent.com/54814433/144295184-09587c45-d7a4-45f8-993c-43e45b2c7f39.png)








