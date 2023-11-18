---
title: Authorization
date: 2021-12-01 19:43:00 +0300
categories: [Writeup, AtHackCTF]
tags: [AtHackCTF]     # TAG names should always be lowercase
---






 



### Description:

Reverse

### Difficulty:

`easy`

### Flag:

Flag: `AtHackCTF{s3cur1ty_95295a20f4a48485}`


### Solve

● At first, when analyzing the behavior of the binary we can see that it’s actually running

![image](https://user-images.githubusercontent.com/54814433/144457864-99aeffa4-97d5-4495-84c4-66ea0a9d86d6.png)


● Decompiling the executable main function with IDA


![image](https://user-images.githubusercontent.com/54814433/144457951-5e616064-276a-42b5-96d9-4ec5ef65faf4.png)


● At first, it will check the username length to be “8” and the password to be "95295a20f4a48485".
● Running with the new information in mind shows different results as expected.
● After the password is checked, it will encrypt the username and compare it to the password.

![image](https://user-images.githubusercontent.com/54814433/144467421-7bf15915-092b-4274-b33d-ed9dc3f18231.png)


● The encryption routine will just xor-encrypt the username using a key of a sequence rand() function after a fixed seed of 0x1337:

![image](https://user-images.githubusercontent.com/54814433/144466979-4880431d-e59c-4262-9441-0092b7066cb5.png)


● Since the seed is fixed, the generated sequence of random numbers with rand() will be the same, in other words, we have the key and the password.

● Notice that you won’t get the same sequence on different OS/Platforms, but on the same operating system and platform, srand with a specific seed followed by
rand will provide the same answer.

● So, the right sequence will only be generated on a windows machine. This code will give you the right username:

```
#include <stdlib.h>
#include <stdio.h>
int main()
{
srand(0x1337);
char password[] = {
0x95, 0x29, 0x5a, 0x20, 0xf4, 0xa4, 0x84, 0x85
};
for (int index = 0;
index < sizeof(password);
index++) printf("%c", password[index] ^ rand());
puts("");
};
```

To run this code you need to put it on a file and run it with a Linux (gcc reverse.c --output reverse)
And by running ./output in your terminal you’ll get the username which is "s3cur1ty"


and i got the flag :D

 AtHackCTF{s3cur1ty_95295a20f4a48485}

