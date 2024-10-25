---
layout: post
title: "HookChain: A Deep Dive into Advanced EDR Bypass Techniques"
date: 2024-10-25
categories: [Maldev, Evasion]
tags: [Evasion]
---

**HookChain** is a novel technique aimed at bypassing Endpoint Detection and Response (EDR) solutions by leveraging low-level Windows APIs and manipulating how system calls interact with user-mode hooks. To better understand how HookChain operates, let’s dive deeper into the technical aspects with real-world examples.

## The Mechanics of Function Hooking and EDR Monitoring

Modern EDR solutions often monitor Windows API calls at the `NTDLL.DLL` level, as this DLL acts as the bridge between user-mode applications and the kernel. For instance, when an application needs to allocate memory, it calls the `NtAllocateVirtualMemory` function, which EDR solutions can hook to monitor or block malicious activity.

### Example: Traditional EDR Hooking

Here’s what happens in a typical EDR-monitored environment:

1. A malware sample attempts to allocate memory by calling `NtAllocateVirtualMemory`.
2. The EDR has hooked `NtAllocateVirtualMemory` in `NTDLL.DLL`. This hook intercepts the function call and forwards it to the EDR for inspection.
3. If the EDR detects suspicious behavior, it may block the function call or allow it with restrictions.
4. The function then proceeds to the kernel and returns the result.

![image](https://github.com/user-attachments/assets/dbbf4cd1-2764-40da-84a5-4e00408de8b7)


This flow is disrupted by **HookChain**, which manipulates the call process.

## HookChain in Action: Bypassing the Hook

In HookChain, the attacker does not call `NtAllocateVirtualMemory` directly as monitored by the EDR. Instead, they bypass the hooked API using **indirect system calls** and **dynamic SSN mapping** to evade detection.


### Step 1: SSN (System Service Number) Mapping

Every system call in Windows has an associated System Service Number (SSN), which is used to identify the syscall in the System Service Dispatch Table (SSDT). HookChain maps these SSNs dynamically.

For example:

- `NtAllocateVirtualMemory` has a corresponding SSN (let's assume it’s `0x18` in this scenario).
- Instead of calling the API directly, HookChain maps this SSN and looks up the actual kernel function address.

![image](https://github.com/user-attachments/assets/be5461b5-2529-4682-9fa3-ca73354ed923)


### Step 2: Using Indirect Syscalls

In this stage, HookChain skips over the hooked `NTDLL` functions by using **Halo’s Gate** or other techniques that identify unhooked neighboring functions in `NTDLL`.

#### Example: Halo’s Gate

Let’s assume the attacker wants to bypass `NtAllocateVirtualMemory` (which has been hooked by the EDR). HookChain does the following:

1. **Byte-Scanning for Hooks**: It reads the first 32 bytes of `NtAllocateVirtualMemory` to detect if it has been hooked. If the original instruction sequence (`mov r10, rcx; mov eax, SSN`) is altered, the function is considered hooked.
   
2. **Neighboring Function Search**: HookChain searches for an adjacent unhooked function in `NTDLL`, such as `NtQueryInformationProcess`. Once found, it calculates the relative distance from `NtAllocateVirtualMemory` to this unhooked function and uses this neighboring function’s address to indirectly perform the syscall.

3. **Syscall Execution**: The attacker can now execute the system call via the unhooked neighboring function, completely bypassing the EDR.

![image](https://github.com/user-attachments/assets/a885671c-891d-46d5-930a-1532ae124e3d)


### Step 3: Modifying the IAT (Import Address Table)

One of the core strategies in HookChain is modifying the **Import Address Table (IAT)** of key DLLs like `kernel32.dll`, `kernelbase.dll`, and others. The IAT stores pointers to imported functions, and by overwriting these pointers, HookChain ensures that API calls bypass the EDR’s hooks.


#### Example: IAT Hooking

1. **Identifying the Target DLL**: Suppose the attacker knows that the target application uses `kernel32.dll` to make system calls such as `ReadFile` or `WriteFile`, which ultimately call `NTDLL` functions (e.g., `NtReadFile` and `NtWriteFile`).
   
2. **Hooking the IAT**: HookChain modifies the IAT entry for `ReadFile` in `kernel32.dll` so that it points to HookChain’s custom handler instead of the original function. This handler then executes an indirect syscall (bypassing the EDR) to the original `NTDLL` function.

3. **Executing the Attack**: The application continues making calls to `ReadFile`, unaware that its IAT entry has been hooked. The hooked IAT entry redirects the function to HookChain’s handler, which ensures that the syscall is executed without being intercepted by the EDR.

![image](https://github.com/user-attachments/assets/d962cda9-8922-4fc4-9989-773105694b3b)



## Technical Walkthrough of HookChain’s Execution Flow

![image](https://github.com/user-attachments/assets/5e5d427c-5054-4661-96f6-c8b9fa8a267e)


Let’s walk through a specific attack scenario:

1. **HookChain Implantation**:
   - The attacker first loads the necessary DLLs into the process space (e.g., `kernel32.dll` and `ntdll.dll`).
   - HookChain checks for function hooks by reading function bytes within `NTDLL` to detect any EDR hooks.
   - It uses dynamic mapping to map SSNs of critical system calls like `NtAllocateVirtualMemory`.

2. **Building the SYSCALL_LIST**:
   HookChain builds an array, **SYSCALL_LIST**, where each entry contains:
   
   - The SSN (system service number) for each critical function.
   - The virtual address of the corresponding function in `NTDLL`.
   - The address of the SYSCALL instruction for indirect syscalls.

3. **Redirection Through the IAT**:
   Once the function pointers in the IAT are hooked, HookChain ensures that all future calls to critical APIs, like `ReadFile` or `VirtualAlloc`, are redirected to its own handler. This handler ensures that syscalls are executed indirectly, without passing through the original, hooked `NTDLL` functions.

4. **Transparent Execution Flow**:
   After the HookChain implant is in place, the EDR sees a normal execution flow. For example:

   - A function call might appear as if it went from `kernel32.dll` to `ntdll.dll` as usual.
   - However, in reality, HookChain intercepted the call, bypassed the `NTDLL` hook, and executed the syscall via a neighboring unhooked function.

By Following these steps we gain shellcode injection successfully  

![image](https://github.com/user-attachments/assets/797220b9-f0d3-47b6-95ad-e2b36f762b89)

## Real-World Testing

**Here's the results of our shellcode injector using HookChain Technique** 

![image](https://github.com/user-attachments/assets/f6f1ed2d-84de-4870-870b-307d575865d6)

![image](https://github.com/user-attachments/assets/2e11c558-0e75-48db-8a1a-bb20f3b20a42)

![image](https://github.com/user-attachments/assets/9718f5d6-7c99-42b3-8680-52f493e442f6)




---
## Real-World Case Study: Lazarus Group and HookChain Techniques

Advanced Persistent Threat (APT) groups, like **Lazarus Group**, have been known to use techniques that bear similarities to HookChain. In a 2021 attack, Lazarus used a variant of their malware toolkit that bypassed kernel and user-mode EDR monitoring by employing direct syscalls. 

HookChain takes this one step further by leveraging **dynamic syscall mapping** and **neighboring function calls** to evade detection.  
**In environments where EDR products like CrowdStrike or SentinelOne were deployed**  
HookChain’s ability to sidestep NTDLL hooks has proven effective in evading detection, allowing attackers to carry out their operations undisturbed.

---

## Advanced Bypassing Mechanisms: Comparing HookChain to SysWhispers

**SysWhispers** is another technique designed to bypass hooked Windows APIs by directly invoking syscalls. However, HookChain distinguishes itself through **dynamic SSN mapping** and **neighboring function redirection**, which makes it more adaptable in scenarios where multiple functions are hooked or when syscall numbers change between Windows versions.

While SysWhispers relies on predefined syscall numbers and static syscall stubs, HookChain dynamically adjusts its approach in real time. This makes HookChain more resilient in scenarios where EDR solutions monitor multiple APIs or hook kernel-mode functions.

---

## The Future of EDR and HookChain

As **HookChain** becomes more widely adopted by threat actors, EDR solutions will need to evolve. One promising area of development is **hypervisor-based monitoring**, which can intercept and analyze syscalls before they reach the OS kernel. **Artificial Intelligence (AI)** and **machine learning** models will also become critical, as they can learn to detect suspicious syscall behavior based on subtle anomalies that static detection methods miss.

Moreover, **behavioral-driven syscall analysis** could become a key defense, enabling EDRs to not just track syscalls but understand their context and flow. This would make it much harder for techniques like HookChain to evade detection without raising red flags.

---

## Challenges for EDR Solutions

EDR systems typically rely on hooks placed in user-mode APIs like NTDLL to monitor and block malicious activities. However, many EDRs do not monitor NTDLL comprehensively enough, leaving certain hooks vulnerable to bypass techniques like HookChain. **94% of analyzed EDR solutions did not present hooks in the subsystem layer above NTDLL**.  

This leaves a significant gap that attackers can exploit.

![image](https://github.com/user-attachments/assets/9d14495c-93c4-44f4-a8cb-d8637e4b216f)
from Helvio Carvalho Junior paper

## Conclusion: The Arms Race Continues

HookChain exemplifies the next evolution in **EDR evasion**, demonstrating how attackers continue to innovate new techniques to bypass even the most sophisticated defenses. As organizations become more reliant on advanced security solutions, the need to stay ahead of these emerging techniques has never been greater. Defenders must combine **kernel-level monitoring**, **behavioral analysis**, and continuous threat intelligence to stay ahead in this ever-changing battlefield.

In the end, cybersecurity is a game of cat-and-mouse, and as defenders adapt to techniques like HookChain, attackers will no doubt devise even more creative methods to achieve their goals.

## References

[Helvio Carvalho Junior. 2024. HookChain](https://arxiv.org/abs/2404.16856): I've expanded upon this foundational work by adding further implementations and advancements to enhance the approach outlined in the research.

> **Note**: This work builds on the foundational concepts outlined in the research by [Helvio Carvalho Junior. 2024. HookChain](https://arxiv.org/abs/2404.16856) while introducing several advancements and additional implementations to enhance the original approach. These improvements include:
> 
> - **Enhanced Hook Evasion Techniques**: Expanding beyond Import Address Table (IAT) manipulation and indirect syscalls, we explore further evasion tactics that address kernel-mode inspection, a potential blind spot for some EDR solutions.
> - **Dynamic Resolution of Hooked Functions with Alternative Methods**: While leveraging Halo’s Gate, we also introduce additional SSN (System Service Number) resolution methods, like custom hashing and Heaven’s Gate, to further reduce detection.
> - **Advanced DLL Loading Mechanisms**: Introducing staggered or randomized loading techniques to avoid behavior-based detection, enhancing the evasion capabilities by timing and variation.
> - **API-Level Obfuscation Enhancements**: Expanding upon indirect syscalls, this work includes multi-layered obfuscation, such as parameter encryption, providing additional resilience against function call monitoring.
> - **Real-Time Hook Verification and Restoration**: A mechanism is included to periodically verify and restore unhooked addresses in real time, making the solution adaptable to runtime EDR monitoring.
> - **Extended Injection Techniques**: Beyond IAT hooking, this work explores methods like process hollowing, DLL hollowing, and Reflective DLL Injection, extending the original research to encompass a broader range of evasion techniques.

> These extensions demonstrate a commitment to pushing past the limitations of the initial approach, making the technique even more robust and resilient against evolving endpoint detection strategies.


