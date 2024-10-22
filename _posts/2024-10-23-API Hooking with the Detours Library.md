---
title: API Hooking with the Detours Library
date: 2024-10-23 01:48:00 +0300
categories: [Maldev, Evasion]
tags: [Evasion]     # TAG names should always be lowercase
---

## Introduction

API hooking is an essential technique in modern malware development, allowing attackers to intercept and manipulate system calls for malicious purposes. One of the most popular libraries for API hooking in Windows is Microsoft's **Detours Library**. Detours enables developers (or attackers) to alter the behavior of system functions by injecting custom code, which is particularly valuable for malware such as keyloggers, process injection techniques, or API monitoring.

In this detailed guide, we’ll explore how to leverage Detours for malicious purposes, such as tampering with system calls and evading security software. We’ll also provide a full working example, along with several key strategies used in real-world malware.

## Understanding Detours Hooking

Detours works by modifying the beginning of a target function (often known as the *prologue*) and inserting an unconditional jump (*trampoline*) to the custom handler function. This means that whenever the original function is called, the custom code will execute instead. This approach is often used in malware to hide activities from anti-virus software, modify parameters of system calls, or monitor sensitive API calls like `NtOpenProcess`.

### How Detours Achieves Hooking

The following is the general procedure Detours uses for function hooking:
- **Patch the entry point** of the target function to redirect the flow.
- **Save original instructions** so they can be executed later (or bypassed).
- **Inject custom behavior** by redirecting execution to the attacker’s function.

Let’s dive into the practical aspects of setting up Detours for API hooking.

## Setting up the Detours Library

1. **Download and compile** the Detours repository from Microsoft's official [GitHub repository](https://github.com/microsoft/detours). Ensure you have both 32-bit and 64-bit binaries for compatibility across different architectures.
2. **Include necessary headers** in your project, such as `detours.h` and link the appropriate `.lib` files depending on the target architecture.

Here’s an example of how you can handle both 32-bit and 64-bit builds in your project using preprocessor directives:

```cpp
#ifdef _M_X64
    #pragma comment(lib, "detours64.lib")
#else
    #pragma comment(lib, "detours32.lib")
#endif
```

### Key Functions in Detours

Detours offers several essential API functions to manage hooks:
- `DetourTransactionBegin()`: Starts a transaction to manage multiple hooks.
- `DetourUpdateThread()`: Updates the transaction to include the current thread.
- `DetourAttach()`: Attaches a hook to the specified function.
- `DetourDetach()`: Detaches the hook, restoring the original function.
- `DetourTransactionCommit()`: Commits the transaction, applying or undoing changes.

## Full Example: Hooking `MessageBoxA`

Below is a complete example demonstrating how to hook the `MessageBoxA` function, which can be leveraged by malware to alter system messages or deceive users:

```cpp
#include <windows.h>
#include <detours.h>
#include <stdio.h>

typedef int (WINAPI* MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
MessageBoxA_t OriginalMessageBoxA = MessageBoxA;

int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    // Modify the message displayed
    printf("Hooked! Original Text: %s
", lpText);
    lpText = "This is a malware-altered message!";
    
    // Call the original function
    return OriginalMessageBoxA(hWnd, lpText, lpCaption, uType);
}

BOOL InstallHook() {
    if (DetourTransactionBegin() != NO_ERROR) return FALSE;
    if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR) return FALSE;
    if (DetourAttach(&(PVOID&)OriginalMessageBoxA, HookedMessageBoxA) != NO_ERROR) return FALSE;
    return DetourTransactionCommit() == NO_ERROR;
}

BOOL UninstallHook() {
    if (DetourTransactionBegin() != NO_ERROR) return FALSE;
    if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR) return FALSE;
    if (DetourDetach(&(PVOID&)OriginalMessageBoxA, HookedMessageBoxA) != NO_ERROR) return FALSE;
    return DetourTransactionCommit() == NO_ERROR;
}

int main() {
    // Original MessageBoxA (before hooking)
    MessageBoxA(NULL, "Hello, world!", "Original", MB_OK);

    // Install the hook
    if (!InstallHook()) {
        printf("Failed to install hook!
");
        return -1;
    }

    // This will trigger the hooked MessageBoxA
    MessageBoxA(NULL, "This should be hooked!", "Hooked", MB_OK);

    // Uninstall the hook
    if (!UninstallHook()) {
        printf("Failed to uninstall hook!
");
        return -1;
    }

    // Back to original MessageBoxA (after unhooking)
    MessageBoxA(NULL, "Back to normal.", "Original", MB_OK);

    return 0;
}
```

### Explanation of Code
- We define a typedef for the original `MessageBoxA` function and store a pointer to it in `OriginalMessageBoxA`.
- The `HookedMessageBoxA` function changes the message that is displayed when `MessageBoxA` is called.
- The hook is installed using the `DetourAttach()` function, and once our custom function executes, it calls the original `MessageBoxA` to avoid breaking functionality.

## Avoiding Infinite Loops

A common pitfall in hooking is accidentally creating an infinite loop when the hooked function calls itself. In our example, we avoid this by calling the `OriginalMessageBoxA` instead of `MessageBoxA` within the hook function. However, an alternative method is to hook a function with similar behavior, such as `MessageBoxW`:

```cpp
int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    // Call a different API to avoid recursion
    return MessageBoxW(hWnd, L"Altered text", L"Altered caption", uType);
}
```
## Advanced Hooking Techniques

To enhance the malware's stealthiness, attackers often use these advanced techniques:
- **Dynamic API Resolution**: Instead of hardcoding function addresses, use `GetProcAddress` to dynamically resolve them at runtime. This makes the malware more portable.
- **Multiple Function Hooks**: Use Detours transactions to hook multiple API functions simultaneously. For instance, you can hook both `VirtualAlloc` and `VirtualFree` to monitor memory allocation by security tools.
- **Inline Patching**: Instead of using Detours’ trampoline approach, some malware may manually patch the entry point of the target function with their custom code for maximum control.

### 1. Dynamic API Resolution with Detours

Instead of hardcoding the address of a function like `MessageBoxA`, malware can dynamically resolve the function's address at runtime using `GetProcAddress`. This makes the malware adaptable across different Windows versions, service packs, and updates.

**Example with Detours:**

```cpp
#include <windows.h>
#include <detours.h>
#include <stdio.h>

typedef int (WINAPI* MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
MessageBoxA_t pMessageBoxA = NULL;

int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    printf("Dynamically Hooked! Original Text: %s\n", lpText);
    lpText = "This message was altered dynamically!";
    return pMessageBoxA(hWnd, lpText, lpCaption, uType);
}

BOOL InstallHook() {
    HMODULE hUser32 = LoadLibraryA("user32.dll");
    pMessageBoxA = (MessageBoxA_t)GetProcAddress(hUser32, "MessageBoxA");
    
    if (!pMessageBoxA) {
        printf("Failed to resolve MessageBoxA dynamically.\n");
        return FALSE;
    }

    if (DetourTransactionBegin() != NO_ERROR) return FALSE;
    if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR) return FALSE;
    if (DetourAttach(&(PVOID&)pMessageBoxA, HookedMessageBoxA) != NO_ERROR) return FALSE;
    return DetourTransactionCommit() == NO_ERROR;
}

BOOL UninstallHook() {
    if (DetourTransactionBegin() != NO_ERROR) return FALSE;
    if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR) return FALSE;
    if (DetourDetach(&(PVOID&)pMessageBoxA, HookedMessageBoxA) != NO_ERROR) return FALSE;
    return DetourTransactionCommit() == NO_ERROR;
}

int main() {
    InstallHook();
    MessageBoxA(NULL, "Hello, world!", "Original Message", MB_OK);
    UninstallHook();
    MessageBoxA(NULL, "Back to normal.", "Original Message", MB_OK);
    return 0;
}
```
* Why this is beneficial for malware development:

- Portability: The malware becomes more adaptable to various Windows versions.
- Evasion: By resolving API functions dynamically, the malware avoids signature-based detection methods that rely on hardcoded addresses.

### 2. Multiple Function Hooks with Detours

In a malware scenario, hooking multiple APIs at once can provide better control and monitoring of system behaviors. For example, hooking both VirtualAlloc and VirtualFree gives control over memory allocation and deallocation processes, useful for tracking or manipulating memory used by security software.

```cpp
#include <windows.h>
#include <detours.h>
#include <stdio.h>

typedef LPVOID (WINAPI* VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
VirtualAlloc_t OriginalVirtualAlloc = VirtualAlloc;

typedef BOOL (WINAPI* VirtualFree_t)(LPVOID, SIZE_T, DWORD);
VirtualFree_t OriginalVirtualFree = VirtualFree;

LPVOID WINAPI HookedVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    printf("Hooked VirtualAlloc: Allocating %llu bytes\n", dwSize);
    return OriginalVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}

BOOL WINAPI HookedVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
    printf("Hooked VirtualFree: Freeing memory\n");
    return OriginalVirtualFree(lpAddress, dwSize, dwFreeType);
}

BOOL InstallMemoryHooks() {
    if (DetourTransactionBegin() != NO_ERROR) return FALSE;
    if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR) return FALSE;
    if (DetourAttach(&(PVOID&)OriginalVirtualAlloc, HookedVirtualAlloc) != NO_ERROR) return FALSE;
    if (DetourAttach(&(PVOID&)OriginalVirtualFree, HookedVirtualFree) != NO_ERROR) return FALSE;
    return DetourTransactionCommit() == NO_ERROR;
}

BOOL UninstallMemoryHooks() {
    if (DetourTransactionBegin() != NO_ERROR) return FALSE;
    if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR) return FALSE;
    if (DetourDetach(&(PVOID&)OriginalVirtualAlloc, HookedVirtualAlloc) != NO_ERROR) return FALSE;
    if (DetourDetach(&(PVOID&)OriginalVirtualFree, HookedVirtualFree) != NO_ERROR) return FALSE;
    return DetourTransactionCommit() == NO_ERROR;
}

int main() {
    InstallMemoryHooks();
    VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_READWRITE);
    VirtualFree(NULL, 0, MEM_RELEASE);
    UninstallMemoryHooks();
    return 0;
}

```
* Why this is beneficial for malware development:

- Comprehensive Monitoring: Hooking multiple related APIs (e.g., memory-related functions) allows attackers to control key aspects of system behavior.
- Efficiency: Using Detours transactions, malware can apply multiple hooks in one go, simplifying the process and minimizing the risk of failure.

### 3. Inline Patching with Detours

Although Detours typically uses trampolines, it is possible to patch function entry points directly. Inline patching gives full control over the target function’s behavior. This method is often harder to detect as it doesn't rely on additional libraries.

Example with Detours for Inline Patching:

```cpp
#include <windows.h>
#include <detours.h>
#include <stdio.h>

typedef int (WINAPI* MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
MessageBoxA_t OriginalMessageBoxA = MessageBoxA;

void PatchFunction(void* targetFunction, void* newFunction) {
    DWORD oldProtect;
    VirtualProtect(targetFunction, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    
    *(BYTE*)targetFunction = 0xE9;  // JMP opcode
    *(DWORD*)((BYTE*)targetFunction + 1) = (DWORD)newFunction - (DWORD)targetFunction - 5;

    VirtualProtect(targetFunction, 5, oldProtect, &oldProtect);
}

int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    printf("Inline patched! Original Text: %s\n", lpText);
    return OriginalMessageBoxA(hWnd, "Inline patch altered this text", lpCaption, uType);
}

int main() {
    PatchFunction((void*)MessageBoxA, HookedMessageBoxA);
    MessageBoxA(NULL, "Hello, world!", "Original Message", MB_OK);
    return 0;
}

```

* Why this is beneficial for malware development:

- Stealth: Inline patching doesn’t rely on external libraries, making it harder for antivirus and monitoring tools to detect.
- Full Control: By manually patching the function’s entry point, attackers gain complete control over the function's execution without relying on Detours' built-in mechanisms.

## Conclusion

By leveraging API hooking via the Detours library, malware developers can gain control over critical system calls, modify program behavior, and potentially bypass security mechanisms. The ability to seamlessly redirect API functions to custom routines makes Detours a powerful tool in the malware developer's arsenal.

For further details, visit the official [Detours GitHub](https://github.com/microsoft/detours) and experiment with different APIs to see the true potential of this technique in malware development.

