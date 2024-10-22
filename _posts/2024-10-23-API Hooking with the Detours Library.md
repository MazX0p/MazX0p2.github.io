---
title: API Hooking with the Detours Library
date: 2024-10-23 01:48:00 +0300
categories: [Maldev, Evasion]
tags: [Evasion]     # TAG names should always be lowercase
---

# API Hooking with the Detours Library

## Overview
The **Detours Hooking Library**, developed by Microsoft Research, allows developers to intercept and redirect function calls in Windows applications. By redirecting calls to specific functions, developers can insert user-defined behavior to modify or extend the original functionality. Detours is typically used with C/C++ programs and works for both 32-bit and 64-bit applications.

## How Does Detours Work?
The Detours library modifies the initial instructions of a target function (the function to be hooked) by inserting an unconditional jump (often called a *trampoline*) to a custom detour function. This detour allows your custom code to execute instead of the original.

The library also uses **transactions** to manage the installation and removal of hooks. Transactions allow multiple hooks to be grouped together, making it easier to apply or revert complex changes.

## Setting Up the Detours Library
To use the Detours library, download and compile the Detours repository to obtain the static library files (`.lib`) and include the `detours.h` header file. Detailed instructions are available in the Detours Wiki under the "Using Detours" section.

### 32-bit vs 64-bit Configuration
Detours supports both 32-bit and 64-bit Windows systems, and the following preprocessor code can be used to determine the appropriate `.lib` file to link:

```cpp
// If compiling as 64-bit
#ifdef _M_X64
#pragma comment (lib, "detoursx64.lib")
#endif // _M_X64

// If compiling as 32-bit
#ifdef _M_IX86
#pragma comment (lib, "detoursx86.lib")
#endif // _M_IX86
```

### Detours API Functions
The key API functions provided by the Detours library include:
- **`DetourTransactionBegin`**: Starts a new transaction for attaching or detaching detours.
- **`DetourUpdateThread`**: Enlists the current thread in the transaction.
- **`DetourAttach`**: Attaches a hook to a target function.
- **`DetourDetach`**: Detaches a hook from a target function.
- **`DetourTransactionCommit`**: Commits the transaction, applying or removing the hooks.

These functions return a `LONG` value for error-checking, where `NO_ERROR` indicates success.

### Creating a Replacement Function
To create a replacement function, it should have the same signature as the original function. This allows you to modify the parameters and/or behavior as needed:

```cpp
INT WINAPI MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
  // Inspect or modify parameters
  printf("Original lpText: %s\n", lpText);
  printf("Original lpCaption: %s\n", lpCaption);
  return MessageBoxA(hWnd, "Modified lpText", "Modified lpCaption", uType);
}
```

### Avoiding Infinite Loops
If you call the original function from within the hook without unhooking it first, it can result in an **infinite loop**. To prevent this, store the original function's address in a global function pointer before hooking:

```cpp
// Pointer to unhooked MessageBoxA
typedef int (WINAPI *fnMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
fnMessageBoxA g_pMessageBoxA = MessageBoxA;

INT WINAPI MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
  printf("Original lpText: %s\n", lpText);
  return g_pMessageBoxA(hWnd, "Modified lpText", "Modified lpCaption", uType);
}
```

## Installing and Removing Hooks
To install a hook, initiate a transaction, enlist the current thread, attach the hook, and commit the transaction.

### Hook Installation Example
```cpp
BOOL InstallHook() {
  if (DetourTransactionBegin() != NO_ERROR) return FALSE;
  if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR) return FALSE;
  if (DetourAttach(&(PVOID&)g_pMessageBoxA, MyMessageBoxA) != NO_ERROR) return FALSE;
  if (DetourTransactionCommit() != NO_ERROR) return FALSE;
  return TRUE;
}
```

### Hook Removal Example
The process for unhooking is similar, using `DetourDetach` instead of `DetourAttach`.

```cpp
BOOL Unhook() {
  if (DetourTransactionBegin() != NO_ERROR) return FALSE;
  if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR) return FALSE;
  if (DetourDetach(&(PVOID&)g_pMessageBoxA, MyMessageBoxA) != NO_ERROR) return FALSE;
  if (DetourTransactionCommit() != NO_ERROR) return FALSE;
  return TRUE;
}
```

## Main Function Example
The following main function demonstrates calling the original, hooked, and unhooked versions of `MessageBoxA`:

```cpp
int main() {
  // Original function call
  MessageBoxA(NULL, "Initial call", "Original", MB_OK);

  // Install hook
  if (InstallHook()) {
    MessageBoxA(NULL, "This will be hooked", "Hooked", MB_OK);
  }

  // Unhook
  if (Unhook()) {
    MessageBoxA(NULL, "Unhooked call", "Original", MB_OK);
  }

  return 0;
}
```

## Summary
The Detours Library provides powerful tools for **API hooking** in Windows, allowing developers to replace and extend the functionality of existing functions. Transactions make managing hooks easy, and understanding the use of trampolines and avoiding infinite loops is crucial for effective usage.

For more detailed information and examples, refer to the [[Detours Wiki|https://github.com/microsoft/Detours/wiki]].
