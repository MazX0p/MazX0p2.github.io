---
layout: post
title: "Shadow Process Chain: A Novel Approach for Advanced EDR Evasion"
date: 2024-10-25
categories: cybersecurity malware EDR-evasion
---

## Introduction

In the constant arms race between malware developers and security researchers, endpoint detection and response (EDR) systems have grown increasingly sophisticated. Traditional methods of malware evasion—such as process hollowing, indirect syscalls, and process injection—are becoming less effective as EDR solutions learn to detect even the most subtle behaviors. In this article, we introduce a **novel technique** called the **"Shadow Process Chain"**, which has the potential to **evade most modern EDR systems** by dynamically shifting the malware execution context across multiple processes.

## Background

Current EDR systems monitor for suspicious behavior at various levels, including:

- **Process creation and destruction**
- **Memory injection**
- **API hooking and interception**
- **Behavioral analysis of process trees**

Most evasion techniques today focus on disguising malicious behavior within a single process or relying on indirect system calls to avoid detection. However, these approaches have limitations as EDRs become more adept at detecting anomalies within a process, even when traditional indicators are obscured.

### The Shadow Process Chain

The **Shadow Process Chain** introduces a dynamic evasion mechanism where the malware process:

1. **Constantly spawns decoy processes** that inherit handles, memory segments, and threads from the original process.
2. **Shifts the execution context** (code, threads, or even memory regions) between these decoy processes, ensuring that no single process appears fully malicious for long.
3. **Fragmented payload distribution** across multiple processes, ensuring that no process holds the entire malicious payload at any given time.

This approach forces the EDR to chase benign processes while the actual malicious execution is hidden in transient and shifting processes.

## How the Shadow Process Chain Works

### Step 1: Process Shadowing and Handle Inheritance

The malware begins by spawning a chain of legitimate-looking **decoy processes**. Each of these processes inherits crucial handles, such as memory sections or threads, from the previous process. These decoy processes are designed to look benign and perform normal operations to evade heuristic analysis.


### Step 2: Dynamic Execution Transition

Rather than executing the payload directly in a single process, the malware dynamically transfers its **execution context** (via shared memory or APC injection) between these decoy processes. At any given time, part of the malware is running in one process, while the rest is fragmented across other decoy processes.

This ensures that no one process appears suspicious for long enough to trigger detection.

### Step 3: Process Ownership Handoff

The malware **periodically spawns new decoy processes** and **relinquishes control** of its execution context to them. This can be done by migrating threads from the old process into the new one. This process ensures that the **EDR systems track processes that appear legitimate**, while the real malicious execution moves to newly created processes that have a fresh and clean process tree.

### Step 4: Thread and Memory Fragmentation

The malware fragments its execution context by distributing code, data, and threads across multiple processes and memory regions. These processes periodically swap their threads and memory allocations, further confusing behavioral analysis engines and making it nearly impossible for an EDR to follow the complete execution flow.

### Step 5: Transient Process Recreation

As the EDR tries to track the legitimate-looking processes, the malware **periodically kills and recreates** processes while keeping the malicious payload alive in a fragmented state across memory. This creates a rapidly changing execution environment that makes it extremely hard for EDR systems to correlate events across processes.



# Technical Overview of Shadow Process Chain

## 1. Process Shadowing via Handle Inheritance

At its core, the **Shadow Process Chain** technique uses **process shadowing** to create decoy processes that inherit critical system resources, such as **handles to memory** and **thread objects**, from the original malicious process. These decoy processes appear legitimate to the OS and security tools.

### Implementation:
- The original malicious process uses the `CreateProcess` function with the `CREATE_SUSPENDED` flag to spawn a decoy process in a suspended state. This prevents immediate execution of the decoy.
- The handles and resources of the malicious process, such as open file handles, memory mappings, and threads, are **inherited** by the decoy process. This is achieved by passing `bInheritHandles` as `TRUE` in the `CreateProcess` call.
- Once the decoy is created, the malicious process can terminate, leaving the decoy process to carry on legitimate-looking operations while holding access to inherited resources.
- A critical step here is using **process hollowing** or **PE image replacement** to swap the decoy’s memory space with a legitimate process's memory space to further reduce suspicion.

### Why It Works:
- **EDR and antivirus solutions** generally trust the inheritance chain of processes, assuming that parent-child relationships are legitimate. Since the decoy inherits resources from a legitimate process and is created in a seemingly valid context, detection engines are less likely to flag it.

---

## 2. Dynamic Execution Context Migration

Instead of executing the entire malicious payload in one process, the technique migrates the **execution context** between decoy processes. This involves moving threads, registers, or execution pointers across multiple processes.

### Implementation:
- **Thread Migration**: The malicious process spawns threads that are injected into a decoy process. The thread’s entry point is set to execute part of the malware’s payload.
  - The malware can use `NtCreateThreadEx` to create threads in the address space of the decoy process, effectively transferring execution to it.
- **Shared Memory Sections**: The malicious payload is split into fragments and stored in **shared memory sections**. These sections are accessible by multiple decoy processes, allowing the malware to execute across multiple processes in a fragmented way.
  - Memory is shared between processes using `CreateFileMapping` and `MapViewOfFile`, with both processes sharing parts of the payload without fully holding the malicious content at any given time.

### Why It Works:
- **Behavioral analysis engines** monitor for sustained abnormal activities in a single process. By fragmenting execution across multiple processes and spreading out the suspicious behaviors, no single process appears malicious for long.
- Additionally, **EDRs struggle** with tracking cross-process execution when a process that exhibits abnormal behavior no longer exists by the time detection is triggered.

---

## 3. Process Ownership Handoff (Context Handover)

Process ownership handoff involves **transferring the execution context** (such as threads or sections of memory) from one decoy process to another. This ensures that the EDR is continually chasing benign processes, while the actual payload is handled by a process that remains "fresh" and undetected.

### Implementation:
- **Thread Handoff**: The malware creates a thread in the original decoy process that executes part of the payload, then transfers the thread handle to another decoy process. This can be done using `NtSetInformationThread` to change the thread’s context or `NtQueueApcThread` to inject code into another process’s thread.
- **Memory Handoff**: The malicious code migrates between processes by copying its execution context (such as instruction pointers, registers, and stack) to another process. The `ZwReadVirtualMemory` and `ZwWriteVirtualMemory` APIs can be used to modify memory spaces between processes.

### Why It Works:
- The malware leaves behind **no persistent malicious activity** in the original decoy process because control is transferred to a newly created process. Each new process starts with a clean slate, which makes detection harder for traditional static or behavioral-based EDR systems.

---

## 4. Thread and Memory Fragmentation

To make detection even harder, the **malicious payload** is divided into small fragments and executed across multiple processes in parallel. Each process holds only a fragment of the execution context or payload, so no single process reveals the complete malicious activity.

### Implementation:
- **Memory Fragmentation**: The payload is fragmented into different memory sections, and these sections are distributed across multiple processes. The `CreateFileMapping` API can be used to map different memory regions into multiple decoy processes, ensuring that no one process contains the entire malicious code.
- **Thread Fragmentation**: The malware splits its execution across multiple threads, each responsible for executing a small part of the payload. These threads are distributed between processes using thread injection techniques like `NtCreateThreadEx`.

### Why It Works:
- **EDR tools** that scan memory or threads for malicious activity will struggle to piece together the fragmented payload. Since no one thread or process holds enough of the payload to be flagged, the malware remains under the detection radar.
- The use of **shared memory** between processes allows the payload to communicate across decoy processes, but EDRs typically focus on individual processes, not cross-process relationships.

---

## 5. Transient Process Recreation

As a final evasion technique, the malware periodically **kills and recreates decoy processes**, making it even harder for EDR systems to track any specific malicious activity.

### Implementation:
- The malware uses the **Process Hollowing** technique to spawn new decoy processes periodically, replacing legitimate executables with a benign-looking memory footprint. Once execution control is handed over to the newly created process, the old process terminates to further avoid detection.
- The malware keeps its malicious execution alive by continuously spawning and destroying decoy processes, using APIs like `CreateProcess`, `ZwTerminateProcess`, and `NtSuspendThread` to pause and shift execution between processes.

### Why It Works:
- EDRs that track **long-term behavioral patterns** will find it difficult to monitor transient processes because each new process appears legitimate. The continuous recreation and destruction of processes ensure that no suspicious process survives long enough to be analyzed.

---

## How Shadow Process Chain Bypasses EDRs

- **Heuristic Evasion**: By dynamically switching between processes and fragmenting the payload, **Shadow Process Chain** breaks the flow of traditional heuristics-based analysis, making it nearly impossible for EDRs to track malicious execution patterns.
- **Memory Forensics Avoidance**: Since the malware's payload is spread across multiple memory regions and processes, even deep memory analysis would struggle to reconstruct the complete execution flow.
- **Process Tree Manipulation**: The creation and destruction of decoy processes leave behind a **clean process tree** that looks legitimate, while the actual malicious execution is hidden in transient processes.

---

## New in This Approach

- **Real-time Execution Migration**: Unlike traditional process hollowing or thread injection techniques, the **Shadow Process Chain** dynamically migrates execution in real time, avoiding static detection.
- **Advanced Memory Fragmentation**: This method fragments not only the payload but also memory sections and execution threads across multiple processes, making detection exponentially harder.

---

This highly technical breakdown provides a detailed, low-level explanation of the **Shadow Process Chain** technique and how it manipulates processes, threads, and memory to evade modern EDR systems.

## Bypassing Advanced EDR Systems

The **Shadow Process Chain** technique is designed to bypass **many modern EDR detection techniques**, including:

1. **Heuristic and Behavioral Analysis**: Since no single process displays sustained malicious behavior, the EDR cannot build a sufficient behavior profile to flag the activity as suspicious.
2. **Memory Scanning**: By fragmenting the payload across multiple processes and frequently transitioning between them, memory scanning tools struggle to identify the complete payload or establish a clear connection between fragments.
3. **Process Tree Analysis**: Traditional process hollowing or injection leaves behind suspicious traces in the process tree. However, in the **Shadow Process Chain**, the process tree remains filled with **legitimate-looking processes** that don’t reveal any signs of malicious activity.
4. **API Hooking and Indirect Syscalls**: The malware uses a combination of **indirect syscalls** and API obfuscation to further confuse the detection mechanisms, ensuring that even if an EDR hooks certain functions, the actual execution remains hidden.

## Advantages of the Shadow Process Chain

1. **Complete Stealth**: No single process behaves in a consistently malicious manner, making detection through behavior analysis extremely difficult.
2. **Minimal Memory Footprint**: By fragmenting the payload and distributing it across multiple processes, the memory footprint of any single process remains small and innocuous.
3. **Constantly Changing Execution**: EDRs struggle to keep up with the constant recreation and destruction of processes, making it nearly impossible to track the actual execution flow.
4. **Versatile**: This technique can be applied to various payload types, from traditional malware to more sophisticated tools like ransomware or advanced persistent threats (APTs).

## Potential Improvements

While the **Shadow Process Chain** provides a robust framework for evading detection, future research can focus on:

- **Automating Execution Context Migration**: Creating an automated system for continuously shifting the execution context between processes to avoid any manual intervention.
- **Combining with Kernel-Level Evasion**: By combining this technique with kernel-level evasion, the malware can further hide its execution from even advanced EDR solutions that monitor kernel-mode behavior.
- **Adding AI-based Context Shifting**: Use machine learning models to dynamically determine the optimal times to shift processes and threads to avoid detection, based on the behavior of the EDR system.

## Conclusion

The **Shadow Process Chain** is a novel technique that enables malware to evade the majority of modern EDR systems by continuously shifting execution across multiple processes, fragmenting the payload, and creating transient processes that confuse process tracking mechanisms. By making EDRs chase benign decoy processes, this technique introduces a new level of stealth, ensuring that no process displays malicious behavior for long enough to be detected.

With this technique, malware developers can move beyond traditional process hollowing or indirect syscall methods, introducing a more dynamic and resilient method of evading even the most advanced detection technologies.
