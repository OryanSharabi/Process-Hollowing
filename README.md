# Process Hollowing
POC in c/c++ for Windows.

Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses.
Process hollowing is a method of executing arbitrary code in the address space of a separate live process.
Process hollowing is commonly performed by creating a process in a suspended state then unmapping/hollowing its memory, which can then be replaced with malicious code.
 A victim process can be created with native Windows API calls such as CreateProcess, which includes a flag to suspend the processes primary thread.
 At this point the process can be unmapped using APIs calls such as ZwUnmapViewOfSection or NtUnmapViewOfSection before being written to,
 realigned to the injected code, and resumed via VirtualAllocEx, WriteProcessMemory, SetThreadContext, then ResumeThread respectively.
 _(mitre att&ck Process Injection: Process Hollowing)_

### Usage:

replace the `<file name>` in CreateProcessA to your legitimate targert process,
and `<finle name>` in pSourceFile to your malware payload.

compile to x86 release for target and inject process 32 bit.
compile to x64 release for target and inject process 64 bit.

### Difference between 32 bit process hollowing and 64 bit:

On a 32 bit process-
    
    on suspend mode ebx register is pointing to the PEB, and eax is pointing to the entry point.

On a 64 bit process- 

    on suspend mode rdx is pointing to the PEB, and rcx is pointing to the entry point.

### Notes:

The hollowing works only if the two PE compiled to the same platform (x86\x64)and cannot work with windows programs.

### Resources 
Process Hollowing - Digital Whisper https://www.digitalwhisper.co.il/files/Zines/0x4D/DW77-3-PoccessHollowing.pdf
