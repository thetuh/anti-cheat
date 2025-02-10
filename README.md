# Anti-Cheat
An open source User Mode Anti-Cheat written for x86 applications.
# Notes
* This is a foundational implementation and should be treated as such.
* All saved files/dumps would practically be sent back to a server for static analysis.
* This was tested with Process Hacker, Xenos, and Extreme Injector.
# Features
* Detects DLL Injection (LoadLibrary or Manual Map)
* Scans suspicious memory regions and dumps them to disk
* Copies unsigned modules to disk
* Reports all activity to console
# Planned
* Showcase/Demo
* Self integrity checks
* Thread start address checks
* Checking .text section modifications
* Syscall callbacks
* Proper callstack walks (see 
* Kernel driver and external process components
# Resources
https://github.com/TsudaKageyu/minhook
https://github.com/vmcall/MapDetection
https://github.com/mq1n/DLLThreadInjectionDetector
