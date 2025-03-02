# Anti-Cheat
An open source user mode anti-cheat compatible with x86 and x64 applications.
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
* Syscall callbacks
* Proper callstack walks (see [unwinder](https://github.com/thetuh/unwinder) based on [SilentMoonWalk](https://github.com/klezVirus/SilentMoonwalk))
* Kernel driver and external process components
# Resources
https://github.com/TsudaKageyu/minhook
https://github.com/vmcall/MapDetection
https://github.com/mq1n/DLLThreadInjectionDetector
