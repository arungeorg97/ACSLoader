# ACSLoader

-------------------------------------\_~~__(··)_~~_/-------------------------------------------

This repository contains a couple of simple loader scripts based on c#. Using Dinvoke concept without having to integrate the dinvoke dll.


- Technique -1 - GetSyscallStub :
  - This works by reading the original syscall stub from ntdll on disk and copying it into a new memory region within our calling process.
  - Binary file is called during runtime to provide better static opsec and the loader to have better entropy.

- Technique -2 - GetLibraryAddress:
  - First, checks if the module is already loaded using GetLoadedModuleAddress. If not, it loads the module into the process using LoadModuleFromDisk, which uses the NT API call LdrLoadDll to load the DLL.
  - Binary file is called during runtime to provide better static opsec and the loader to have better entropy.

- Opsec:
  - Obfusicate and remove debug statements.
  - For better file opsec follow this - highly recommended [SharpUp](https://redteamer.tips/basic-operational-security-when-dropping-to-disk/).


- Acknowledgments:
  - [Red Team Ops II](https://training.zeropointsecurity.co.uk/courses/red-team-ops-ii)
  - [DInvoke](https://github.com/TheWover/DInvoke)
  - [thewover](https://thewover.github.io/Dynamic-Invoke/)
  - [jfmaes](https://github.com/jfmaes)
