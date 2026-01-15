# Shellcode Test Harness
A lightweight test harness designed to speed up shellcode development by providing an execution environment with integrated crash diagnostics and debug output redirection. 

## Features
* Executes shellcode via module stomping
* Uses VEH to catch crashes: If the shellcode faults, it prints a register dump, a stack dump, and a code dump at the failure point.
* Realtime Debug Output: intercept shellcode output and displays it in the console.
* Built-in hex dump utility: By prepending debug output with "HEXDUMP:0xADDR:SIZE", the loader will dump that memory range automatically.
* DLL Discovery: Finds compatible DLL's, optionally filtering out DLL's that don't have a .text section large enough for a specific payload. ***NOTE: Not all found DLL's will be compatible, some may have unique entry point behaviors, protected memory regions, or dependencies that interfere with stomping*** 

### Building
```make
g++ -o loader.exe loader.cc -ladvapi32 -luser32 -lkernel32 -static
```

### Usage
```make
# Execute a payload using the default host DLL
loader.exe --bin payload.bin

# Execute a payload by stomping a specific DLL
loader.exe --bin payload.bin --dll mscoree.dll

# Scan for all compatible DLLs
loader.exe --scan

# Scan for DLLs with a .text section large enough for a specific payload
loader.exe --scan --bin payload.bin
```

### Example DbgPrint Wrapper
```C++
#if defined(DEBUG)
#define PDEBUG(format, ...)                                                    \
  {                                                                            \
    ntdll.DbgPrint(symbol<PCH>("%-48s " format), symbol<PCH>(({                \
                     char __buf[48];                                           \
                     memory::snprintf(__buf, sizeof(__buf), "[%s:%d]",         \
                                      __FUNCTION__, __LINE__);                 \
                     __buf;                                                    \
                   })),                                                        \
                   ##__VA_ARGS__);                                             \
  }
#define PDEBUG_CTX(ctx, format, ...)                                           \
  {                                                                            \
    if ((ctx) && (ctx)->ntdll.DbgPrint) {                                      \
      (ctx)->ntdll.DbgPrint(symbol<PCH>("%-48s " format), symbol<PCH>(({       \
                              char __buf[48];                                  \
                              memory::snprintf(__buf, sizeof(__buf), "[%s:%d]",\
                                               __FUNCTION__, __LINE__);        \
                              __buf;                                           \
                            })),                                               \
                            ##__VA_ARGS__);                                    \
    }                                                                          \
  }
#else
#define PDEBUG(format, ...)                                                    \
  {                                                                            \
    ;                                                                          \
  }
#define PDEBUG_CTX(ctx, format, ...)                                           \
  {                                                                            \
    ;                                                                          \
  }
#endif
```

### HEXDUMP Example
```C++
PSYSCALL_TABLE pTable = NULL;
SIZE_T regionSize = sizeof(SYSCALL_TABLE);

ntdll.NtAllocateVirtualMemory(
    (HANDLE)-1,               
    (PVOID*)&pTable,         
    0,                      
    &regionSize,             
    MEM_COMMIT | MEM_RESERVE, 
    PAGE_READWRITE  
);

if (pTable) {
    pTable->NtTerminateProcess = 0x2c; // Example syscall number
    PDEBUG("HEXDUMP:%p:%zu", pTable, sizeof(SYSCALL_TABLE));
}
```

![example run](loader.gif)   
