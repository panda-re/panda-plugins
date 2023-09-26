# syscall tracer

This plugin takes in a PANDA recording and outputs a database file,`syscalls.db`, containing a list of information regarding to syscalls that are being executed within the recording period on a system.

## Syscall Tracer Schema

* SystemCall
  - Syscall ID
  - Name
  - Number_of_args

* Type:
  - Name

* IoType:
  - Name

* SyscallInvocation
  - PID
  - ASID
  - TID
  - EntryPoint (Boolean)
  - ReturnValue (Optional)
  - Instruction Count
  - SystemCall
  - List<Arguments>

* Argument:
  - Type
  - IoType
  - Value
  - Position
  - Description (Json)

* The current list of supported operating systems are:
    * `windows-32-7sp1`
    * `windows-64-7sp1`
    * `windows-32-xpsp2`
    * `windows-32-xpsp3`
    * `linux-32-3.16`
    * `linux-64-3.16`


## Dependencies plugins
* `ipanda`
* `typesignature`
* `sqlite3`
* `liboffset`
* `libiohal`
* `libosi`

## Usage


### Running manually
The `syscall_tracer` plugin takes exactly one argument, `os`, which asks for the type of operating system that the recording is used. An example invocation: (NOTE: need to have `RECORDING-rr-nondet.log` and `RECORDING-rr-snp` in the path)

```bash
panda-system-i386 -m 2048 -replay /path/to/RECORDING -os "windows-32-7sp1" -panda "syscall_tracer"
```

