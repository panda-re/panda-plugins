# bbstats

This plugin takes in a PANDA recording and outputs an avro record file,`bbstats.panda` containing a list of processes

1. takes in an input filter file (a json file containing a list of whitelisted `guid` along with the corresponding `pid`, `tid`, `asid` to trace)
2. the tracer will then disassembles every basic block in the module is executing in memory with `guid` in `guid_whitelist`


* A sample filter file can be crafted as follows:
```
{
  "thread_whitelist": [
    [
      pid,
      tid1,
      asid
    ],
    [
      pid,
      tid2,
      asid
    ]
  ],
  "guid_whitelist": [
    "guid",
  ]
}
```



* The current list of supported operating systems are:
    * `windows-32-7sp1`
    * `windows-64-7sp1`
    * `windows-32-xpsp2`
    * `windows-32-xpsp3`
    * `linux-32-3.16`
    * `linux-64-3.16`


## Dependencies plugins
* `ipanda`
* `process_introspection` (to get mapping of process common name to `pid` and `guid`)
* `syscall_tracer` (to get mapping of `pid` to `tid`, `asid`)

## Usage


### Running manually
`bbstats` plugin takes two arguments, `-os`, which asks for the type of operating system that the recording is used, and `--panda-arg params:filter=FILE.txt` to pass in the filter file to plugin. An example invocation: (NOTE: need to have `RECORDING-rr-nondet.log`, `RECORDING-rr-snp`, and `filter.txt` in the path)

```bash
panda-system-i386 -m 2048 -replay /path/to/RECORDING -os "windows-32-7sp1" -panda bbstats --panda-arg params:filter=filter.txt
```

* To view the result avro record, we can use `jq` (a command line JSON processor for better visualization)
```bash
avro cat bbstats.panda | jq
```

* Sample output:
```bash
...
{
  "pid": 2460,
  "asid": 101543936,
  "threads": [
    2464
  ],
  "image_guid": "971D2945E998438C847643A9DB39C88E",
  "image_path": "C:\\Windows\\system32\\calc.exe",
  "image_base": 10092544,
  "pc": 10255746,
  "rva": 163202,
  "icount": 1,
  "size": 5,
  "hits": 1,
  "instructions": [
    {
      "offset": 0,
      "hexdump": "e9412dfeff",
      "mnemonic": "JMP",
      "arguments": "0xfffe2d46"
    }
  ]
}
...
```

