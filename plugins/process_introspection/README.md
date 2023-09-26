# Process Introspection

This plugin takes in a PANDA recording and outputs an avro record file,`process_introspection.panda`, containing a list of processes  , along with its metadata (e.g, `pid`, `asid`, `modules`), that are running during the time of recording.

* The current list of supported operating systems are:
    * `windows-32-7sp1`
    * `windows-64-7sp1`
    * `windows-32-xpsp2`
    * `windows-32-xpsp3`
    * `linux-32-3.16`
    * `linux-64-3.16`


## Dependencies plugins
* `ipanda`

## Usage


### Running manually
The `process_introspection` plugin takes exactly one argument, `os`, which asks for the type of operating system that the recording is used. An example invocation: (NOTE: need to have `RECORDING-rr-nondet.log` and `RECORDING-rr-snp` in the path)

```bash
panda-system-i386 -m 2048 -replay /path/to/RECORDING -os "windows-32-7sp1" -panda 'process_introspection' 
```

* To view the result avro record, we can use `jq` (a command line JSON processor for better visualization)
```bash
avro cat process_introspection.panda | jq
```

* Sample output:
```bash
...
{
  "type": "windows-32-7sp1",
  "pid": 2496,
  "ppid": 1108,
  "asid": 2041053184,
  "name": "calc.exe",
  "cmdline": "\"C:\\Windows\\system32\\calc.exe\" ",
  "create_time": 132893838329236000,
  "base_vba": 5505024,
  "start_rrindex": 2329425696,
  "end_rrindex": 5556213185,
  "modules": [
    {
      "name": "",
      "path": "",
      "base_address": 0,
      "image_size": 0,
      "timedatestamp": 0,
      "entry_point": 0,
      "guid": ""
    },
    {
      "name": "ADVAPI32.dll",
      "path": "c:\\windows\\system32\\advapi32.dll",
      "base_address": 1981546496,
      "image_size": 659456,
      "timedatestamp": 1505315341,
      "entry_point": 1981630777,
      "guid": "9D2559DE439D4F27A336602B9098C936"
    },
    {
      "name": "calc.exe",
      "path": "c:\\windows\\system32\\calc.exe",
      "base_address": 5505024,
      "image_size": 786432,
      "timedatestamp": 1290246045,
      "entry_point": 5582188,
      "guid": "971D2945E998438C847643A9DB39C88E"
    },
...
```

