# Volatility Plugin

This plugin provides an interface to the Volatility framework through an
embedded Python interpreter. Analyses are specified as scripts that are
either co-located with the plugin library. Results are stored as an `avro` record.

This plugin takes in a PANDA recording and outputs an avro record file,`volatility.panda` containing a list of processes information (process hashes, socket information, etc)

* A sample filter inupt file is require, it can be crafted as follows:
```
{
  "threads": [
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
  ]
}
```

## Dependencies plugins
* `ipanda`

## Usage

### Running manually
`volatility` plugin takes two arguments, `-os`, which asks for the type of operating system that the recording is used, and `--panda-arg filter=FILE.txt` to pass in the filter file to plugin. An example invocation: (NOTE: you need to have `RECORDING-rr-nondet.log`, `RECORDING-rr-snp`, and `filter.txt` in the path)

```bash
panda-system-i386 -m 2048 -replay /path/to/RECORDING -panda 'volatility' -os windows-32-7sp1 --panda-arg filter:file=filter.txt
```

* To view the result avro record, we can use `jq` (a command line JSON processor for better visualization)
```bash
avro cat volatility.panda | jq
```

* Sample output:
```JSON
{"rrindex": 859751564, "results": "{
     "process_hashes": [
      {
       "sha256": "04d624915b4fc5afc98e41e4e04950c8f8f41c0c00a4ec848b592c0c585effb3", 
       "base": 458752, 
       "pid": 3936
      }
     ],
      "pslist": [
      {
       "ppid": 0,
       "pid": 4,
       "asid": 1593344
      }
     ]
    "sockets" : [
      {
           "state": "",
           "remote_addr": "*",
           "proto": "UDPv4",
           "owner": "svchost.exe",
           "local_port": "3702",
           "pid": "1504",
           "remote_port": "*",
           "local_addr": "0.0.0.0"
      }
    ]
}}
```


## Modifying the analysis
Editing the analysis script is straightforward:
1. Edit `volatility/volglue.py`
2. Re-run `make`


