# Network Packet Dump

This plugin writes out packets sent and received during a replay. It
does so using the `PANDA_CB_REPLAY_HANDLE_PACKET` callback, which is
triggered when the replay system encounters a log entry corresponding to
a packet being sent or received. `libpcap` is used to produce the PCAP
file.

## Usage

The `network_pcap` plugin will generate an output file called `network_pcap-panda3.pcap`. An example invocation:

```bash
panda-system-i386 -m 2048 -replay RECORDING_NAME -panda 'network_pcap' 
```
## Caveats

Note that currently network information is only recorded for the `e1000`
NIC (this is the default for QEMU x86). Also, replays created before May
2014 do not contain network information, and so this plugin will not
work with them.

At present, the replay system does not have access to the time inside
the guest, so the PCAP timestamps on the packets are taken from the time
during *replay*, not the time the packet was actually sent during the
recording.
