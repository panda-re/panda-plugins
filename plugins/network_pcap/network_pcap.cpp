
#include <pcap/pcap.h>
#include <stdio.h>

#include "panda/plugin.h"
#include "exec/cpu-defs.h"

extern "C" {

bool init_plugin(void*);
void uninit_plugin(void*);

void handle_packet(CPUState* env, uint8_t* buf, size_t size, uint8_t direction,
                   uint64_t old_buf_addr);

extern uint64_t rr_get_guest_instr_count(void);
}

panda_arg_list* args;
pcap_dumper_t* plugin_log;

bool init_plugin(void* self)
{
    panda_cb pcb;

    const char* tblog_filename = NULL;
    panda_arg_list* args = panda_get_args("network_pcap");
    tblog_filename = panda_parse_string(args, "output", "network_pcap-panda3.pcap");

    if (!tblog_filename) {
        fprintf(stderr,
                "[%s] Plugin needs additional argument: "
                "-panda-arg network_pcap:output=<file>\n",
                __FILE__);
        return false;
    }

    fprintf(stdout, "Writing pcap to %s\n", tblog_filename);
    pcap_t* p = pcap_open_dead(DLT_EN10MB, 65535);
    pcap_activate(p);
    plugin_log = pcap_dump_open(p, tblog_filename);
    if (!plugin_log)
        return false;

    pcb.replay_handle_packet = handle_packet;
    panda_register_callback(self, PANDA_CB_REPLAY_HANDLE_PACKET, pcb);

    return true;
}

void uninit_plugin(void* self)
{
    fprintf(stdout, "Unloading network_pcap plugin.\n");
    panda_free_args(args);
    pcap_dump_close(plugin_log);
}

void handle_packet(CPUState* env, uint8_t* buf, size_t size, uint8_t direction,
                   uint64_t old_buf_addr)
{
    struct pcap_pkthdr h = {};
    uint64_t rridx = rr_get_guest_instr_count();

    // Assuming a 1 MHz clock
    h.ts.tv_sec = rridx / 1000000;
    h.ts.tv_usec = rridx % 1000000;

    h.caplen = size;
    h.len = size;
    pcap_dump((u_char*)plugin_log, &h, buf);

    return;
}
