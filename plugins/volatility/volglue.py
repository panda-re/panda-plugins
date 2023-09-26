# This section sets up the volatility environment
# and is invoked by the plugin when it loads this
# script as a module
#
# It should be refactored so that the setup
# is done as a function call to make it cleaner
# and take the profile as an argument
import os
import json
import shutil
import hashlib
import tempfile
import traceback

import volatility
import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.addrspace as addrspace
import volatility.plugins.taskmods as taskmods
import volatility.plugins.malware.svcscan as svcscan
import volatility.plugins.netscan as netscan
import volatility.plugins.procdump as procdump
import volatility.plugins.vadinfo as vadinfo

# Volatility initialization code
registry.PluginImporter()
config = conf.ConfObject()
registry.register_global_options(config, commands.Command)
registry.register_global_options(config, addrspace.BaseAddressSpace)


def maybe_add_image(obj, proc):
    if proc.Peb:
        obj["ImagePathName"] = str(proc.Peb.ProcessParameters.ImagePathName).encode(
            "utf-8", "replace"
        )
    return obj


def filter_invalid_ascii(strobj):
    return strobj.encode("utf-8", "replace")


def is_interesting(eprocess, filter_data):
    check_pid = int(eprocess.UniqueProcessId)
    check_asid = int(eprocess.Pcb.DirectoryTableBase)

    for (pid, tid, asid) in filter_data["threads"]:
        if check_pid == int(pid) and check_asid == int(asid):
            return True
    return False


def hash_file(filepath, *algorithms):
    with open(filepath, "rb") as fobj:
        while True:
            chunk = fobj.read(4096)
            if not chunk:
                break

            for a in algorithms:
                a.update(chunk)

    return {a.name: a.hexdigest().lower() for a in algorithms}


def get_process_hashes(config, filter_data):
    config.DUMP_DIR = tempfile.mkdtemp()

    runner = procdump.ProcDump(config)

    results = []
    for proc in runner.calculate():
        addr = proc.get_process_address_space()

        vtop_check = False
        invalid = any(
            [
                addr is None,
                proc.Peb is None,
            ]
        )
        if proc.Peb:
            vtop_check = addr.vtop(proc.Peb.ImageBaseAddress) is None

        if invalid:
            if vtop_check:
                continue

        if is_interesting(proc, filter_data):
            name = str(proc.ImageFileName)

            runner.dump_pe(addr, proc.Peb.ImageBaseAddress, name)

            dumped_file = os.path.join(config.DUMP_DIR, name)

            result = {
                "pid": int(proc.UniqueProcessId),
                "base": int(proc.Peb.ImageBaseAddress),
            }
            result.update(hash_file(dumped_file, hashlib.sha256()))
            results.append(result)

    shutil.rmtree(config.DUMP_DIR)

    return results


def get_memory_hashes(config, filter_data):
    config.DUMP_DIR = tempfile.mkdtemp()

    runner = vadinfo.VADDump(config)

    results = []
    for proc in runner.calculate():
        addr = proc.get_process_address_space()

        if not addr:
            continue

        if is_interesting(proc, filter_data):

            for vad, _ in proc.get_vads(
                vad_filter=lambda v: v.Length < pow(2, 30), skip_max_commit=True
            ):
                path = os.path.join(
                    config.DUMP_DIR,
                    "{}_{}.{}".format(vad.Start, vad.End, proc.UniqueProcessId),
                )

                runner.dump_vad(path, vad, addr)

                result = {
                    "pid": int(proc.UniqueProcessId),
                    "start": int(vad.Start),
                    "end": int(vad.End),
                }
                result.update(hash_file(path, hashlib.sha256()))
                results.append(result)

    shutil.rmtree(config.DUMP_DIR)

    return results


def get_pslist(config):
    """List all the tasks that aren't hidden, unlinked, etc"""
    p = taskmods.PSList(config)
    pdata = []
    for proc in p.calculate():
        obj = {
            "pid": int(proc.UniqueProcessId),
            "ppid": int(proc.InheritedFromUniqueProcessId),
            "asid": int(proc.Pcb.DirectoryTableBase),
        }
        obj = maybe_add_image(obj, proc)
        pdata.append(obj)
    return pdata


def get_svcscan(config):
    """List all of the system services"""
    scanner = svcscan.SvcScan(config)
    aggregate_data = []
    for service in scanner.calculate():
        sdata = {
            "ServiceName": str(service.ServiceName.dereference()),
            "DisplayName": str(service.DisplayName.dereference()),
            "DriverName": str(service.DriverName.dereference()),
            "State": str(service.State),
            "Pid": int(service.ServiceProcess.dereference().ProcessId),
        }

        aggregate_data.append(sdata)
    return aggregate_data


SOCKETS_PROFILES = [
    "VistaSP0x64",
    "VistaSP0x86",
    "VistaSP1x64",
    "VistaSP1x86",
    "VistaSP2x64",
    "VistaSP2x86",
    "Win7SP0x64",
    "Win7SP0x86",
    "Win7SP1x64",
    "Win7SP1x86",
    "Win2008R2SP0x64",
    "Win2008R2SP1x64",
    "Win2008SP1x64",
    "Win2008SP1x86",
    "Win2008SP2x64",
    "Win2008SP2x86",
    "Win8SP0x64",
    "Win8SP0x86",
    "Win8SP1x64",
    "Win8SP1x86",
    "Win81U1x64",
    "Win81U1x86",
    "Win2012R2x64",
    "Win2012x64",
    "Win10x64",
    "Win10x86",
]


def get_sockets(config):
    """List all of the sockets that have not been unlinked or hidden"""

    # This only works for Vista and later

    if config.PROFILE not in SOCKETS_PROFILES:
        return []

    scanner = netscan.Netscan(config)
    socket_data = []

    for socket in scanner.calculate():
        netobj, proto, laddr, lport, raddr, rport, state = socket

        if netobj.Owner != None:
            pid = str(netobj.Owner.UniqueProcessId)
            owner = filter_invalid_ascii(netobj.Owner.ImageFileName)
        else:
            pid = "-1"
            owner = "Unknown"

        sdata = {
            "pid": str(pid),
            "owner": str(owner),
            "proto": str(proto),
            "local_addr": str(laddr),
            "local_port": str(lport),
            "remote_addr": str(raddr),
            "remote_port": str(rport),
            "state": str(state),
        }
        socket_data.append(sdata)

    return socket_data


# TODO add a pool tag scanner to look for unlinked processes?


def run(profile, location, filterfile):
    """Returns a list of the processes as a JSON string

    This analysis demonstrates that volatility can be successfully
    invoked and that data can be serialized as JSON data and
    returned to the plugin.

    """
    print("Volatility version: %r" % volatility.constants.VERSION)
    try:
        config.PROFILE = profile
        config.LOCATION = location

        with open(filterfile, "rb") as fobj:
            filter_data = json.load(fobj)

        analysis_results = {
            "pslist": get_pslist(config),
            "svcscan": get_svcscan(config),
            "sockets": get_sockets(config),
            "process_hashes": get_process_hashes(config, filter_data),
            "memory_hashes": get_memory_hashes(config, filter_data),
        }
    except Exception as err:
        analysis_results = {"error": traceback.format_exc(err)}

    json_str = json.dumps(analysis_results, indent=1)
    return json_str


# This stub is here to make it easier to test. Use pmemsave
# in a QEMU monitor to write a sample image to /tmp/memshot
# and then run this script as `python volglue.py` to
# see if it works.
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Test analysis")
    parser.add_argument("--location", default="file:///tmp/memshot")
    parser.add_argument("--profile", default="Win7SP1x64")
    args = parser.parse_args()
    print(run(args.profile, args.location))


### Must end with this comment
