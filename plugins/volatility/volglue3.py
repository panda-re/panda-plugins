# This section sets up the volatility environment
# and is invoked by the plugin when it loads this
# script as a module
#
# It should be refactored so that the setup
# is done as a function call to make it cleaner
# and take the profile as an argument
import os
import json
import logging
import shutil
import subprocess
import hashlib
import tempfile
import traceback

import volatility3
from volatility3.cli import text_renderer
from volatility3.plugins.windows import pedump, psscan, pslist, svcscan, netscan, vadinfo
from volatility3.framework.interfaces.context import ModuleInterface, ModuleContainer
from volatility3.framework import automagic, contexts, interfaces, plugins


import socket
from typing import Optional

vollog = logging.getLogger(__name__)

class UnixSocketFileHandler(interfaces.plugins.FileHandlerInterface):
    def __init__(self, socket_path: str, filename: str) -> None:
        """Initializes the UnixSocketFileHandler."""
        super().__init__(filename)
        self.socket_path = socket_path
        self.sock: Optional[socket.socket] = None
        self.file: Optional[socket.SocketIO] = None

    def open(self):
        """Connects to the existing Unix domain socket and wraps it in a file-like interface."""
        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(self.socket_path)
            # Wrap the socket in a file-like interface
            self.file = self.sock.makefile(mode="rwb")
        except FileNotFoundError:
            raise Exception(f"Socket file not found: {self.socket_path}")
        except PermissionError:
            raise Exception(f"Permission denied for socket: {self.socket_path}")
        except Exception as e:
            raise Exception(f"Failed to connect to Unix domain socket: {e}")

    def read(self, buffer_size: int = 1024) -> bytes:
        """Reads data from the socket."""
        if self.file is None:
            raise Exception("Socket is not connected")
        return self.file.read(buffer_size)

    def write(self, data: bytes):
        """Writes data to the socket."""
        if self.file is None:
            raise Exception("Socket is not connected")
        self.file.write(data)
        self.file.flush()

    def close(self):
        """Closes the socket connection."""
        if self.file is not None:
            self.file.close()
            self.file = None
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitizes the filename to ensure only a specific allow list of characters is allowed through."""
        allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.- ()[]{}!$%^#~,"
        result = ""
        for char in filename:
            if char in allowed:
                result += char
            else:
                result += "_"  # change unwanted chars to an underscore
        return result


ctx = contexts.Context()


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


def get_process_hashes():
    config_path = "plugins.PEDump"
    automagics = automagic.choose_automagic(available_automagics, pedump.PEDump)
    # breakpoint()
    constructed = plugins.construct_plugin(ctx, automagics, pedump.PEDump, config_path, progress_callback=None, open_method=None)
    treegrid = constructed.run()
    # breakpoint()

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

    return results


def get_memory_hashes(filter_data):
    # breakpoint()
    runner = vadinfo.VADDump()

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

    return results

def socket_visitor(node, accumulator):
    if node.values:
        proto, laddr, lport, raddr, rport, state, pid, owner = node.values[1:9]
        state = "STATELESS" if state == "" else state
        laddr = "::" if type(laddr) == volatility3.framework.renderers.UnreadableValue else laddr
        pid = -1 if type(pid) == volatility3.framework.renderers.UnreadableValue else int(pid)
        owner = "" if type(owner) == volatility3.framework.renderers.UnreadableValue else owner
        raddr = "::" if type(raddr) == volatility3.framework.renderers.UnreadableValue else raddr

        sdata = {
            "pid": pid,
            "owner": owner,
            "proto": proto,
            "local_addr": laddr,
            "local_port": int(lport),
            "remote_addr": raddr,
            "remote_port": rport,
            "state": state,
        }
        # print(sdata)
        # breakpoint()
        accumulator.append(sdata)
    return accumulator

def pslist_visitor(node, accumulator):
    if node.values:
        pid, ppid, img_name, offset = node.values[0:4]
        proc = ctx.object("symbol_table_name1!_EPROCESS", "layer_name", offset)
        # if img_name == "services.exe":
        #     print(offset)
        #     breakpoint()
        pdata = {
            "pid": int(pid),
            "ppid": int(ppid),
            "asid": int(proc.Pcb.DirectoryTableBase),
            "ImagePathName": img_name,
        }
        accumulator.append(pdata)
    return accumulator


def svcscan_visitor(node, accumulator):
    if node.values:
        # print(node)
        offset = node.values[0]
        pid = node.values[2]
        state = node.values[4]
        name, display_name = node.values[6:8]

        pid = -1 if type(pid) == volatility3.framework.renderers.NotApplicableValue else int(pid)

        svc_data = {
            "ServiceName": name,
            "DisplayName": display_name,
            "DriverName": '',
            "State": state,
            "Pid": pid,
        }
        accumulator.append(svc_data)
        # breakpoint()
    return accumulator

def driverscan_visitor(node, accumulator):
    if node.values:
        offset, start = node.values[:2]
        servicekey = node.values[3]
        name = node.values[-1]
        drv_data = {
            "servicekey": servicekey,
            "name": str(name),
        }
        accumulator.append(drv_data)
        # breakpoint()
    return accumulator


def get_pslist(available_automagics, socket_path):
    """List all the tasks that aren't hidden, unlinked, etc"""
    config_path = "plugins.PsList"
    automagics = automagic.choose_automagic(available_automagics, pslist.PsList)
    # breakpoint()
    # constructed = plugins.construct_plugin(ctx, automagics, pslist.PsList, config_path, progress_callback=None, open_method=lambda filename: UnixSocketFileHandler(socket_path, filename))
    constructed = plugins.construct_plugin(ctx, automagics, pslist.PsList, config_path, progress_callback=None, open_method=None)
    # breakpoint()
    treegrid = constructed.run()
    pslist_data = []
    treegrid.visit(node=None, function=pslist_visitor, initial_accumulator=pslist_data)
    return pslist_data
    # text_renderer.PrettyTextRenderer().render(treegrid)

def get_psscan():
    """List all the tasks including hidden, unlinked, etc"""
    config_path = "plugins.PsScan"
    automagics = automagic.choose_automagic(available_automagics, psscan.PsScan)
    constructed = plugins.construct_plugin(ctx, automagics, psscan.PsScan, config_path, progress_callback=None, open_method=None)
    treegrid = constructed.run()
    psscan_data = []
    treegrid.visit(node=None, function=pslist_visitor, initial_accumulator=psscan_data)
    return psscan_data
    # text_renderer.PrettyTextRenderer().render(treegrid)

def get_svcscan(available_automagics):
    """List all of the system services"""
    config_path = "plugins.SvcScan"
    automagics = automagic.choose_automagic(available_automagics, svcscan.SvcScan)
    constructed = plugins.construct_plugin(ctx, automagics, svcscan.SvcScan, config_path, progress_callback=None, open_method=None)
    treegrid = constructed.run()
    svcscan_data = []
    treegrid.visit(node=None, function=svcscan_visitor, initial_accumulator=svcscan_data)
    driverscan_data = get_driverscan(available_automagics)

    for svc in svcscan_data:
        for drv in driverscan_data:
            if svc["ServiceName"] == drv["servicekey"]:
                svc["DriverName"] = drv["name"]
    return svcscan_data


def get_driverscan(available_automagics):
    from volatility3.plugins.windows import driverscan # Imported here because circular import error when at top of file
    config_path = "plugins.DriverScan"
    automagics = automagic.choose_automagic(available_automagics, driverscan.DriverScan)
    constructed = plugins.construct_plugin(ctx, automagics, driverscan.DriverScan, config_path, progress_callback=None, open_method=None)
    treegrid = constructed.run()
    driverscan_data = []
    treegrid.visit(node=None, function=driverscan_visitor, initial_accumulator=driverscan_data)
    return driverscan_data


def get_sockets(available_automagics):
    """List all of the sockets that have not been unlinked or hidden"""

    config_path = "plugins.NetScan"
    automagics = automagic.choose_automagic(available_automagics, netscan.NetScan)
    # breakpoint()
    constructed = plugins.construct_plugin(ctx, automagics, netscan.NetScan, config_path, progress_callback=None, open_method=None)
    treegrid = constructed.run()
    socket_data = []
    treegrid.visit(node=None, function=socket_visitor, initial_accumulator=socket_data)
    return socket_data


def run(location):
    """Returns a list of the processes as a JSON string

    This analysis demonstrates that volatility can be successfully
    invoked and that data can be serialized as JSON data and
    returned to the plugin.

    """
    # print("Volatility version: %r" % volatility3.framework.constants.VERSION)
    ctx.config["automagic.LayerStacker.single_location"] = location
    available_automagics = automagic.available(ctx)
    # socket_path = location[6:]
    # breakpoint()
    # unix_socket_handler = UnixSocketFileHandler(socket_path, location[12:])
    # unix_socket_handler.open()
    # breakpoint()
    try:
        # with open(filterfile, "rb") as fobj:
        #     filter_data = json.load(fobj)

        analysis_results = {
            "pslist": get_pslist(available_automagics, location),
            "svcscan": get_svcscan(available_automagics),
            "sockets": get_sockets(available_automagics),
            # "process_hashes": get_process_hashes(filter_data),
            # "memory_hashes": get_memory_hashes(filter_data),
        }
    except Exception as err:
        analysis_results = {"error": traceback.format_exc(err)}

    json_str = json.dumps(analysis_results, indent=1)
    return json_str

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Test analysis")
    parser.add_argument("--location", default="file:mymem.dd")
    args = parser.parse_args()
    print(run(args.location))


### Must end with this comment