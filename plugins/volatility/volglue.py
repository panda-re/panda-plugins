# This section sets up the volatility environment
# and is invoked by the plugin when it loads this
# script as a module

import os
import json
import logging
import shutil
import subprocess
import hashlib
import tempfile
import traceback

import urllib
from urllib.request import BaseHandler

import volatility3
from volatility3.cli import CommandLine, text_renderer
from volatility3.plugins.windows import pedump, psscan, pslist, svcscan, netscan, vadinfo, vadwalk
from volatility3.framework.interfaces.context import ModuleInterface, ModuleContainer
from volatility3.framework import automagic, contexts, interfaces, plugins
from volatility3.framework.layers.physical import FileLayer
from volatility3.framework.layers.linear import LinearlyMappedLayer

import socket
from typing import Optional
from pathlib import Path

# import pandamem

vollog = logging.getLogger(__name__)
DEBUG = False

ctx = contexts.Context()

class PandaFile(object):
    """
    Constructs a file that volatility can't ignore
    to back by PANDA physical memory
    """
    
    def __init__(self, length):
        self.pos = 0
        self.length = length
        self.closed = False
        self.mode = "rb"
        self.name = "/tmp/panda.panda"
        self.classname = type(self).__name__
        self.x86_32 = (length <= 0xffffffff)
    
    def readable(self):
        return self.closed
    
    def read(self, size=1):
        if self.x86_32:
            addr = self.pos & 0xfffffff
        else:
            addr = self.pos
        
        data = pandamem.read_physical(addr, size)
        # print(len(data))
        # breakpoint()
        # mem_buf.extend(data)
        
        if DEBUG:
            print(self.classname+": Reading " + str(size)+" bytes from "+hex(self.pos))
            
            # file_path = Path(f'/data/small_{hex(self.pos)}.dd')
            # if not file_path.exists():
            #     with open(file_path, 'wb') as f:
            #         f.write(data)
        
        self.pos += size
        return data
    
    def peek(self, size=1):
        return pandamem.read_physical(self.pos, size)
    
    def seek(self, pos, whence=0):
        if whence == 0:
            self.pos = pos
        elif whence == 1:
            self.pos += pos
        else:
            self.pos = self.length - pos
        if self.pos > self.length:
            print(self.classname+": We've gone off the deep end")
        if DEBUG:
            print(self.classname+" Seeking to address "+hex(self.pos))
    
    def tell(self):
        return self.pos
    
    def close(self):
        self.closed = True

class PandaFileHandler(BaseHandler):
    def default_open(self, req):
        if 'panda.panda' in req.full_url:
            length = pandamem.get_ram_size()
            
            if length > 0xc0000000:
                length += 0x40000000  # 3GB hole
            if DEBUG:
                print(type(self).__name__ + ": initializing PandaFile with length="+hex(length))
                # breakpoint()
            
            return PandaFile(length=length)
        
        return None
    
    def file_close(self):
        return True

def setup_panda_handler():
    """
    Register the panda:// URL handler with urllib.
    This allows Volatility to open "panda://memory" as if it were a file.
    """
    opener = urllib.request.build_opener(PandaFileHandler())
    urllib.request.install_opener(opener)
    vollog.info("[PandaFileHandler] Registered panda:// protocol handler")

def test_file_behavior():
    print(f"\n{'='*60}")
    print(f"Testing pandamem module...")
    print(f"{'='*60}")
    ram_size = pandamem.get_ram_size()
    print(f"Ram size: {ram_size}")
    # TEST 1: Can we read from address 0?
    print("TEST 1: Reading 16 bytes from address 0x0...")
    try:
        data = pandamem.read_physical(0, 16)
        print(f"  SUCCESS: {data.hex()}")
    except Exception as e:
        print(f"  FAILED: {e}")
        return json.dumps({"error": f"pandamem.read_physical failed: {e}"})
    
    # TEST 2: Can we read from address 0x1000 (typical page)?
    # print("TEST 2: Reading 4096 bytes from address 0x1000...")
    # try:
    #     data = pandamem.read_physical(0x1000, 4096)
    #     print(f"  SUCCESS: {data.hex()}")
    # except Exception as e:
    #     print(f"  FAILED: {e}")
    
    # TEST 3: Can we read a larger chunk?
    print("TEST 3: Reading 4096 bytes (one page)...")
    try:
        data = pandamem.read_physical(0, 4096)
        print(f"  SUCCESS: Read {len(data)} bytes")
    except Exception as e:
        print(f"  FAILED: {e}")
    print(f"{'='*60}\n")


def hash_file(filepath, *algorithms):
    with open(filepath, "rb") as fobj:
        while True:
            chunk = fobj.read(4096)
            if not chunk:
                break

            for a in algorithms:
                a.update(chunk)

    return {a.name: a.hexdigest().lower() for a in algorithms}


def get_process_hashes(available_automagics, filter_data):
    config_path = "plugins.PEDump"
    ctx.config["plugins.PEDump.PEDump.base"] = 0x400000
    ctx.config["plugins.PEDump.PEDump.pid"] = [x[0] for x in filter_data['thread_whitelist']]
    cmd = CommandLine()
    cmd.output_dir = tempfile.mkdtemp()
    FileHandler = cmd.file_handler_class_factory()
    automagics = automagic.choose_automagic(available_automagics, pedump.PEDump)
    constructed = plugins.construct_plugin(ctx, automagics, pedump.PEDump, config_path, progress_callback=None, open_method=FileHandler)

    treegrid = constructed.run()
    proc_hash_data = []
    treegrid.visit(node=None, function=lambda node, acc: process_hashes_visitor(node, acc, cmd), initial_accumulator=proc_hash_data)

    return proc_hash_data


def process_hashes_visitor(node, accumulator, cmd):
    if node.values:
        result = {
            "pid": int(node.values[0]),
            "base": ctx.config["plugins.PEDump.PEDump.base"],
        }
        dumped_file = f"{cmd.output_dir}/{node.values[2]}"
        result.update(hash_file(dumped_file, hashlib.sha256()))
        accumulator.append(result)
    return accumulator


def get_memory_hashes(available_automagics, filter_data):
    config_path = "plugins.VadInfo"
    ctx.config["plugins.VadInfo.VadInfo.pid"] = [x[0] for x in filter_data['thread_whitelist']]
    ctx.config["plugins.VadInfo.VadInfo.dump"] = True

    cmd = CommandLine()
    cmd.output_dir = tempfile.mkdtemp()
    FileHandler = cmd.file_handler_class_factory()
    automagics = automagic.choose_automagic(available_automagics, vadinfo.VadInfo)
    constructed = plugins.construct_plugin(ctx, automagics, vadinfo.VadInfo, config_path, progress_callback=None, open_method=FileHandler)

    vadinfo_data = {}
    treegrid = constructed.run()
    treegrid.visit(node=None, function=lambda node, acc: vadinfo_visitor(node, acc), initial_accumulator=vadinfo_data)

    config_path = "plugins.VadWalk"
    ctx.config["plugins.VadWalk.VadWalk.pid"] = [x[0] for x in filter_data['thread_whitelist']]
    mem_hash_data = []
    automagics = automagic.choose_automagic(available_automagics, vadwalk.VadWalk)
    constructed = plugins.construct_plugin(ctx, automagics, vadwalk.VadWalk, config_path, progress_callback=None, open_method=None)

    treegrid = constructed.run()
    treegrid.visit(node=None, function=lambda node, acc: memory_hashes_visitor(node, acc, cmd, vadinfo_data), initial_accumulator=mem_hash_data)

    return mem_hash_data


def vadinfo_visitor(node, accumulator):
    if node.values:
        startvpn, endvpn = node.values[3:5]
        fileoutput = node.values[-1]
        accumulator[(int(startvpn), int(endvpn))] = fileoutput
    return accumulator


def memory_hashes_visitor(node, accumulator, cmd, vadinfo_data):
    if node.values:
        start = int(node.values[-3])
        end = int(node.values[-2])
        result = {
            "pid": int(node.values[0]),
            "start": start,
            "end": end
        }
        dumped_file = f"{cmd.output_dir}/{vadinfo_data[(start, end)]}"
        result.update(hash_file(dumped_file, hashlib.sha256()))
        accumulator.append(result)
    return accumulator


def get_pslist(available_automagics, filter_data):
    """List all the tasks that aren't hidden, unlinked, etc"""
    
    config_path = "plugins.PsList"
    automagics = automagic.choose_automagic(available_automagics, pslist.PsList)
    constructed = plugins.construct_plugin(
        ctx, automagics, pslist.PsList, config_path, 
        progress_callback=None, open_method=None
    )
    
    treegrid = constructed.run()
    
    pslist_data = []
    treegrid.visit(node=None, function=lambda node, acc: pslist_visitor(node, acc, filter_data), initial_accumulator=pslist_data)
    return pslist_data
        

def pslist_visitor(node, accumulator, filter_data):
    if node.values:
        pid, ppid, img_name, offset = node.values[0:4]
        proc = ctx.object("symbol_table_name1!_EPROCESS", "layer_name", offset)
        pdata = {
            "pid": int(pid),
            "ppid": int(ppid),
            "asid": int(proc.Pcb.DirectoryTableBase),
            "ImagePathName": img_name,
        }
        accumulator.append(pdata)
    return accumulator


def get_svcscan(available_automagics):
    """List all of the system services"""

    config_path = "plugins.SvcScan"
    automagics = automagic.choose_automagic(available_automagics, svcscan.SvcScan)
    constructed = plugins.construct_plugin(ctx, automagics, svcscan.SvcScan, config_path, progress_callback=None, open_method=None)
    existing_hive_layer = next((layer_name for layer_name in ctx.layers.keys() if "hive" in layer_name), None)
    if existing_hive_layer:
        return

    treegrid = constructed.run()

    svcscan_data = []
    treegrid.visit(node=None, function=svcscan_visitor, initial_accumulator=svcscan_data)

    driverscan_data = get_driverscan(available_automagics)
    for svc in svcscan_data:
        for drv in driverscan_data:
            if svc["ServiceName"] == drv["servicekey"]:
                svc["DriverName"] = drv["name"]
    return svcscan_data


def svcscan_visitor(node, accumulator):
    if node.values:
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
    return accumulator


def get_driverscan(available_automagics):
    from volatility3.plugins.windows import driverscan # Imported here because circular import error when at top of file
    config_path = "plugins.DriverScan"
    automagics = automagic.choose_automagic(available_automagics, driverscan.DriverScan)
    constructed = plugins.construct_plugin(ctx, automagics, driverscan.DriverScan, config_path, progress_callback=None, open_method=None)
    treegrid = constructed.run()
    driverscan_data = []
    treegrid.visit(node=None, function=driverscan_visitor, initial_accumulator=driverscan_data)
    return driverscan_data

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
    return accumulator


def get_sockets(available_automagics):
    """List all of the sockets that have not been unlinked or hidden"""

    config_path = "plugins.NetScan"
    automagics = automagic.choose_automagic(available_automagics, netscan.NetScan)
    constructed = plugins.construct_plugin(ctx, automagics, netscan.NetScan, config_path, progress_callback=None, open_method=None)
    treegrid = constructed.run()
    socket_data = []
    treegrid.visit(node=None, function=socket_visitor, initial_accumulator=socket_data)
    return socket_data

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
        accumulator.append(sdata)
    return accumulator


def run(filterfile):
    """Returns a list of the processes as a JSON string

    This analysis demonstrates that volatility can be successfully
    invoked and that data can be serialized as JSON data and
    returned to the plugin.

    """

    memory_file = "mem.ram"
    location = f"file:{memory_file}"
    config_path = "automagic.LayerStacker.single_location"
    ctx.config[config_path] = location

    # Build automagics
    available_automagics = automagic.available(ctx)

    try:
        with open(filterfile, "rb") as fobj:
            filter_data = json.load(fobj)

        analysis_results = {
            "pslist": get_pslist(available_automagics, filter_data),
            "svcscan": get_svcscan(available_automagics),
            "sockets": get_sockets(available_automagics),
            "process_hashes": get_process_hashes(available_automagics, filter_data),
            "memory_hashes": get_memory_hashes(available_automagics, filter_data),
        }
    except Exception as err:
        analysis_results = {"error": traceback.format_exc(err)}

    json_str = json.dumps(analysis_results, indent=1)
    return json_str

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Test analysis")
    parser.add_argument("--location", default="file:mymem.dd")
    parser.add_argument("--filter", default="aprog-x64-tracefilter.json")
    args = parser.parse_args()
    print(run(args.filter))


### Must end with this comment