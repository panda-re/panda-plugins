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

def filter_invalid_ascii(strobj):
    return strobj.encode("utf-8", "replace")


def is_interesting(eprocess, filter_data):
    check_pid = int(eprocess.UniqueProcessId)
    check_asid = int(eprocess.Pcb.DirectoryTableBase)

    for (pid, tid, asid) in filter_data["thread_whitelist"]:
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


def get_process_hashes(available_automagics, filter_data):
    print("\n" + "="*60)
    print("[get_process_hashes] Starting")
    print("="*60)

    results = []
    try:
        config_path = "plugins.PEDump"
        ctx.config["plugins.PEDump.PEDump.base"] = 0x400000
        ctx.config["plugins.PEDump.PEDump.pid"] = [x[0] for x in filter_data['thread_whitelist']]
        # print(filter_data)
        cmd = CommandLine()
        cmd.output_dir = tempfile.mkdtemp()
        FileHandler = cmd.file_handler_class_factory()
        automagics = automagic.choose_automagic(available_automagics, pedump.PEDump)
        constructed = plugins.construct_plugin(ctx, automagics, pedump.PEDump, config_path, progress_callback=None, open_method=FileHandler)

        print(f"[get_process_hashes] Config after construct:")
        # breakpoint()
        # print(ctx.config)
        
        print("[get_process_hashes] Running plugin...")
        treegrid = constructed.run()
        proc_hash_data = []
        treegrid.visit(node=None, function=lambda node, acc: process_hashes_visitor(node, acc, cmd), initial_accumulator=proc_hash_data)
        
        print(f"[get_process_hashes] SUCCESS: Found {len(proc_hash_data)} processes")
        print("="*60 + "\n")

        return proc_hash_data
    
    except Exception as e:
        print(f"\n[get_process_hashes] EXCEPTION CAUGHT: {type(e).__name__}")
        print(f"[get_process_hashes] Error message: {str(e)}")
        
        # Try to extract unsatisfied requirements
        if hasattr(e, 'unsatisfied'):
            print(f"[get_process_hashes] Unsatisfied requirements:")
            for req in e.unsatisfied:
                # breakpoint()
                print(f"  - {req}")
        
        # Also check what's in the context
        print(f"[get_process_hashes] Context config keys:")
        for key in sorted(ctx.config.keys()):
            print(f"  - {key}: {ctx.config[key]}")
        
        print(f"[get_process_hashes] Context layers:")
        for layer_name in ctx.layers.keys():
            print(f"  - {layer_name}")
        
        print(f"[get_process_hashes] Context symbol tables:")
        for symbol in ctx.symbol_space.keys():
            print(f"  - {symbol}")
        
        print("\n" + traceback.format_exc())
        print("="*60 + "\n")

        return {"error": str(e), "traceback": traceback.format_exc()}

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

def vadinfo_visitor(node, accumulator):
    if node.values:
        startvpn, endvpn = node.values[3:5]
        fileoutput = node.values[-1]
        accumulator[(int(startvpn), int(endvpn))] = fileoutput
        # breakpoint()
    return accumulator

def get_memory_hashes(available_automagics, filter_data):
    print("\n" + "="*60)
    print("[get_memory_hashes] Starting")
    print("="*60)

    results = []
    try:
        config_path = "plugins.VadInfo"
        ctx.config["plugins.VadInfo.VadInfo.pid"] = [x[0] for x in filter_data['thread_whitelist']]
        ctx.config["plugins.VadInfo.VadInfo.dump"] = True
        # print(filter_data)
        cmd = CommandLine()
        cmd.output_dir = tempfile.mkdtemp()
        FileHandler = cmd.file_handler_class_factory()
        automagics = automagic.choose_automagic(available_automagics, vadinfo.VadInfo)
        constructed = plugins.construct_plugin(ctx, automagics, vadinfo.VadInfo, config_path, progress_callback=None, open_method=FileHandler)

        print(f"[get_memory_hashes] Config after construct:")
        # print(ctx.config)
        print("[get_memory_hashes] Running vadinfo plugin...")
        vadinfo_data = {}
        treegrid = constructed.run()
        treegrid.visit(node=None, function=lambda node, acc: vadinfo_visitor(node, acc), initial_accumulator=vadinfo_data)

        config_path = "plugins.VadWalk"
        ctx.config["plugins.VadWalk.VadWalk.pid"] = [x[0] for x in filter_data['thread_whitelist']]
        mem_hash_data = []
        automagics = automagic.choose_automagic(available_automagics, vadwalk.VadWalk)
        constructed = plugins.construct_plugin(ctx, automagics, vadwalk.VadWalk, config_path, progress_callback=None, open_method=None)

        print(f"[get_memory_hashes] Config after vadwalk construct:")
        # breakpoint()
        # print(ctx.config)
        
        print("[get_memory_hashes] Running vadwalk plugin...")
        treegrid = constructed.run()
        treegrid.visit(node=None, function=lambda node, acc: memory_hashes_visitor(node, acc, cmd, vadinfo_data), initial_accumulator=mem_hash_data)
        
        print(f"[get_memory_hashes] SUCCESS: Found {len(mem_hash_data)} processes")
        print("="*60 + "\n")

        return mem_hash_data
    
    except Exception as e:
        print(f"\n[get_memory_hashes] EXCEPTION CAUGHT: {type(e).__name__}")
        print(f"[get_memory_hashes] Error message: {str(e)}")
        
        
        print("\n" + traceback.format_exc())
        print("="*60 + "\n")

        return {"error": str(e), "traceback": traceback.format_exc()}


def memory_hashes_visitor(node, accumulator, cmd, vadinfo_data):
    if node.values:
        # print(vadinfo_data)
        start = int(node.values[-3])
        end = int(node.values[-2])
        result = {
            "pid": int(node.values[0]),
            "start": start,
            "end": end
        }
        # breakpoint()
        dumped_file = f"{cmd.output_dir}/{vadinfo_data[(start, end)]}"
        result.update(hash_file(dumped_file, hashlib.sha256()))
        accumulator.append(result)
    return accumulator


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

def pslist_visitor(node, accumulator, filter_data):
    if node.values:
        pid, ppid, img_name, offset = node.values[0:4]
        proc = ctx.object("symbol_table_name1!_EPROCESS", "layer_name", offset)
        if is_interesting(proc, filter_data):
            # breakpoint()
            result = {
                "pid": int(pid),
                "base": int(proc.get_peb().ImageBaseAddress)
            }
            # result.update(hash_file(, hashlib.sha256()))
        #     accumulator[1].append(result)
        # for dumps in os.listdir(cmd.output_dir):

        # breakpoint()
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


def get_pslist(available_automagics, filter_data):
    """List all the tasks that aren't hidden, unlinked, etc"""
    print("\n" + "="*60)
    print("[get_pslist] Starting")
    print("="*60)
    
    try:
        config_path = "plugins.PsList"
        
        print("[get_pslist] Choosing automagic...")
        # ctx.config[f"{config_path}.PsList.pid"] = [x[0] for x in filter_data['thread_whitelist']]
        # cmd = CommandLine()
        # cmd.output_dir = tempfile.mkdtemp()
        # FileHandler = cmd.file_handler_class_factory()

        automagics = automagic.choose_automagic(available_automagics, pslist.PsList)
        print(f"[get_pslist] Chosen {len(automagics)} automagics")
        print("[get_pslist] Constructing plugin...")
        constructed = plugins.construct_plugin(
            ctx, automagics, pslist.PsList, config_path, 
            progress_callback=None, open_method=None
        )
        
        print(f"[get_pslist] Config after construct:")
        # breakpoint()
        # print(ctx.config)
        
        print("[get_pslist] Running plugin...")
        treegrid = constructed.run()
        
        print("[get_pslist] Extracting data...")
        pslist_data = []
        treegrid.visit(node=None, function=lambda node, acc: pslist_visitor(node, acc, filter_data), initial_accumulator=pslist_data)
        # breakpoint()
        print(f"[get_pslist] SUCCESS: Found {len(pslist_data)} processes")
        print("="*60 + "\n")
        LinearlyMappedLayer.read.cache_clear()
        return pslist_data
        
    except Exception as e:
        print(f"\n[get_pslist] EXCEPTION CAUGHT: {type(e).__name__}")
        print(f"[get_pslist] Error message: {str(e)}")
        
        # Try to extract unsatisfied requirements
        if hasattr(e, 'unsatisfied'):
            print(f"[get_pslist] Unsatisfied requirements:")
            for req in e.unsatisfied:
                # breakpoint()
                print(f"  - {req}")
        
        # Also check what's in the context
        print(f"[get_pslist] Context config keys:")
        for key in sorted(ctx.config.keys()):
            print(f"  - {key}: {ctx.config[key]}")
        
        print(f"[get_pslist] Context layers:")
        for layer_name in ctx.layers.keys():
            print(f"  - {layer_name}")
        
        print(f"[get_pslist] Context symbol tables:")
        for symbol in ctx.symbol_space.keys():
            print(f"  - {symbol}")
        
        print("\n" + traceback.format_exc())
        print("="*60 + "\n")
        
        return {"error": str(e), "traceback": traceback.format_exc()}


def get_svcscan(available_automagics):
    """List all of the system services"""
    print("\n" + "="*60)
    print("[get_svcscan] Starting")
    print("="*60)

    try:
        config_path = "plugins.SvcScan"
        print(f"[Location] {ctx.config['automagic.LayerStacker.single_location']}")

        print("[get_svcscan] Choosing automagic...")
        automagics = automagic.choose_automagic(available_automagics, svcscan.SvcScan)
        print(f"[get_svcscan] Chosen {len(automagics)} automagics")
        print("[get_svcscan] Constructing plugin...")
        constructed = plugins.construct_plugin(ctx, automagics, svcscan.SvcScan, config_path, progress_callback=None, open_method=None)
        print(f"[get_svcscan] Config after construct:")
        # print(ctx.config)

        print("[get_svcscan] Running plugin...")
        treegrid = constructed.run()

        print("[get_svcscan] Extracting data...")
        svcscan_data = []
        treegrid.visit(node=None, function=svcscan_visitor, initial_accumulator=svcscan_data)
        print(f"[get_svcscan] SUCCESS: Found {len(svcscan_data)} services")
        print("="*60 + "\n")

        driverscan_data = get_driverscan(available_automagics)

        for svc in svcscan_data:
            for drv in driverscan_data:
                if svc["ServiceName"] == drv["servicekey"]:
                    svc["DriverName"] = drv["name"]
        LinearlyMappedLayer.read.cache_clear()
        return svcscan_data
    except Exception as e:
        print(f"\n[get_svcscan] EXCEPTION CAUGHT: {type(e).__name__}")
        print(f"[get_svcscan] Error message: {str(e)}")
        
        # Try to extract unsatisfied requirements
        if hasattr(e, 'unsatisfied'):
            print(f"[get_svcscan] Unsatisfied requirements:")
            for req in e.unsatisfied:
                # breakpoint()
                print(f"  - {req}")
        
        # Also check what's in the context
        print(f"[get_svcscan] Context config keys:")
        for key in sorted(ctx.config.keys()):
            print(f"  - {key}: {ctx.config[key]}")
        
        print(f"[get_svcscan] Context layers:")
        for layer_name in ctx.layers.keys():
            print(f"  - {layer_name}")
        
        print(f"[get_svcscan] Context symbol tables:")
        for symbol in ctx.symbol_space.keys():
            print(f"  - {symbol}")
        
        print("\n" + traceback.format_exc())
        print("="*60 + "\n")
        LinearlyMappedLayer.read.cache_clear()
        return {"error": str(e), "traceback": traceback.format_exc()}


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


def run(filterfile):
    """Returns a list of the processes as a JSON string

    This analysis demonstrates that volatility can be successfully
    invoked and that data can be serialized as JSON data and
    returned to the plugin.

    """
    # print("Volatility version: %r" % volatility3.framework.constants.VERSION)
    # setup_panda_handler()

    # test_file_behavior()
    memory_file = "mem.ram"
    location = f"file:{memory_file}"
    config_path = "automagic.LayerStacker.single_location"
    ctx.config[config_path] = location

    # Build automagics
    print("Running automagic to build layers...")
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
    except Exception as e:
        print(f"ERROR: {e}")
        print(traceback.format_exc())
        print(dict(ctx.config))
        analysis_results = {"error": str(e),
            "error_type": type(e).__name__,
            "traceback": traceback.format_exc(e)
            }

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