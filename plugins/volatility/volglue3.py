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

import urllib
from urllib.request import BaseHandler

import volatility3
from volatility3.cli import text_renderer
from volatility3.plugins.windows import pedump, psscan, pslist, svcscan, netscan, vadinfo
from volatility3.framework.interfaces.context import ModuleInterface, ModuleContainer
from volatility3.framework import automagic, contexts, interfaces, plugins
from volatility3.framework.layers.physical import FileLayer

import socket
from typing import Optional
from pathlib import Path

import pandamem

vollog = logging.getLogger(__name__)
DEBUG = True

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
        
        if DEBUG:
            print(self.classname+": Reading " + str(size)+" bytes from "+hex(self.pos))
            
            file_path = Path(f'/data/small_{hex(self.pos)}.dd')
            if not file_path.exists():
                with open(file_path, 'wb') as f:
                    f.write(data)
        
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
        if 'panda://' in req.full_url or 'panda.panda' in req.full_url:
            length = pandamem.get_ram_size()
            
            if length > 0xc0000000:
                length += 0x40000000  # 3GB hole
            if DEBUG:
                print(type(self).__name__ + ": initializing PandaFile with length="+hex(length))
            
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
    config_path = "plugins.PEDump"
    # dump = pedump.PEDump(ctx, config_path, file_name=args.location)
    # breakpoint()
    automagics = automagic.choose_automagic(available_automagics, pedump.PEDump, base=0)
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


def get_pslist(available_automagics):
    """List all the tasks that aren't hidden, unlinked, etc"""
    print("\n" + "="*60)
    print("[get_pslist] Starting")
    print("="*60)
    
    try:
        config_path = "plugins.PsList"
        
        print("[get_pslist] Choosing automagic...")
        automagics = automagic.choose_automagic(available_automagics, pslist.PsList)
        print(f"[get_pslist] Chosen {len(automagics)} automagics")
        print("[get_pslist] Constructing plugin...")
        constructed = plugins.construct_plugin(
            ctx, automagics, pslist.PsList, config_path, 
            progress_callback=None, open_method=None
        )
        
        print(f"[get_pslist] Config after construct:")
        # breakpoint()
        print(ctx.config)
        
        print("[get_pslist] Running plugin...")
        treegrid = constructed.run()
        
        print("[get_pslist] Extracting data...")
        pslist_data = []
        treegrid.visit(node=None, function=pslist_visitor, initial_accumulator=pslist_data)
        
        print(f"[get_pslist] SUCCESS: Found {len(pslist_data)} processes")
        print("="*60 + "\n")
        
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
    print("\n" + "="*60)
    print("[get_svcscan] Starting")
    print("="*60)

    try:
        config_path = "plugins.SvcScan"

        print("[get_svcscan] Choosing automagic...")
        automagics = automagic.choose_automagic(available_automagics, svcscan.SvcScan)
        print(f"[get_svcscan] Chosen {len(automagics)} automagics")
        print("[get_svcscan] Constructing plugin...")
        constructed = plugins.construct_plugin(ctx, automagics, svcscan.SvcScan, config_path, progress_callback=None, open_method=None)
        print(f"[get_svcscan] Config after construct:")
        print(ctx.config)

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


def run(location):
    """Returns a list of the processes as a JSON string

    This analysis demonstrates that volatility can be successfully
    invoked and that data can be serialized as JSON data and
    returned to the plugin.

    """
    # print("Volatility version: %r" % volatility3.framework.constants.VERSION)
    setup_panda_handler()

    # test_file_behavior()

    location = "file:/tmp/panda.panda"
    config_path = "automagic.LayerStacker.single_location"
    ctx.config[config_path] = location
    # breakpoint()
    # Build automagics
    print("Running automagic to build layers...")
    available_automagics = automagic.available(ctx)

    try:
        # with open(filterfile, "rb") as fobj:
        #     filter_data = json.load(fobj)

        analysis_results = {
            "pslist": get_pslist(available_automagics),
            "svcscan": get_svcscan(available_automagics),
            "sockets": get_sockets(available_automagics),
            # "process_hashes": get_process_hashes(available_automagics, filter_data),
            # "memory_hashes": get_memory_hashes(filter_data),
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
    args = parser.parse_args()
    print(run(args.location))


### Must end with this comment