import sys, os
from service import *
import distorm3
import yara
import platform
import libapi
from win32api import GetFileVersionInfo, LOWORD, HIWORD

# Author: Jamie Levy <jamie.levy@gmail.com>
#
# memtriage
# 
#  pyinstaller --upx-dir=upx391w --onefile pyinstaller.spec
#
#   This program is free software; you can redistribute it and/or
#   modify it under the terms of the GNU General Public License
#   as published by the Free Software Foundation; version #2

plugin_cols = {
    "yarascan":{"cols":["Rule", "Owner", "Address", "Data"], "options": ["YARA_RULES", "YARA_FILE", "KERNEL", "OFFSET", "PID", "NAME", "ALL", "CASE", "WIDE", "SIZE", "REVERSE"]},
    "dlllist":{"cols": ["Pid", "Base", "Size", "LoadCount", "LoadTime", "Path"], "options": ["PID", "OFFSET", "NAME"]},
    "pslist":{"cols": ["Offset(V)", "Name", "PID", "PPID", "Thds", "Hnds", "Sess", "Wow64", "Start", "Exit"], "options": ["PID", "OFFSET", "NAME", "PHYSICAL_OFFSET"]},
    "handles":{"cols": ["Offset(V)", "Pid", "Handle", "Access", "Type", "Details"], "options": ["PID", "OFFSET", "NAME", "PHYSICAL_OFFSET"]},
    "modules":{"cols": ["Offset(V)", "Name", "Base", "Size", "File"], "options": ["PHYSICAL_OFFSET"]},
    "malfind":{"cols": ["Process", "Pid", "Address", "VadTag", "Protection", "Flags", "Data"], "options": ["PID", "OFFSET"]},
    "driverirp":{"cols": ["Offset(P)", "Pointers", "Handles", "Start", "Size", "Service Key", "Name", "Driver Name"], "options": ["REGEX"]},
    "psxview":{"cols": ["Offset(P)", "Name", "PID", "pslist", "psscan", "thrdproc", "pspcid", "csrss", "session", "deskthrd", "ExitTime"],"options": []},
    "privs":{"cols": ["Pid", "Process", "Value", "Privilege", "Attributes", "Description"], "options": ["PID", "OFFSET", "REGEX"]},
    "svcscan":{"cols": ["Offset", "Order", "Start", "PID", "ServiceName", "DisplayName", "ServiceType", "State", "BinaryPath"], "options": []},
    "getsids":{"cols": ["PID", "Process", "SID", "Name"], "options": ["PID", "OFFSET", "NAME"]},
    "vadinfo":{"cols": ["Pid", "VADNodeAddress", "Start", "End", "Tag", "Flags", "Protection", "VadType", "ControlArea", "Segment", "NumberOfSectionReferences", "NumberOfPfnReferences", "NumberOfMappedViews", "NumberOfUserReferences", "Control Flags", "FileObject", "FileNameWithDevice", "FirstPrototypePte", "LastContiguousPte", "Flags2"], "options": ["PID", "OFFSET", "NAME"]},
    "ldrmodules":{"cols": ["Pid", "Process", "Base", "InLoad", "InInit", "InMem", "MappedPath"], "options": ["PID", "OFFSET", "NAME"]},
    "netscan":{"cols": ["Offset(P)", "Proto", "LocalAddr", "ForeignAddr", "State", "PID", "Owner", "Created"], "options": []},
    "cmdline":{"cols": ["Process", "PID", "CommandLine"], "options": ["PID", "OFFSET", "NAME"]},
    "envars":{"cols": ["Pid", "Process", "Block", "Variable", "Value"], "options": ["PID", "OFFSET", "NAME"]},
    "verinfo":{"cols": ["Module", "FileVersion", "ProductVersion", "Flags", "OS", "FileType", "FileDate", "InfoString"], "options": ["IGNORE_CASE", "OFFSET", "REGEX"]},
    "atoms":{"cols": ["Offset(V)", "Session", "WindowStation", "Atom", "RefCount", "HIndex", "Pinned", "Name"], "options": []},
    "shimcachemem":{"cols": ["Order", "Last Modified", "Last Update", "Exec Flag", "File Size", "File Path"], "options": []},
    "apihooks":{"cols": ["HookMode", "HookType", "Process", "PID", "VictimModule", "VictimModBase", "VictimModSize", "Function", "HookAddress", "HookingModule", "DataAddress", "Data"], "options": ["PID", "OFFSET", "NAME"]},
    "volshell":{"cols": [], "options":[]},
    "dlldump":{"cols": ["Process(V)", "Name", "Module Base", "Module Name", "Result"], "options": ["PID", "BASE", "MEMORY", "OFFSET"]},
    "procdump":{"cols": ["Process(V)", "ImageBase", "Name", "Result"],"options": ["PID", "BASE", "MEMORY", "OFFSET"]},
    "vaddump":{"cols": ["Pid", "VADNodeAddress", "Start", "End", "Tag", "Flags", "Protection", "VadType", "ControlArea", "Segment", "NumberOfSectionReferences", "NumberOfPfnReferences", "NumberOfMappedViews", "NumberOfUserReferences", "Control Flags", "FileObject", "FileNameWithDevice", "FirstPrototypePte", "LastContiguousPte", "Flags2"], "options": ["PID", "BASE", "MEMORY", "OFFSET"]},
    "moddump":{"cols": ["Module Base", "Module Name", "Result"], "options": ["BASE", "MEMORY"]},
    "dumpfiles":{"cols":["Source", "Address", "PID", "Name", "OutputPath", "Data"], "options":["PHYSOFFSET", "PID", "OFFSET", "REGEX", "IGNORE_CASE", "KEEPNAME"]},
}

dumpers = ["dlldump", "procdump", "vaddump", "moddump", "dumpfiles", "malfind", "yarascan"]

all_options = ["BASE", "MEMORY", "REGEX", "PID", "OFFSET", "NAME", "PHYSOFFSET", "PHYSICAL_OFFSET", "IGNORE_CASE", "DUMP_DIR", "YARA_FILE", "KERNEL", "ALL", "CASE", "WIDE", "SIZE", "REVERSE"]

outputs = ["text", "json", "csv"]

WindowsVersionsX86 = {
    "5.1.2600.2180":"WinXPSP2x86",
    "5.1.2600.5512":"WinXPSP3x86",
    "5.2.3790.0":"Win2003SP0x86",
    "5.2.3790.1830":"Win2003SP1x86",
    "5.2.3790.3959":"Win2003SP2x86",
    "6.0.6000.16386":"VistaSP0x86",
    "6.0.6001.18000":"VistaSP1x86",
    "6.0.6002.18005":"VistaSP2x86",
    "6.1.7600.16385":"Win7SP0x86",
    "6.1.7601.17514":"Win7SP1x86",
    "6.1.7601.23418":"Win7SP1x86_23418",
    "6.1.7601.24000":"Win7SP1x86_24000",
    "6.2.9200.16384":"Win8SP0x86",
    "6.3.9600.16384":"Win8SP1x86",
    "6.3.9600.17031":"Win81U1x86",
    "10.0.10240.16384":"Win10x86",
    "10.0.10586.420":"Win10x86_10586",
    "10.0.14393.0":"Win10x86_14393",
    "10.0.15063.0":"Win10x86_15063",
    "10.0.15063.608":"Win10x64_15063",
    "10.0.16299.15":"Win10x86_16299",
    "10.0.10240.17770":"Win10x86_10240_17770",
    "10.0.17134.1":"Win10x86_17134",
    "10.0.17763.0":"Win10x86_17763",
    "10.0.18362.0":"Win10x86_18362",
    "10.0.18362.1":"Win10x86_18362",
}

WindowsVersionsX64 = { 
    "5.1.2600.2180":"WinXPSP2x64",
    "5.1.2600.5512":"WinXPSP3x64",
    "5.2.3790.0":"Win2003SP0x64",
    "5.2.3790.1830":"Win2003SP1x64",
    "5.2.3790.3959":"Win2003SP2x64",
    "6.0.6000.16386":"VistaSP0x64",
    "6.0.6001.18000":"VistaSP1x64",
    "6.0.6002.18005":"VistaSP2x64",
    "6.1.7600.16385":"Win7SP0x64",
    "6.1.7601.17514":"Win7SP1x64",
    "6.1.7601.23418":"Win7SP1x64_23418",
    "6.1.7601.24000":"Win7SP1x64_24000",
    "6.2.9200.16384":"Win8SP0x64",
    "6.3.9600.16384":"Win8SP1x64",
    "6.3.9600.17031":"Win81U1x64",
    "6.3.9600.17581":"Win81U1x64",
    "6.3.9600.18340":"Win8SP1x64_18340",
    "10.0.10240.16384":"Win10x64",
    "10.0.10586.306":"Win10x64_10586",
    "10.0.14393.0":"Win10x64_14393",
    "10.0.15063.0":"Win10x64_15063",
    "10.0.15063.608":"Win10x64_15063",
    "10.0.14393.479":"Win10x64_14393",
    "10.0.16299.0":"Win10x64_16299",
    "10.0.10240.17770":"Win10x64_10240_17770",
    "10.0.17134.1":"Win10x64_17134",
    "10.0.17763.0":"Win10x64_17763",
    "10.0.18362.0":"Win10x64_18362",
    "10.0.18362.1":"Win10x64_18362",
}

def get_hostname():
    import socket
    return socket.gethostname()

def service_running(service):
    try:
        return win32serviceutil.QueryServiceStatus(service, get_hostname())[1] == 4
    except:
        return False

def get_version_number(filename):
    #modified from
    # https://stackoverflow.com/questions/580924/python-windows-file-version-attribute
    try:
        info = GetFileVersionInfo (filename, "\\")
        ms = info['FileVersionMS']
        ls = info['FileVersionLS']
        return "{0}.{1}.{2}.{3}".format(HIWORD (ms), LOWORD (ms), HIWORD (ls), LOWORD (ls))
    except:
        return "0.0.0.0"

def first_try_brute_force(debugg = False, version = None):
    if version == None:
        if debugg:
            print "No version given"
        return "UNKNOWN"

    if debugg:
        print "Version: {}".format(version)
        print "Short version: {}".format(".".join(version.split(".")[:-1]))
    if platform.machine() == "AMD64":
        for i in WindowsVersionsX64:
            if i.find(".".join(version.split(".")[:-1])) != -1:
                if debugg:
                    print "Returning profile: {}".format(WindowsVersionsX64[i])
                return WindowsVersionsX64[i]
    else:
        for i in WindowsVersionsX86:
            if i.find(".".join(version.split(".")[:-1])) != -1:
                if debugg:
                    print "Returning profile: {}".format(WindowsVersionsX86[i])
                return WindowsVersionsX86[i]
    return "UNKNOWN"

def brute_force_profile(version = None):
    profile = ""
    sp = "SP1"
    bits = ""
    if platform.machine() == "AMD64":
        bits = "x64"
        if version != None:
            temp = version.split(".")
            temp = temp[:-1]
            for i in WindowsVersionsX64:
                temp2 = i.split(".")
                temp2 = temp2[:-1]
                if temp2 == temp:
                    return WindowsVersionsX64[i] 
    else:
        bits = "x86"
        if version != None:
            temp = version.split(".")
            temp = temp[:-1]
            for i in WindowsVersionsX86:
                temp2 = i.split(".")
                temp2 = temp2[:-1]
                if temp2 == temp:
                    return WindowsVersionsX86[i]
    if platform.platform().find("SP") != -1:
        sp = platform.platform().split("-")[-1]
    if platform.release() == "Vista" or platform.release() == "2008":
        profile = "VistaSP2"
        if sp:
            profile = "Vista" + sp
    else:
        if platform.release() == "XP":
            sp = "SP3"
        elif platform.release() == "2003":
            sp = "SP2"
        else:
            sp = "SP1"
        profile = "Win" + platform.release() + sp
    profile = profile + bits
    return profile


def list_plugins():
    plugins = ""
    for p in sorted(plugin_cols):
        plugins += "\t\t{0}\n".format(p)
    return plugins


def setup(driver, service_name, pmem_service, debug_enabled = False):
    destroyer = threading.Thread(target=destroy, args=(driver, service_name, debug_enabled))
    destroyer.start()
    destroyer.join()
    try:
        pmem_service.create()
    except:
        debug.debug("Unable to ceate service {0}".format(service_name))
    try:
        pmem_service.stop()
    except:
        debug.debug("Unable to stop service {0}".format(service_name))

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

def printinfo(data, item):
    index = data['columns'].index(item)
    for row in data['rows']:
        print row[index]

def printinfos(data, out, items =[], output = "text"):
    indeces = []
    if output == "json":
        out.write("{0}\n\n".format(data))
        return
    for item in items:
        indeces.append(data['columns'].index(item))
    if output == "csv":
        out.write(",".join(items))
        out.write("\n")
    else:
        out.write("\t".join(items))
        out.write("\n")
    for row in data['rows']:
        therow = ""
        for index in indeces:
            if output == "csv":
                therow += "{0},".format(row[index])
            else:
                therow += "{0}\t".format(row[index])
        out.write("{0}\n".format(therow.rstrip(",").strip()))

def printinfos_line(data, out = None, items = []):
    indeces = []
    for item in items:
        indeces.append(data['columns'].index(item))
    for row in data['rows']:
        for index in indeces:
            if out:
                out.write(row[index])
            else:
                print row[index]

def getinfos(data, items = []):
    indeces = []
    datas = []
    for item in items:
        indeces.append(data['columns'].index(item))
    for row in data['rows']:
        therow = []
        for index in indeces:
            therow.append(row[index])
        datas.append(therow)
    return datas

def parse_yarascan_data(data, out, output = "text"):
    import volatility.plugins.malware.malfind as malfind
    import volatility.utils as utils
    datas = getinfos(data, plugin_cols["yarascan"]["cols"])
    if output == "json":
        out.write("{}\n\n".format(datas))
        return
    elif output == "text":
        mode = "32bit"
        if platform.machine() == "AMD64":
            mode = "64bit"
        for rule, owner, addr, content in datas:
            out.write("Rule: {0}\n".format(rule))
            if owner == None:
                out.write("Owner: (Unknown Kernel Memory)\n")
            else:
                out.write("Owner: {0}\n".format(owner))
            out.write("Hexdump:\n")
            out.write("".join(
                ["{0:#010x}  {1:<48}  {2}\n".format(addr, h, ''.join(c))
                for offset, h, c in utils.Hexdump(content.decode("hex"))
                ]))
            out.write("\n\nDisassembly:\n")
            out.write("\n".join(
                    ["{0:#x} {1:<16} {2}".format(o, h, i)
                    for o, i, h in malfind.Disassemble(content.decode("hex"), int(addr), mode)
                    ]))
            out.write("\n\n")
    else:
        out.write("{0},{1},{2},{3}\n".format("Rule", "Owner", "Address", "Data"))
        for rule, owner, addr, content in datas:
            out.write("{0},{1},{2},{3}\n".format(rule, owner, addr, content))
        out.write("\n\n")
    out.write("\n\n")

def parse_malfind_data(data, out, output = "text"):
    import volatility.plugins.malware.malfind as malfind
    import volatility.utils as utils
    datas = getinfos(data, plugin_cols["malfind"]["cols"])
    if output == "json":
        out.write("{}\n\n".format(datas))
        return
    elif output == "text":
        mode = "32bit"
        if platform.machine() == "AMD64":
            mode = "64bit"
        for proc, pid, address, vadtag, protection, flags, data in datas:
            out.write("Process: {}, Pid: {}\n".format(proc, pid))
            out.write("VadTag: {}, Protection: {}, Flags: {}\n\n".format(vadtag, protection, flags))
            out.write("Raw data at address {0:#x}: {1}\n\n".format(address, data))
            out.write("Disassembly:\n")
            out.write("\n".join(
                    ["{0:#x} {1:<16} {2}".format(o, h, i)
                    for o, i, h in malfind.Disassemble(data.decode("hex"), int(address), mode)
                    ]))
            out.write("\n\nHexdump:\n")
            out.write("{0}\n".format("\n".join(
                    ["{0:#010x}  {1:<48}  {2}".format(int(address) + o, h, ''.join(c))
                    for o, h, c in utils.Hexdump(data.decode("hex"))
                    ])))
            out.write("\n\n")
    else:
        out.write("{},{},{},{},{},{},{}\n").format(
            "Process", "Pid", "Address", "VadTag", "Protection", "Flags", "Data")
        for proc, pid, address, vadtag, protection, flags, data in datas:
            out.write("{},{},{},{},{},{},{}\n".format(proc, pid, address, vadtag, protection, flags, data))
        out.write("\n\n")
    out.write("\n\n")

class Configs:
    def __init__(self, path = "\\\\.\\pmem", profile = "Win10x64_18362", kdbg = None, debug_enabled = False):
        self.config = libapi.get_config(profile, path)

        if debug_enabled:
            print "Config created with Profile: {0} and Path: {1}".format(profile, path)
        if kdbg:
            self.kdbg = kdbg
            if debug_enabled:
                print "KDBG:", hex(kdbg.v())
        else:
            self.kdbg = self.get_the_kdbg()
            if self.kdbg != None:
                if hasattr(self.kdbg, 'KdCopyDataBlock'):
                    self.kdbg = self.kdbg.KdCopyDataBlock
                else:
                    self.kdbg = self.kdbg.v()
                if debug_enabled:
                    print "KDBG:", hex(self.kdbg)
        self.config.KDBG = self.kdbg

    def gettext(self, plugin):
        return libapi.get_text(self.config, plugin)

    def getdata(self, plugin):
        if plugin == None:
            return None
        data = libapi.get_json(self.config, plugin)
        return data
    
    def get_the_kdbg(self):
        kdbg = libapi.get_the_kdbg(self.config, self.config.PROFILE)
        return kdbg

def get_parser():
    from argparse import ArgumentParser
    parser = ArgumentParser(description="Memtriage options:")
    parser.add_argument("--unload", help="Unload the driver and exit", action='store_true')
    parser.add_argument("--load", help="Load the driver and exit", action='store_true')
    parser.add_argument("--debug", help="Output debug messages while running", action='store_true')
    parser.add_argument("--service", help="Change the service name (default: pmem)", action = 'store')
    parser.add_argument("--output", help="Output type: json/text/csv", action = 'store')
    parser.add_argument("--dumpdir", help="Directory to dump files to (dlldump,procdump,moddump,vaddump,dumpfiles)", action = 'store')
    parser.add_argument("--base", help="Base of PE file to dump (dlldump,procdump,moddump)", action = 'store')
    parser.add_argument("--offset", help="Physical offset of process to act on (dlldump,procdump,moddump,vaddump,dumpfiles)", action = 'store')
    parser.add_argument("--memory", help="Carve as a memory sample rather than exe/disk (dlldump,procdump,moddump)", action = 'store')
    parser.add_argument("--pid", help="Operate on this process ID", action = 'store')
    parser.add_argument("--leave", help="Leave pmem service running with driver", action = 'store_true')
    parser.add_argument("--plugins", help="Comma delimited list of plugins to run: {0}".format(list_plugins()), action = 'store')
    parser.add_argument("--physoffset", help="Dump File Object at physical address PHYSOFFSET (dumpfiles)", action = 'store')
    parser.add_argument("--physical", help="Display the physical address of object (pslist,handles,modules)", action = 'store_true')
    parser.add_argument("--ignore", help="Ignore case in pattern match (dumpfiles,verinfo)", action = "store_true")
    parser.add_argument("--regex", help="Dump files matching REGEX (dumpfiles,driverirp,privs)", action = "store")
    parser.add_argument("--name", help="Name of process/object to operate on", action = "store")
    parser.add_argument("--keepname", help="Keep original file name (dumpfiles)", action = "store_true")
    parser.add_argument("--outfile", help="Combined output file (default: stdout)", action = "store")
    parser.add_argument("--yararules", help="Yara rule given on the commandline (yarascan)", action = "store")
    parser.add_argument("--yarafile", help="Yara rules given as a file (yarascan)", action = "store")
    parser.add_argument("--kernel", help="Scan kernel memory (yarascan)", action = "store_true")
    parser.add_argument("--all", help="Scan both process and kernel memory (yarascan)", action = "store_true")
    parser.add_argument("--case", help="Make the search case insensitive (yarascan)", action = "store_true")
    parser.add_argument("--wide", help="Match wide (unicode) strings (yarascan)", action = "store_true")
    parser.add_argument("--size", help="Size of preview hexdump in bytes (default: 256) (yarascan)", action = "store")
    parser.add_argument("--reverse", help="Reverse [REVERSE] number of bytes (default: 0) (yarascan)", action = "store")
    parser.add_argument("--kdbg", help="Manually select KDBG value", action = "store")
    return parser


def main():
    args = get_parser().parse_args()
    sys.argv = [sys.argv[0]]

    import volatility.plugins.taskmods as taskmods
    import volatility.plugins.malware.malfind as malfind
    import volatility.plugins.volshell as volshell
    import volatility.commands as commands
    import volatility.registry as registry
    import volatility.obj as obj

    import volatility.conf as conf
    import volatility.constants as constants
    import volatility.exceptions as exceptions
    import volatility.debug as debug
    import volatility.addrspace as addrspace
    import volatility.scan as scan
    try:
        debug.setup()
    except:
        pass

    service_name = "pmem"
    unload = args.unload
    load = args.load
    plugins = args.plugins
    output = "text"
    out = sys.stdout
    debugg = args.debug
    dump = args.dumpdir
    kdbg = args.kdbg

    if args.output:
        output = args.output
    if args.service:
        service_name = args.service
    if args.outfile:
        try:
            out = open(args.outfile, "wb")
        except:
            print "Unable to open file: {}\nUsing stdout".format(args.outfile)
            pass

    if not unload and not load and plugins == None:
        print "You must specify a plugin (or list of plugins) to run!"
        get_parser().print_help()
        out.close()
        return

    if plugins:
        plugins = plugins.split(",")
    profs = registry.get_plugin_classes(obj.Profile)
    if platform.system() != "Windows":
        print "cannot run on a non-Windows machine"
        out.close()
        return
    profile = "Win10x64_18362"
    version = get_version_number("ntdll.dll")
    if platform.machine() == "AMD64":
        driver = "winpmem_x64.sys"
        profile = WindowsVersionsX64.get(version, "UNKNOWN")
    else:
        driver = "winpmem_x86.sys"
        profile = WindowsVersionsX86.get(version, "UNKNOWN")
    if profile == "UNKNOWN":
        profile = first_try_brute_force(debugg, version)
        if profile == "UNKNOWN":
            profile = brute_force_profile(version)

    if profile not in profs:
        if debugg:
            print "Incorrect profile found: {0}, version: {1}".format(profile, version)
        profile = "Win10x64_18362"
        if debugg:
            print "Trying profile", profile
    if debugg:
        print "Suggested profile: {0}".format(profile)

    driver = resource_path(driver)
    if not service_name or not os.access(driver, os.R_OK):
        out.write("Make sure the driver is in place: {0}".format(driver))
        sys.exit(-1)
    
    pmem_service = Service(driver = driver, service = service_name, debug = debugg)


    if not service_running(service_name):
        setup(driver, service_name, pmem_service, debugg)
        try:
            pmem_service.start()
        except:
            print "Unable to start winpmem service"
            out.close()
            return

    if unload:
        setup(driver, service_name, pmem_service, debugg)
        out.close()
        return

    if load:
        return

    myconfigs = Configs(path = "\\\\.\\" + service_name, kdbg = kdbg, profile = profile, debug_enabled = debugg)
    if myconfigs.config.KDBG == None:
        print "Unable to find valid KDBG value... quitting"
        if not load:
            setup(driver, service_name, pmem_service, debugg)
        out.close()
        return

    dovolshell = False
    cmds = registry.get_plugin_classes(commands.Command, lower = True)
    if dump:
        import errno
        if not os.path.isdir(dump):
            try:
                os.makedirs(dump)
            except OSError as e:
                if e.errno != errno.EEXIST:
                    print "Unable to create directory", dump
                    out.close()
                    return

    for p in plugins:
        items = plugin_cols.get(p.strip(), None)
        if items == None:
            print "Unable to process plugin", p
            continue
        cols = items["cols"]
        myconfigs.config.DUMP_DIR = None
        if p.strip() == "volshell":
            dovolshell = True
            continue
        if "YARA_RULES" not in items["options"]:
            myconfigs.config.YARA_RULES = None
        else:
            myconfigs.config.YARA_RULES = str(args.yararules)
        if "YARA_FILE" not in items["options"]:
            myconfigs.config.YARA_FILE = None
        else:
            myconfigs.config.YARA_FILE = args.yarafile
        if "KERNEL" not in items["options"]:
            myconfigs.config.KERNEL = None
        else:
            myconfigs.config.KERNEL = args.kernel
        if "ALL" not in items["options"]:
            myconfigs.config.ALL = None
        else:
            myconfigs.config.ALL = args.all
        if "CASE" not in items["options"]:
            myconfigs.config.CASE = None
        else:
            myconfigs.config.CASE = args.case
        if "WIDE" not in items["options"]:
            myconfigs.config.WIDE = None
        else:
            myconfigs.config.WIDE = args.case
        if "SIZE" not in items["options"]:
            myconfigs.config.SIZE = None
        elif not args.size:
            myconfigs.config.SIZE = 256
        else:
            try:
                myconfigs.config.SIZE = int(args.size)
            except ValueError:
                try:
                    myconfigs.config.SIZE = int(args.size, 16)
                except TypeError:
                    myconfigs.config.SIZE = None
        if "REVERSE" not in items["options"]:
            myconfigs.config.REVERSE = None
        elif not args.reverse:
            myconfigs.config.REVERSE = 0
        else:
            try:
                myconfigs.config.REVERSE = int(args.reverse)
            except ValueError:
                try:
                    myconfigs.config.REVERSE = int(args.reverse, 16)
                except TypeError:
                    myconfigs.config.REVERSE = None
        if "BASE" not in items["options"]:
            myconfigs.config.BASE = None
        else:
            myconfigs.config.BASE = args.base
        if "MEMORY" not in items["options"]:
            myconfigs.config.MEMORY = None
        else:
            myconfigs.config.MEMORY = args.memory
        if "REGEX" not in items["options"]:
            myconfigs.config.REGEX = None
        else:
            myconfigs.config.REGEX = args.regex
        if "PID" not in items["options"]:
            myconfigs.config.PID = None
        else:
            myconfigs.config.PID = args.pid
        if "OFFSET" not in items["options"]:
            myconfigs.config.OFFSET = None
        else:
            try:
                myconfigs.config.OFFSET = int(args.offset)
            except ValueError:
                try:
                    myconfigs.config.OFFSET = int(args.offset, 16)
                except:
                    print "Unable to use offset: {0}".format(args.offset)
            except TypeError:
                myconfigs.config.OFFSET = None
        if "NAME" not in items["options"]:
            myconfigs.config.NAME = None
        else:
            myconfigs.config.NAME = args.name
        if "KEEPNAME" not in items["options"]:
            myconfigs.config.NAME = None
        else:
            myconfigs.config.NAME = args.keepname
        if "PHYSOFFSET" not in items["options"]:
            myconfigs.config.PHYSOFFSET = None
        else:
            try:
                myconfigs.config.PHYSOFFSET = hex(int(args.physoffset))
            except:
                myconfigs.config.PHYSOFFSET = args.physoffset
        if "PHYSICAL_OFFSET" not in items["options"] or not args.physical:
            myconfigs.config.PHYSICAL_OFFSET = None
        else:
            myconfigs.config.PHYSICAL_OFFSET = args.physical
            cols[0] = cols[0].replace("V", "P")
        if "IGNORE_CASE" not in items["options"]:
            myconfigs.config.IGNORE_CASE = None
        else:
            myconfigs.config.IGNORE_CASE = args.ignore
        if p.strip() in dumpers and dump:
            myconfigs.config.DUMP_DIR = dump
        elif p.strip() in dumpers and not dump and p.strip() not in ["malfind", "yarascan"]:
            print "You must supply a dump directory (--dumpdir=DIRECTORY) to dump to"
            print "Skipping plugin", p
            continue
        myconfigs.config.parse_options()
        if p.strip() == "yarascan":
            if output == "text":
                out.write("{1}Plugin: {0}{1}\n".format(p.strip(), "*" * 20))
            parse_yarascan_data(myconfigs.getdata(malfind.YaraScan), out, output = output)
            if output == "text":
                out.write("{0}\n\n".format("*" * 60))
            else:
                out.write("\n\n")
            continue
        if p.strip() == "malfind":
            if output == "text":
                out.write("{1}Plugin: {0}{1}\n".format(p.strip(), "*" * 20))
            parse_malfind_data(myconfigs.getdata(malfind.Malfind), out, output = output)
            if output == "text":
                out.write("{0}\n\n".format("*" * 60))
            else:
                out.write("\n\n")
            continue
        data = myconfigs.getdata(cmds.get(p.strip(), None))
        if data == None:
            print "Plugin", p, "not found"
            continue
        if output == "text":
            out.write("{1}Plugin: {0}{1}\n".format(p.strip(), "*" * 20))
        printinfos(data, out, cols, output = output)
        if output == "text":
            out.write("{0}\n\n".format("*" * 60))
        else:
            out.write("\n\n")
    
    if dovolshell:
        for option in all_options:
            setattr(myconfigs.config, option, None)
        myconfigs.config.parse_options()
        myconfigs.gettext(volshell.volshell)
    if not args.leave:
        setup(driver, service_name, pmem_service, debugg)
    out.close()

if __name__ == "__main__":
    main()

