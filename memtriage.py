from service import *
import distorm3
import yara
import platform
import getopt
import sys, os
import volatility.plugins.taskmods as taskmods 
import volatility.plugins.malware.malfind as malfind
import volatility.plugins.volshell as volshell
import volatility.commands as commands
import volatility.registry as registry
import volatility.obj as obj
import libapi 
from win32api import GetFileVersionInfo, LOWORD, HIWORD

import volatility.conf as conf
import volatility.constants as constants
import volatility.exceptions as exceptions
import volatility.debug as debug
import volatility.addrspace as addrspace
import volatility.scan as scan


# Author: Jamie Levy <jamie.levy@gmail.com>
#
# memtriage
#
#  pyinstaller --upx-dir=upx391w --onefile pyinstaller.spec
#
#   This program is free software; you can redistribute it and/or
#   modify it under the terms of the GNU General Public License
#   as published by the Free Software Foundation; version #2

plugin_rows = {
    "dlllist":["Pid", "Base", "Size", "LoadCount", "LoadTime", "Path"],
    "pslist":["Offset(V)", "Name", "PID", "PPID", "Thds", "Hnds", "Sess", "Wow64", "Start", "Exit"],
    "handles":["Offset(V)", "Pid", "Handle", "Access", "Type", "Details"],
    "modules":["Offset(V)", "Name", "Base", "Size", "File"],
    "malfind":["Process", "Address", "Data"],
    "driverirp":["Offset(P)", "Pointers", "Handles", "Start", "Size", "Service Key", "Name", "Driver Name"],
    "psxview":["Offset(P)", "Name", "PID", "pslist", "psscan", "thrdproc", "pspcid", "csrss", "session", "deskthrd", "ExitTime"],
    "privs":["Pid", "Process", "Value", "Privilege", "Attributes", "Description"],
    "svcscan":["Offset", "Order", "Start", "PID", "ServiceName", "DisplayName", "ServiceType", "State", "BinaryPath"],
    "getsids":["PID", "Process", "SID", "Name"],
    "vadinfo":["Pid", "VADNodeAddress", "Start", "End", "Tag", "Flags", "Protection", "VadType", "ControlArea", "Segment", "NumberOfSectionReferences", "NumberOfPfnReferences", "NumberOfMappedViews", "NumberOfUserReferences", "Control Flags", "FileObject", "FileNameWithDevice", "FirstPrototypePte", "LastContiguousPte", "Flags2"],
    "ldrmodules":["Pid", "Process", "Base", "InLoad", "InInit", "InMem", "MappedPath"],
    "netscan":["Offset(P)", "Proto", "LocalAddr", "ForeignAddr", "State", "PID", "Owner", "Created"],
    "cmdline":["Process", "PID", "CommandLine"],
    "envars":["Pid", "Process", "Block", "Variable", "Value"],
    "verinfo":["Module", "FileVersion", "ProductVersion", "Flags", "OS", "FileType", "FileDate", "InfoString"],
    "atoms":["Offset(V)", "Session", "WindowStation", "Atom", "RefCount", "HIndex", "Pinned", "Name"],
    "volshell":[],
}

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
}

def get_version_number(filename):
    try:
        info = GetFileVersionInfo (filename, "\\")
        ms = info['FileVersionMS']
        ls = info['FileVersionLS']
        return "{0}.{1}.{2}.{3}".format(HIWORD (ms), LOWORD (ms), HIWORD (ls), LOWORD (ls))
    except:
        return "0.0.0.0"

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
    for p in plugin_rows:
        print "\t\t{0}".format(p)


def setup(driver, service_name, pmem_service, debug = False):
    destroyer = threading.Thread(target=destroy, args=(driver, service_name, debug))
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

def printinfos(data, items =[], output = "text"):
    indeces = []
    if output == "json":
        print data
        return
    for item in items:
        indeces.append(data['columns'].index(item))
    if output == "csv":
        print ",".join(items)
    else:
        print "\t".join(items)
    for row in data['rows']:
        therow = ""
        for index in indeces:
            if output == "csv":
                therow += "{0},".format(row[index])
            else:
                therow += "{0}\t".format(row[index])
        print therow.rstrip(",").strip()

def printinfos_line(data, items = []):
    indeces = []
    for item in items:
        indeces.append(data['columns'].index(item))
    for row in data['rows']:
        for index in indeces:
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

def get_malfind_data(data, output = "text"):
    datas = getinfos(data, plugin_rows["malfind"])
    if output == "json":
        print datas
        return
    elif output == "text":
        for proc, address, data in datas:
            print "Process: ", proc
            print
            print "Raw data at address{0}: {1}".format(address, data)
            print
            print "Disassembly:"
            print "\n".join(
                    ["{0:#x} {1:<16} {2}".format(o, h, i)
                    for o, i, h in malfind.Disassemble(data.decode("hex"), int(address))
                    ])
    else:
        for proc, address, data in datas:
            print "{0},{1},{2}".format(proc, address, data)

class Configs:
    def __init__(self, path = "\\\\.\\pmem", profile = "Win10x64_16299", kdbg = None, debug = False):
        self.config = libapi.get_config(profile, path)

        if debug:
            print "Config created with Profile: {0} and Path: {1}".format(profile, path)
        if kdbg:
            self.kdbg = kdbg
            if debug:
                print "KDBG:", hex(kdbg.v())
        else:
            self.kdbg = self.get_the_kdbg()
            if self.kdbg != None:
                self.kdbg = self.kdbg.v()
                if debug:
                    print "KDBG:", hex(self.kdbg)
        if hasattr(self.kdbg, 'KdCopyDataBlock'):
            self.kdbg = self.kdbg.KdCopyDataBlock
            if debug:
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


def usage():
    print sys.argv[0], "\n"
    print "\t--plugins=<comma delimited list of plugins"
    list_plugins()
    print "\t--output=<output type: json/text/csv> (default: text)"
    print "\t--service=<service name> (default: pmem)"
    #print "\t--outfile=<output file> (default: stdout)"
    print "\t--debug: print out debug statements"
    print "\t--unload: unload the driver"

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hus:p:o:", ["help", "unload", "service=", "plugins=", "output=", "outfile=", "debug"])
    except getopt.GetoptError, err:
        print str(err)
        sys.exit(2)

    service_name = "pmem"
    unload = False
    plugins = None
    output = "text"
    out = sys.stdout
    debugg = False

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit(0)
        elif o in ("-s", "--service"):
            service_name = a 
        elif o in ("-u", "--unload"):
            unload = True
        elif o in ("--debug"):
            debugg = True
        elif o in ("-p", "--plugins"):
            plugins = a
        elif o in ("--outfile"):
            if os.path.exists(a):
                out = open(a, "wb")
            else:
                print "File not found! {0}".format(a)
                usage()
                sys.exit(-2)
        elif o in ("-o", "--output"):
            output = a.lower()
            if output not in outputs:
                print "Unsupported output: {0}".format(output)
                usage()
                sys.exit(-1)

    if not unload and plugins == None:
        print "You must specify a plugin (or list of plugins) to run!"
        usage()
        out.close()
        return

    if not unload:
        plugins = plugins.split(",")
    profs = registry.get_plugin_classes(obj.Profile)
    if platform.system() != "Windows":
        print "cannot run on a non-Windows machine"
        out.close()
        return
    profile = "Win10x64_16299"
    version = get_version_number("ntdll.dll")
    if platform.machine() == "AMD64":
        driver = "winpmem_x64.sys"
        profile = WindowsVersionsX64.get(version, "UNKNOWN")
    else:
        driver = "winpmem_x86.sys"
        profile = WindowsVersionsX86.get(version, "UNKNOWN")
    if profile == "UNKNOWN":
        profile = brute_force_profile(version)

    if profile not in profs:
        #out.close()
        #return
        if debugg:
            print "Incorrect profile found: {0}, version: {1}".format(profile, version)
            profile = "Win10x64_16299"
            print "Trying profile", profile
        profile = "Win10x64_16299"
    if debugg:
        print "Suggested profile: {0}".format(profile)

    driver = resource_path(driver)
    if not service_name or not os.access(driver, os.R_OK):
        out.write("Make sure the driver is in place: {0}".format(driver))
        sys.exit(-1)
    
    pmem_service = Service(driver = driver, service = service_name, debug = debugg)
    setup(driver, service_name, pmem_service, debugg)

    if unload:
        out.close()
        return
    try:
        pmem_service.start()
    except:
        print "Unable to start winpmem service"
        out.close()
        return

    myconfigs = Configs(path = "\\\\.\\" + service_name, profile = profile, debug = debugg)
    if myconfigs.kdbg == None:
        print "Unable to find valid KDBG value... quitting"
        setup(driver, service_name, pmem_service, debugg)
        out.close()
        return
    dovolshell = False
    cmds = registry.get_plugin_classes(commands.Command, lower = True)
    for p in plugins:
        rows = plugin_rows.get(p.strip(), None)
        if rows == None:
            print "Unable to process plugin", p
            continue
        if p == "malfind":
            get_malfind_data(myconfigs.getdata(malfind.Malfind), output = output)
            continue
        if p == "volshell":
            dovolshell = True
            continue
        data = myconfigs.getdata(cmds.get(p.strip(), None))
        if data == None:
            print "Plugin", p, "not found"
            continue
        printinfos(data, rows, output = output)
    
    if dovolshell:
        myconfigs.gettext(volshell.volshell)
    setup(driver, service_name, pmem_service, debugg)
    out.close()

if __name__ == "__main__":
    main()

