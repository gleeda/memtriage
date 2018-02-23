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


'''
Author: Jamie Levy

memtriage

pyinstaller --upx-dir=upx391w --onefile pyinstaller.spec

'''

plugin_rows = {
    "dlllist":["Pid", "Base", "Size", "LoadCount", "LoadTime", "Path"],
    "pslist":["Offset(V)", "Name", "PID", "PPID", "Wow64", "Start", "Exit"],
    "handles":["Offset(V)", "Pid", "Handle", "Access", "Type", "Details"],
    "modules":["Offset(V)", "Name", "Base", "Size", "File"],
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
    #"6.2.9200.16384":"Win8SP0x64",
    "6.3.9600.16384":"Win8SP1x64",
    "6.3.9600.17031":"Win81U1x64",
    "6.3.9600.17581":"Win81U1x64",
    "6.3.9600.18340":"Win8SP1x64_18340",
    "10.0.10240.16384":"Win10x64",
    "10.0.10586.306":"Win10x64_10586",
    "10.0.14393.0":"Win10x64_14393",
    "10.0.15063.0":"Win10x64_15063",
    "10.0.16299.0":"Win10x64_16299",
}

def get_version_number (filename):
    try:
        info = GetFileVersionInfo (filename, "\\")
        ms = info['FileVersionMS']
        ls = info['FileVersionLS']
        return "{0}.{1}.{2}.{3}".format(HIWORD (ms), LOWORD (ms), HIWORD (ls), LOWORD (ls))
    except:
        return "0.0.0.0"

def brute_force_profile():
    profile = ""
    sp = "SP1"
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
    if platform.machine() == "AMD64":
        profile = profile + "x64"
    else:
        profile = profile + "x86"
    return profile


def setup(driver, service_name, pmem_service):
    destroyer = threading.Thread(target=destroy, args=(driver, service_name))
    destroyer.start()
    destroyer.join()
    try:
        pmem_service.create()
    except:
        print "Unable to ceate service", service_name
    try:
        pmem_service.stop()
    except:
        print "Unable to stop service", service_name

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

class Configs:
    def __init__(self, path = "\\\\.\\pmem", profile = "Win10x64_16299", kdbg = None):
        self.config = libapi.get_config(profile, path)

        print "Config created with Profile: {0} and Path: {1}".format(profile, path)
        if kdbg:
            self.kdbg = kdbg
            print "KDBG:", hex(kdbg.v())
        else:
            self.kdbg = self.get_the_kdbg()
            if self.kdbg != None:
                self.kdbg = self.kdbg.v()
                print "KDBG:", hex(self.kdbg)

        if hasattr(self.kdbg, 'KdCopyDataBlock'):
            self.kdbg = self.kdbg.KdCopyDataBlock
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
    print "\t--output=<output type: json/text/csv> (default: text)"
    print "\t-s <service name> (default: pmem)"
    print "\t-u: unload the driver"

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hus:p:o:", ["help", "unload", "service=", "plugins=", "output="])
    except getopt.GetoptError, err:
        print str(err)
        sys.exit(2)

    service_name = "pmem"
    unload = False
    plugins = None
    output = "text"

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit(0)
        elif o in ("-s", "--service"):
            service_name = a 
        elif o in ("-u", "--unload"):
            unload = True
        elif o in ("-p", "--plugins"):
            plugins = a
        elif o in ("-o", "--output"):
            output = a.lower()
            if output not in outputs:
                print "Unsupported output:", output
                usage()
                sys.exit(-1)

    if not unload and plugins == None:
        print "You must specify a plugin (or list of plugins) to run!"
        usage()
        return

    if not unload:
        plugins = plugins.split(",")
    profs = registry.get_plugin_classes(obj.Profile)
    if platform.system() != "Windows":
        print "cannot run on a non-Windows machine"
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
        profile = brute_force_profile()

    if profile not in profs:
        print "Incorrect profile found:", profile, "version:", version
        return
    print "Suggested profile:", profile

    driver = resource_path(driver) #os.path.join(resource_path("."), driver)
    print "Driver at: ", driver
    if not service_name or not os.access(driver, os.R_OK):
        print "make sure the driver is in place.", driver
        sys.exit(-1)
    
    pmem_service = Service(driver = driver, service = service_name)
    setup(driver, service_name, pmem_service)

    if unload:
        return
    try:
        pmem_service.start()
    except:
        print "Unable to start winpmem service"
        return

    myconfigs = Configs(path = "\\\\.\\" + service_name, profile = profile)
    if myconfigs.kdbg == None:
        print "Unable to find valid KDBG value... quitting"
        setup(driver, service_name, pmem_service)
        return
    cmds = registry.get_plugin_classes(commands.Command, lower = True)
    for p in plugins:
        data = myconfigs.getdata(cmds.get(p.strip(), None))
        if data == None:
            print "Plugin", p, "not found"
            continue
        rows = plugin_rows.get(p.strip(), None)
        if rows == None:
            print "Unable to process plugin", p
            continue
        printinfos(data, rows, output = output)
    
    '''
    print
    print "Getting a process list"
    print
    data = myconfigs.getdata(taskmods.PSList)
    printinfos(data, ["Name", "PID", "PPID", "Start", "Exit"])
    print 
    print "Running Malfind..."
    print
    data = myconfigs.getdata(malfind.Malfind)
    datas = getinfos(data, ["Process", "Data"])
    for proc, data in datas:
        print "Process: ", proc
        print
        print "Raw data: ", data
        print
        print "Disassembly:"
        print "\n".join(
                    ["{0:#x} {1:<16} {2}".format(o, h, i)
                    for o, i, h in malfind.Disassemble(data.decode("hex"), 0)
                    ])
    '''
    myconfigs.gettext(volshell.volshell)
    setup(driver, service_name, pmem_service)
    #pmem_service.destroy()

if __name__ == "__main__":
    main()

