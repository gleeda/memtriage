# memtriage (previously lmem)
Allows you to quickly query a Windows machine for RAM artifacts

This tool utilizes the [Winpmem](https://github.com/google/rekall/tree/master/tools/pmem/resources/winpmem) drivers to access physical memory, and [Volatility](https://github.com/volatilityfoundation/volatility) for analysis.

**Caveats:**
* Doesn't work with Device Guard enabled.
* Should be tested on machines before deploying.

## Volatility Plugins

The following are currently supported:

* pslist
* dlllist
* ldrmodules
* modules
* handles
* malfind
* driverirp
* psxview
* privs
* svcscan
* getsids
* vadinfo
* netscan
* cmdline
* envars
* verinfo
* atoms
* shimcachemem
* apihooks
* procdump
* dlldump
* moddump
* dumpfiles
* volshell

## Example Usage

```
usage: memtriage.exe [-h] [--unload] [--load] [--debug] [--service SERVICE]
                     [--output OUTPUT] [--dumpdir DUMPDIR] [--base BASE]
                     [--offset OFFSET] [--memory MEMORY] [--pid PID] [--leave]
                     [--plugins PLUGINS] [--physoffset PHYSOFFSET]
                     [--physical] [--ignore] [--regex REGEX] [--name NAME]
                     [--keepname]

Memtriage options:

optional arguments:
  -h, --help            show this help message and exit
  --unload              Unload the driver and exit
  --load                Load the driver and exit
  --debug               Output debug messages while running
  --service SERVICE     Change the service name (default: pmem)
  --output OUTPUT       Output type: json/text/csv
  --dumpdir DUMPDIR     Directory to dump files to
                        (dlldump,procdump,moddump,vaddump,dumpfiles)
  --base BASE           Base of PE file to dump (dlldump,procdump,moddump)
  --offset OFFSET       Physical offset of process to act on
                        (dlldump,procdump,moddump,vaddump,dumpfiles)
  --memory MEMORY       Carve as a memory sample rather than exe/disk
                        (dlldump,procdump,moddump)
  --pid PID             Operate on this process ID
  --leave               Leave pmem service running with driver
  --plugins PLUGINS     Comma delimited list of plugins to run: dlldump
                        netscan cmdline procdump envars moddump handles
                        dlllist psxview vadinfo dumpfiles svcscan malfind
                        atoms apihooks volshell vaddump privs driverirp
                        shimcachemem ldrmodules modules verinfo pslist getsids
  --physoffset PHYSOFFSET
                        Dump File Object at physical address PHYSOFFSET
                        (dumpfiles)
  --physical            Display the physical address of object
                        (pslist,handles,modules)
  --ignore              Ignore case in pattern match (dumpfiles,verinfo)
  --regex REGEX         Dump files matching REGEX (dumpfiles,driverirp,privs)
  --name NAME           Name of process/object to operate on
  --keepname            Keep original file name (dumpfiles)
  --outfile OUTFILE     Combined output file (default: stdout)
```

### No Need to Specify Profiles

Memtriage will attempt to figure out the profile automattically and run with the appropriate settings.  If there is a not an exact match, Memtriage will attempt to use the closest named profile available.  Therefore, there is a possibility that object definitions won't line up exactly (like process names etc), which you may also see when running Volatility with an incorrect profile.  Profiles can be added to the Volatility code, and the executable can be recompiled with `pyinstaller`.
  
### Loading and Unloading the Driver
  
By default, `memtriage.exe` will attempt to load the driver when it first runs, and unload it when it exits.  You may however load and unload the driver manually with the `--load` and `--unload` options.  You may also request that the driver remain loaded after plugins have finished running with the `--leave` option.
  
```
> memtriage.exe --leave --plugins=dumpfiles --dumpdir=outdir --physoffset=1066160184 --keepname 
```

#### Service Name

The default service name that is created is `pmem`.  You may specify a different service name with the `--service=` option.  You must then use this `--service=` option for future invocations if you leave the driver loaded.  Example:

```
> c:\Users\user\Desktop>memtriage.exe --leave --service=somename --plugins=dlllist --pid=2924
[snip]
> c:\Users\user\Desktop>memtriage.exe --unload --service=somename 
```

### Running Plugins

You may run several plugins at a time by specifying them with comma delimitation with the `--plugins=` option.  Example:

```
> memtriage.exe --plugins=pslist,handles,dlllist 
```

Other options will be used for the appropriate plugin.  Example:

```
> memtriage.exe --plugins=pslist,handles,dlllist,dlldump,dumpfiles,shimcachemem,volshell --outfile=outfile.txt --pid=2924 --dumpdir=outdir --leave --keepname ----physoffset=1066160184
```
