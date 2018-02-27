# Modified from Rekall to work with Volatility
#
# Rekall Memory Forensics
# Copyright (C) 2012 Michael Cohen
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Authors:
# Michael Cohen <scudette@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
"""This is a windows specific address space."""
import struct
import win32file

import volatility.addrspace as addrspace

def CTL_CODE(DeviceType, Function, Method, Access):
    return (DeviceType<<16) | (Access << 14) | (Function << 2) | Method

# IOCTLS for interacting with the driver.
INFO_IOCTRL = CTL_CODE(0x22, 0x103, 0, 3)

class Win32FileAddressSpace(addrspace.AbstractRunBasedMemory):
    """ This is a direct file AS for use in windows.

    In windows, in order to open raw devices we need to use the win32 apis. This
    address space allows us to open the raw device as exported by e.g. the
    winpmem driver.
    """

    order = 90

    def __init__(self, base, config, **kwargs):
        self.as_assert(base == None, 'Must be first Address Space')
        addrspace.AbstractRunBasedMemory.__init__(self, base, config, **kwargs)     

        self.fhandle = win32file.CreateFile(
            "\\\\.\\pmem",
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
            None,
            win32file.OPEN_EXISTING,
            win32file.FILE_ATTRIBUTE_NORMAL,
            None)
            
        self.ParseMemoryRuns()

    def __del__(self):
        self.close()

    FIELDS = (["CR3", "NtBuildNumber", "KernBase", "KDBG"] +
              ["KPCR%02d" % i for i in xrange(32)] +
              ["PfnDataBase", "PsLoadedModuleList", "PsActiveProcessHead"] +
              ["Padding%s" % i for i in xrange(0xff)] +
              ["NumberOfRuns"])

    def ParseMemoryRuns(self):
        result = win32file.DeviceIoControl(
            self.fhandle, INFO_IOCTRL, "", 102400, None)

        fmt_string = "Q" * len(self.FIELDS)
        memory_parameters = dict(zip(self.FIELDS, struct.unpack_from(
                    fmt_string, result)))

        self.dtb = memory_parameters["CR3"]

        offset = struct.calcsize(fmt_string)

        for x in xrange(memory_parameters["NumberOfRuns"]):
            start, length = struct.unpack_from("QQ", result, x * 16 + offset)
            self.runs.append((start, start, length))

    def _read(self, addr, length, pad = False):
    
        offset = self.translate(addr)
        if offset == None:
            if pad:
                return "\x00" * length
            else:
                return None
            
        win32file.SetFilePointer(self.fhandle, offset, 0)
        data = win32file.ReadFile(self.fhandle, length)[1]

        return data
        
    def close(self):
        try:
            win32file.CloseHandle(self.fhandle)
        except AttributeError:
            pass

