# Modified from: Detekt:
#   https://github.com/botherder/detekt
# Other refs:
#   https://code.activestate.com/recipes/135700-win32-service-administration/
# GPL 

import os, sys
import time
import win32service
import win32serviceutil
import win32file
from threading import Timer, Event
import threading
import struct

RUNNING = win32service.SERVICE_RUNNING
STARTING = win32service.SERVICE_START_PENDING
STOPPING = win32service.SERVICE_STOP_PENDING
STOPPED = win32service.SERVICE_STOPPED

SERVICE_WAIT_TIMEOUT = 30

class Service(object):
    def __init__(self, driver, service):
        self.driver = driver
        self.service_name = service
        self.manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CREATE_SERVICE)
        self.service = None

    def __del__(self):
        if self.service:
            win32service.CloseServiceHandle(self.service)

    def load(self):
        kdbg = None
        try:
            fd = win32file.CreateFile(
                "\\\\.\\" + self.service_name,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
                None,
                win32file.OPEN_EXISTING,
                win32file.FILE_ATTRIBUTE_NORMAL,
                None)

            print "Loaded the winpmem driver. You can now attach volatility to", "\\\\.\\" + self.service_name
        except:
            print "error with CreateFile of fd", "\\\\.\\" + self.service_name
        try:
            #image = Image(fd)
            print
        except:
            print "error loading driver", self.driver
        return kdbg

    def wait_status(self, status=win32service.SERVICE_RUNNING, timeout=SERVICE_WAIT_TIMEOUT):
        abort = Event()
        abort.clear()

        def die():
            abort.set()

        timer = Timer(timeout, die)
        timer.start()

        current = None
        while True:
            if abort.is_set():
                # If timeout is hit we abort.   
                print "Timeout hit waiting service for status {0}, current status {1}".format(status, current['CurrentState'])
                return

            current = win32service.QueryServiceStatusEx(self.service)

            if current['CurrentState'] == status:
                timer.cancel()
                return

            time.sleep(1)

    def open(self):
        try:
            self.service = win32service.OpenService(
                self.manager,
                self.service_name,
                win32service.SERVICE_ALL_ACCESS
            )
        except Exception as e:
            print "Unable to OpenService: {0}".format(e)

    def create(self):
        if not self.driver or not os.path.exists(self.driver):
            print "The driver does not exist at path: {0}".format(self.driver)
            return
        print "Trying to create service", self.service_name, self.driver

        try:
            if not self.service:
                self.service = win32service.CreateService(
                    self.manager,
                    self.service_name,
                    self.service_name,
                    win32service.SERVICE_ALL_ACCESS,
                    win32service.SERVICE_KERNEL_DRIVER,
                    win32service.SERVICE_DEMAND_START,
                    win32service.SERVICE_ERROR_IGNORE,
                    self.driver,
                    None, 0, None, None, None)
        except win32service.error as e:
            print "Unable to create service: {0}".format(e)
            self.service = win32service.OpenService(self.manager, self.service_name,
                                        win32service.SERVICE_ALL_ACCESS)
        try:
            win32service.ControlService(self.service, win32service.SERVICE_CONTROL_STOP)
        except win32service.error:
            pass

    def start(self):
        print "Trying to start the winpmem service..."

        try:
            win32service.StartService(self.service, [])
        except Exception as e:
            # If the service is already loaded we can continue.
            # This generally shouldn't happen, but in case it does we can just
            # try to use the running instance and unload it when we're done.
            if hasattr(e, 'winerror') and int(e.winerror) == 1056:
                print "The service appears to be already loaded"
            # If the problem is different, we need to terminate.
            else:
                print "Unable to start service: {0}".format(e)

        self.wait_status()

    def svcStatus(self):
        return win32serviceutil.QueryServiceStatus(self.service_name, None)[1]   # scvType, svcState, svcControls, err, svcErr, svcCP, svcWH

    def svcStop(self):
        status = win32serviceutil.StopService(self.service_name, None)[1]
        while status == STOPPING:
            time.sleep(1)
            status = svcStatus(self.service_name, None)
        return status

    def stop(self):
        print "Trying to stop the winpmem service..."

        try:
            win32service.ControlService(self.service, win32service.SERVICE_CONTROL_STOP)
        except Exception as e:
            print "Unable to stop service: {0}".format(e)

        self.wait_status(win32service.SERVICE_STOPPED)

    def delete(self):
        print "Trying to delete the winpmem service..."

        try:
            win32service.DeleteService(self.service)
        except:
            print "Unable to DeleteService"
        try:
            win32service.CloseServiceHandle(self.service)
        except Exception as e:
            print "Unable to CloseServiceHandle: {0}, {1}".format(self.service, e)
        try:
            win32service.CloseServiceHandle(self.manager)
        except Exception as e:
            print "Unable to delete the service: {0}".format(e)

def destroy(driver, service):
    print ("Launching service destroyer...")
    service = Service(driver, service)
    try:
        service.open()
    except Exception as e:
        print e
        return

    try:
        service.stop()
    except:
        pass

    try:
        service.delete()
    except Exception as e:
        print e

