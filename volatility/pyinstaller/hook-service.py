# Service hook
#
# This currently contains the hardcoded location for the driver files
# It could be improved by carrying out a search, or using sys.path
#
# This also requires the openpyxl module to be modified with the following patch:

# import sys
# if hasattr(sys, '_MEIPASS'):
#     here = sys._MEIPASS

import os
import sys

datas = []
path = os.path.join(os.getcwd(), "drivers")

datas.append((os.path.join(path, "winpmem_64.sys"), "."))
datas.append((os.path.join(path, "winpmem_32.sys"), "."))
datas.append((os.path.join(path, "att_winpmem_64.sys"), "."))
datas.append((os.path.join(path, "att_winpmem_32.sys"), "."))
