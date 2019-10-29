# -*- mode: python -*-
import sys
projpath = os.path.dirname(os.path.abspath(SPEC))

def get_plugins(list):
    for item in list:
        if item[0].startswith('volatility.plugins') and not (item[0] == 'volatility.plugins' and '__init__.py' in item[1]):
            yield item

exeext = ".exe" if sys.platform.startswith("win") else ""

a = Analysis([os.path.join(projpath, 'memtriage.py')],
              pathex = [HOMEPATH],
              hookspath = [os.path.join(projpath, 'pyinstaller')])

for d in a.datas:
    if 'pyconfig' in d[0]: 
        a.datas.remove(d)
        break

excludes = [".DS_Store", "arm.py", "elfcoredump.py", "ieee1394.py", "hpak.py", "vmware.py", "macho.py", "lime.py", "osxpmemelf.py", "vmem.py", "vmware.py"]

for d in a.binaries:
    for item in d[0]:
        if item in excludes:
            print ("removing {}".format(d[0]))
            a.binaries.remove(d)

pyz = PYZ(a.pure)
plugins = Tree(os.path.join(projpath, 'volatility', 'plugins'),
               os.path.join('plugins'))
exe = EXE(pyz,
          a.scripts + [('u', '', 'OPTION')],
          a.binaries,
          a.zipfiles,
          a.datas,
          plugins,
          name = os.path.join(projpath, 'dist', 'pyinstaller', 'memtriage' + exeext),
          debug = False,
          strip = False,
          upx = True,
          icon = os.path.join(projpath, 'resources', 'memforensics.ico'),
          console = 1)

