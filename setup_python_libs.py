# Allow Ghidra jython to access installed python libraries
# @author achin
# @category Python

import os
import pwd
import sys

# ofc these depend on your system installations
sys.path.append('/usr/lib/python3/dist-packages')
sys.path.append('/usr/local/lib/python3.8/dist-packages')
username = pwd.getpwuid(os.getuid())[0]
sys.path.append('/home/{}/.local/python3.8/site-packages'.format(username))

# attempt to make this more portable, but I forgot Ghidra uses jython which is python 2.7
#import subprocess
#script="""import site
#for dir in site.getsitepackages():
#    print dir
#"""
#res = subprocess.run(['python3', '-c', script], stdout=subprocess.PIPE)
#pkgs = res.stdout.decode('utf-8').split()
#for pkg in pkgs:
#    sys.append(pkg)
