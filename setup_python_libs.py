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
