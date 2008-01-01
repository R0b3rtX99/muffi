#
# muffi - Malware and Unpacking Framework for Immunity Debugger
# 
# Copyright (C) 2007 Justin Seitz <jms@bughunter.ca>, BoB <BobSoft@GMail.Com>
#
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program; if not, write to the Free
# Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

'''
@author:       Justin Seitz, BoB
@license:      GNU General Public License 2.0 or later
@contact:      jms@bughunter.ca, bobsoft@gmail.com
'''

import struct
import random
import ctypes

from immlib        import *
from mfx           import *
from muffi_defines import *
from patch_utils   import *

class vm_detect():
    """
    This class is aimed to allow the malware analyst or reverse
    engineer the ability to cloak that they are debugging the process
    in a virtual machine.
    """
    def __init__(self):
        
        self.imm        =    Debugger()
        
    def cloak_vmware(self):
        """
        This function is responsible for finding traces of
        VMWare(c) detection code in the debuggee. It will
        then hook SIDT, SGDT, and SLDT instructions so that
        the virtual machine is hidden. Future copies should 
        also hook all registry checks, file checks etc.
        
        @raise: mfx An exception is raised if the cloaking fails.
        @rtype: Boolean
        @return: Returns True if the patches were applied correctly.
        """
        pass