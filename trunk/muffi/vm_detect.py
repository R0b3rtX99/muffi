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
        self.sidt_list  =    []            # List of SIDT instruction addresses
        self.sldt_list  =    []            # List of SLDT instruction addresses
        self.sgdt_list  =    []            # List of SGDT instruction addresses
        self.os         =    None          # Operating system to spoof to the executable
        
    def cloak_vmware(self,os=None):
        """
        This function is responsible for finding traces of
        VMWare(c) detection code in the debuggee. It will
        then hook SIDT, SGDT, and SLDT instructions so that
        the virtual machine is hidden. Future copies should 
        also hook all registry checks, file checks etc.
        
        @type: os    String
        @param os    (Optional)The operating system you wish to spoof, 
        defaults to randomly picking one. The options are::
        
            WindowsXP
            Windows2000
        
        @raise: mfx An exception is raised if the cloaking fails.
        @rtype: Boolean
        @return: Returns True if the patches were applied correctly.
        
        @see: dt_search()
        """
        if os.lower() not in ("WindowsXP".lower(),"Windows2000".lower()):
            raise mfx("The operating system must be one of WindowsXP or Windows2000")
        else:
            self.os    =    os
        
        # First find any SIDT, SGDT and SLDT instructions
        # and hook them so that we can modify the return value
        dt_matches = self.dt_search()
    
    def dt_search(self):
        """
        This is a helper function for cloaking VMWare. It locates
        any SIDT, SGDT and SLDT functions, so that we can install
        hooks into them.
        
        @raise: mfx An exception is raised if the search fails.
        @rtype: List
        @return: Returns a list of all the matches.
        """
        
        self.sidt_list = self.imm.Search(SIDT_OPCODE)
        self.sgdt_list = self.imm.Search(SGDT_OPCODE)
        self.sldt_list = self.imm.Search(SLDT_OPCODE)
        
        
        # Now let's build some hooks 
        dt_hooker = dt_hooks()
    
    
 
class dt_hooks(LogBpHook):
    """
    This is a helper class that is responsible for
    hooking the various instructions that are responsible
    for storing descriptor table addresses.
    """
    
    def __init__(self,hook_register,operating_system):
        """
        This just sets up the hook itself, and initializes 
        a debugger instance.
        
        @type:  hook_register String
        @param: hook_register The register that we need to modify with our own table entry.
        
        """
        LogBpHook.__init__(self)
        self.imm        =    Debugger()
    
    def run(self,regs):
        """
        This is run when the hook gets hit. It is responsible
        for writing a 
        