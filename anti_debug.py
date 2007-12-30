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

from patch_utils import *
from immlib      import *

class anti_debug():
    '''
    This class encapsulates all anti-debugging tricks, you can call
    individual methods to apply a particular patch or you can use 
    anti_debug.all() to apply all developed anti-debugging bypasses.
    Unless specifically stated otherwise, all of these tricks are by BoB 
    from team PEid.
    '''
    
    def __init__(self):
        
        self.imm            =    Debugger()
    
    
    def is_debugger_present(self):
        '''
        Patches the instructions responsible for checking the PEB
        to determine if a debugger is attached. However, it does 
        NOT modify the PEB itself.
        
        
        @rtype          Bool
        @return:        Returns True if the patch succeeded.
        '''
        # Check whether the function is exported from kernel32.dll
        function_present = self.imm.getAddress( "kernel32.IsDebuggerPresent" )
        
        if (function_present <= 0):
            self.imm.Log("[*] No IsDebuggerPresent to patch ..")
            return True

        self.imm.Log("[*] Patching kernel32.IsDebuggerPresent...",address = function_present)
        
        patch_header = self.imm.Assemble("DB 0x64\n Mov EAX, DWORD PTR DS:[0x18]")
        ret          = self.imm.Assemble("ret")
        
        # Create patch code
        patch_code = patch_header + poly_eax_zero() + ret
        
        # Write the patched instructions
        if self.imm.writeMemory(function_present, patch_code):
            return True
        
        
    # Careful for Win2k ..
    while len(Code) > 0x0E:
      Code = imm.Assemble("DB 0x64\n Mov EAX, DWORD PTR DS:[0x18]") + Poly_Return0(imm) + imm.Assemble( "ret" )
    imm.writeMemory( ispresent, Code )
    
    def harness(self):
        '''
        Standard harness for testing new functionality
        as we build it. This is kept in the final release
        so that developers can test their patches before
        we commit them.
        '''
        
        self.imm.Log("[*] Anti-debug harness function called.")
    
        