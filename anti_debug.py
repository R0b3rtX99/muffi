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

from mfx         import *
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
        Poly-patches the instructions responsible for checking the PEB
        to determine if a debugger is attached. However, it does 
        NOT modify the PEB itself.
        
        @rtype          Bool
        @return:        Returns True if the patch succeeded.
        '''
        
        # Check whether the function is exported from kernel32.dll
        function_present = self.imm.getAddress("kernel32.IsDebuggerPresent")
        
        if (function_present <= 0):
            self.imm.Log("[*] No IsDebuggerPresent to patch ..")
            return True

        self.imm.Log("[*] Patching kernel32.IsDebuggerPresent...",address = function_present)
        
        patch_header = self.imm.Assemble("DB 0x64\n Mov EAX, DWORD PTR DS:[0x18]")
        ret          = self.imm.Assemble("ret")
        
        # Create patch code
        patch_code = patch_header + patch_utils().poly_eax_zero() + ret
        
        # Write the patched instructions
        if self.imm.writeMemory(function_present, patch_code):
            return True
    
    def patch_peb(self, peb_flag = None):
        '''
        Various patches for the PEB. Use the Flag
        variable to select particular fields in the 
        PEB that you wish to patch.
        
        @type  flag:  STRING
        @param flag:  (Optional) Specific flag you wish to patch. Values can be one of:
        
                      IsDebugged
                      ProcessHeap
                      NtGlobalFlag
                      LDR_DATA
        
          
        @rtype BOOLEAN
        @return    Returns True if the patch was successful.
        '''
        try:
            peb_address = self.imm.getPEBaddress()
        except:
            raise mfx("[*] Could not obtain PEB address.")
        
        # Patch the IsDebugged member
        if peb_flag is None or peb_flag.lower() == "isdebugged":
            offset = peb_address + 0x02
            self.imm.Log( "[*] Patching PEB.IsDebugged", address = offset )
            # Zero out the flag, BoB's original patch assembled a DB 0 into that position
            self.imm.writeMemory(offset, "\x00" )
        
        # Patch the ProcessHeap member
        if peb_flag is None or peb_flag.lower() == "processheap":
            offset = self.imm.readLong(peb_address + 0x18) + 0x10
            self.imm.Log("[*] Patching PEB.ProcessHeap", address = offset)
            self.imm.writeLong(offset, "\x00")
        
        # Patch the NtGlobalFlag member
        if peb_flag is None or peb_flag.lower() == "ntglobalflag":
            offset = peb_address + 0x68
            self.imm.Log("[*] Patching PEB.NtGlobalFlag", address = offset)
            self.imm.writeLong(offset, "\x00")

        # Patch the PEB_LDR_DATA struct by replaciong 0xFEEEFEEE
        # with zeros
        if peb_flag is None or peb_flag.lower() == "ldr_data":
            offset = self.imm.readLong(peb_address + 0x0C)
            imm.Log("[*] Patching PEB LDR_DATA", address = offset)
        
            # Now we are going to iterate over the LDR_DATA
            # and replace any instances of 0xFEEEFEEE with zeros
            fill_bytes = True
            
            while fill_bytes == True:
                offset += 1
                
                try:
                    first_dword = self.imm.readLong(offset)
                    second_dword= self.imm.readLong(offset + 0x4)
                    
                    if first_dword == LDR_DEBUG_FILL and second_dword == LDR_DEBUG_FILL:
                        self.imm.writeLong(offset, "\x00")
                        self.imm.writeLong(offset + 0x4, "\x00")
                        
                        offset += 7
                
                except:
                    break
 
    def harness(self):
        '''
        Standard harness for testing new functionality
        as we build it. This is kept in the final release
        so that developers can test their patches before
        we commit them.
        '''
        
        self.imm.Log("[*] Anti-debug harness function called.")
    
        