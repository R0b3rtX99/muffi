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
    '''
    
    def __init__(self):
        
        self.imm            =    Debugger()
        self.patch_utils    =    patch_utils()
    
    def check_remote_debugger_present(self):
        """
        Patches the instructions in the beginning of the
        CheckRemoteDebuggerPresent() function call.
        
        @rtype: Boolean
        @return: True if the patch to CheckRemoteDebuggerPresent() succeeds.
        """
        func_address = self.imm.getAddress("kernel32.CheckRemoteDebuggerPresent")
        
        if (func_address <= 0):
            self.imm.Log("[*] No CheckRemoteDebuggerPresent() function.")

    
        self.imm.Log("[*] Patching CheckRemoteDebuggerPresent.", address = func_address )
        
        # Patch instructions in to bypass the call
        patch_code = self.imm.Assemble( " \
            Mov   EDI, EDI                                    \n \
            Push  EBP                                         \n \
            Mov   EBP, ESP                                    \n \
            Mov   EAX, [EBP + C]                              \n \
            Push  0                                           \n \
            Pop   [EAX]                                       \n \
            Xor   EAX, EAX                                    \n \
            Pop   EBP                                         \n \
            Ret   8                                           \
        " )
        
        bytes_written = self.imm.writeMemory(func_address,patch_code)
        
        if bytes_written == 0:
            raise mfx("[*] Could not patch CheckRemoteDebuggerPresent()")
        
        return True
    
    def get_tick_count(self):
        """
        Poly-patches the GetTickCount() function call, the reason it
        uses poly-patching is because it's too easy to check for 
        XOR EAX,EAX or MOV EAX, 0xXXXXXXXX.
        
        @rtype:    Boolean
        @return:   True if function was patched successfully, False if it fails.
        """
        func_address = self.imm.getAddress("kernel32.GetTickCount")
        
        if func_address <= 0:
            return False
        
        self.imm.Log("[*] Patching GetTickCount().")
        
        # We keep the first instruction to avoid integrity checks
        patch_header = self.imm.Assemble("MOV EDX, 0x7FFE0000")
        patch_body   = self.patch_utils.poly_eax_dword()
                
        patch_code   = patch_header + patch_body + FUNCTION_RETURN
        
        # Patch the function call
        bytes_written = self.imm.writeMemory(func_address, patch_code)
            
        if bytes_written != len(patch_code):
            return False
        
        return True
            
    
    def is_debugger_present(self):
        """
        Poly-patches the instructions responsible for checking the PEB
        to determine if a debugger is attached. However, it does 
        NOT modify the PEB itself.
        
        @rtype:         Boolean
        @return:        Returns True if the patch succeeded.
        """
        
        # Check whether the function is exported from kernel32.dll
        function_address = self.imm.getAddress("kernel32.IsDebuggerPresent")
        
        if (function_address <= 0):
            self.imm.Log("[*] No IsDebuggerPresent to patch ..")
            return True

        self.imm.Log("[*] Patching kernel32.IsDebuggerPresent...",address = function_address)
        
        patch_header = self.imm.Assemble("DB 0x64\n Mov EAX, DWORD PTR DS:[0x18]")
                
        # Create patch code
        patch_code = patch_header + self.patch_utils.poly_eax_zero() + FUNCTION_RETURN
        
        # Write the patched instructions
        if self.imm.writeMemory(function_address, patch_code):
            return True
    
    def patch_peb(self, peb_flag = None):
        """
        Various patches for the PEB. Use the Flag
        variable to select particular fields in the 
        PEB that you wish to patch.
        
        @type  peb_flag:  String
        @param peb_flag:  (Optional) Specific flag you wish to patch. 
        Values can be one of (case IN-sensitive)::
        
        
            BeingDebugged
            ProcessHeap
            NtGlobalFlag
            LDR_DATA
        
          
        @rtype: Boolean
        @return:    Returns True if the patch was successful.
        """
        try:
            peb_address = self.imm.getPEBaddress()
            peb         = self.imm.getPEB()
        except:
            raise mfx("[*] Could not obtain PEB address.")
        
        # Patch the IsDebugged member
        if peb_flag is None or peb_flag.lower() == "beingdebugged":
            offset = peb_address + 0x02
            self.imm.Log( "[*] Patching PEB.BeingDebugged", address = offset )
            
            # Zero out the flag, BoB's original patch assembled a DB 0 into that position
            self.imm.writeMemory(offset, "\x00")
        
        # Patch the ProcessHeap member
        if peb_flag is None or peb_flag.lower() == "processheap":
            offset = self.imm.readLong(peb_address + 0x18) + 0x10
            self.imm.Log("[*] Patching PEB.ProcessHeap", address = offset)
            self.imm.writeMemory(offset, DWORD_ZERO)
        
        # Patch the NtGlobalFlag member
        if peb_flag is None or peb_flag.lower() == "ntglobalflag":
            offset = peb_address + 0x68
            self.imm.Log("[*] Patching PEB.NtGlobalFlag", address = offset)
            self.imm.writeMemory(offset, DWORD_ZERO)

        # JMS: Patch the PEB_LDR_DATA struct by replaciong 0xFEEEFEEE
        # with zeros
        if peb_flag is None or peb_flag.lower() == "ldr_data":
            
            # Grab the memory page where the LDR_DATA struct resides
            # dump it to dirty_memory, and then replace all 0xFEEEFEEE
            page         = self.imm.getMemoryPagebyAddress(peb.Ldr[0])
            dirty_memory = page.getMemory()
            clean_memory = dirty_memory.replace("\xEE\xFE\xEE\xFE","\x00\x00\x00\x00")
    
            bytes_written = self.imm.writeMemory(page.getBaseAddress(), clean_memory)
            
            if bytes_written == 0:
                raise mfx("[*] Could not write the memory page to patch PEB.LDR_DATA.")
            
        return True
    
    def process32_first_next(self):
        """
        This patch prevents a packer or malware sample from
        iterating all of the running processes on the system. 
        This disables checks where they are iterating through all running
        processes doing checks for debuggers or for determining the parent
        process which spawned their executable. This will patch: 
        kernel32.Process32FirstW and kernel32.Process32NextW
        
        @rtype:     Boolean
        @return:    Returns True if the patch was successful, False if it failed.
        """
        function_addresses = []
        
        # Build the list of function addresses to patch
        function_addresses.append(self.imm.getAddress("kernel32.Process32FirstW"))
        function_addresses.append(self.imm.getAddress("kernel32.Process32NextW"))
                        
        # TODO: Preserve the first instructions to evade integrity checks
        for address in function_addresses:
            if address != 0:
                
                # Generate the poly-patch to zero out EAX
                patch_code = self.patch_utils.poly_eax_zero() + FUNCTION_RETURN
                
                # Write the patch to the function header
                bytes_written = self.imm.writeMemory(address, patch_code)
                
                if bytes_written != len(patch_code):
                    return False
        
        return True
                
    def zw_query_information_process(self):
        """
        This patches ntdll.ZwQueryInformationProcess to hide that
        there is a debugger present. This essentially patches the 
        ProcessDebugPort in the ProcessInformationClass parameter.
        
        @rtype:    Boolean
        @return:   Returns True if the patch was successful, False if it failed.
        """
        function_address = self.imm.getAddress("ntdll.ZwQueryInformationProcess")
        
        if (function_address <= 0):
            self.imm.Log("[*] No ZwQueryInformationProcess to patch.")
            return True
        
        self.imm.Log("[*] Patching ntdll.ZwQueryInformationProcess.")
        
        is_patched    = False
        
        instruction_length = self.patch_utils.find_instruction_length(function_address,2)
                
        # Now let's test to see if the function has been patched already
        fake_code = self.imm.readMemory(function_address,1) + self.imm.Assemble("DD 0x12345678") + self.imm.readMemory(function_address + 5,1)
        
        if fake_code == self.imm.Assemble("Push 0x12345678\n Ret"):
            
            # It's been patched already
            is_patched = True
            
            # Find the address where the patch points to 
            address = self.imm.readLong(function_address + 1)
            
            # Find the length of the two instructions
            instruction_length = self.patch_utils.find_instruction_length(address,2)
            
        # If the function hasn't been patched already then
        # allocate a page for our detour code and write the 
        # first two original instructions
        if is_patched == False:
            
            # Allocate our detour page
            stub_address = self.imm.remoteVirtualAlloc()
            
            # Write the instructions
            bytes_written = self.imm.writeMemory(stub_address, self.imm.readMemory(function_address,instruction_length))
            
            if bytes_written < instruction_length:
                raise mfx("[*] ZwQueryInformation Patch failed - couldn't write to memory page.")
            
        patch_body = " \
            CMP DWORD [ESP+8], 7        \n    \
            DB 0x74, 0x06               \n    \
                                        \n    \
            PUSH 0x%08x                 \n    \
            RET                         \n    \
                                        \n    \
            MOV EAX, DWORD [ESP+0x0C]   \n    \
            PUSH 0                      \n    \
            POP [EAX]                   \n    \
            XOR EAX, EAX                \n    \
            RET 14" % (function_address + instruction_length)
        
        patch_body = self.imm.Assemble(patch_body)
        
        # Write the patch code after the first two original instructions
        bytes_written = self.imm.writeMemory(stub_address + instruction_length, patch_body)
        
        if bytes_written < len(patch_body):
            raise mfx("[*] ZwQueryInformationProcess - couldn't write primary patch code to memory.")
        
        # If it hasn't been patched already then write the detour
        # jmp as a PUSH/RET combo
        if is_patched == False:
            
            detour_jmp = self.imm.Assemble("PUSH 0x%08x\n RET" % stub_address)
            
            bytes_written = self.imm.writeMemory(function_address, detour_jmp)
            
            if bytes_written < len(detour_jmp):
                raise mfx("[*] ZwQueryInformationProcess - couldn't write the detour combo at original function address.")
        
        return True
    
    def harness(self):
        '''
        Standard harness for testing new functionality
        as we build it. This is kept in the final release
        so that developers can test their patches before
        we commit them.
        '''
        
        self.imm.Log("[*] Anti-debug harness function called.")
    
        