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
        self.os         =    None          # Operating system to spoof to the executable
        self.sidt_list  =    []            # List of SIDT instruction addresses
        self.sldt_list  =    []            # List of SLDT instruction addresses
        self.sgdt_list  =    []            # List of SGDT instruction addresses
        self.hook_addrs =    {}            # Dictionary of hook locations for descriptor tables
        
    def cloak_vmware(self,os=None):
        """
        This function is responsible for finding traces of
        VMWare(c) detection code in the debuggee. It will
        then hook SIDT, SGDT, and SLDT instructions so that
        the virtual machine is hidden. Future copies should 
        also hook all registry checks, file checks etc.
        
        @type: os    String
        @param os    (Optional)The operating system you wish to spoof, 
        defaults to WindowsXP. The options are::
        
            WindowsXP
            Windows2003
            Windows2000
        
        @raise: mfx An exception is raised if the cloaking fails.
        @rtype: Boolean
        @return: Returns True if the patches were applied correctly.
        
        @see: dt_search(), dt_hooks()
        """
        
        if self.os is None:
            self.os    =    "WindowsXP"
        elif os.lower() not in ("WindowsXP".lower(),"Windows2000".lower(),"Windows2003".lower()) and os.lower() != None:
            raise mfx("The operating system must be one of WindowsXP or Windows2000")
        else:
            self.os    =    os
        
    
        # First find any SIDT, SGDT and SLDT instructions
        # and hook them so that we can modify the return value
        self.imm.Log("About to search")
        search = self.dt_search()

        if search != False:
            # Now iterate through the found addresses and 
            # patch the code so that it sets the appropriate
            # descriptor constant
            self.dt_patch()
        
                  
    def dt_search(self):
        """
        This is a helper function for cloaking VMWare. It locates
        any SIDT, SGDT and SLDT functions, so that we can install
        hooks into them.
        
        @raise: mfx An exception is raised if the search fails.
        @rtype: List
        @return: Returns a list of all the matches.
        """
        
        # Grab the module information and make sure the code is
        # analysed
        module = self.imm.getModule(self.imm.getDebuggedName())
        
        if not module.isAnalysed():
            self.imm.analyseCode(module.getCodebase())
        
        # Calculate how much of the binary we need to walk through
        code_base = module.getCodebase()
        code_len  = code_base + module.getCodesize()
        current_ea= module.getCodebase()
        
        # Start walking through the binary looking for those
        # particular calls
        found_call    =    False
        while current_ea <= code_len:
            current_opcode = self.imm.disasmForward(current_ea)
            
            current_ea = current_opcode.getAddress()
            
            inst = current_opcode.getDisasm()[:4]
            
            if inst == "SIDT":
                self.imm.Log("Found it!",address = current_opcode.getAddress())
                self.hook_addrs[current_ea] = ("idt",current_opcode)
                found_call = True
            elif inst == "SLDT":
                self.imm.Log("Found it!",address = current_opcode.getAddress())
                self.hook_addrs[current_ea] = ("ldt",current_opcode)
                found_call = True
            elif inst == "SGDT":
                self.imm.Log("Found it!",address = current_opcode.getAddress())
                self.hook_addrs[current_ea] = ("gdt",current_opcode)
                found_call = True
        
        return found_call        
        
        
    def dt_patch(self):
        """
        This function is responsible for patching the instructions
        that are issuing descriptor table address lookups. We simply
        do a MOV [R32], 0xCONSTANT at the address of the instruction.
        
        @raise:     mfx     An error is raised if we can't patch the instructions.
        @rtype:     Boolean
        @return:    True if the patches were applied successfully.
        """
                
        if self.os.lower() == "windowsxp":
            idt     =    WINXP_2003_IDT
            ldt     =    WINXP_2003_LDT
            gdt     =    WINXP_2003_GDT
        else:
            idt     =    WIN2000_IDT
            ldt     =    WIN2000_LDT
            gdt     =    WIN2000_GDT
        
        # Iterate through the addresses, and write 
        # the trickery
        for address in self.hook_addrs:
            
            # Create the stub where we will detour
            stub_address = self.imm.remoteVirtualAlloc(size=50)

            opcode = self.hook_addrs[address][1]
                        
            # Determine what we have to patch
            if self.hook_addrs[address][0] == "idt":
                patch_value = idt
            elif self.hook_addrs[address][0] == "gdt":
                patch_value = gdt
            elif self.hook_addrs[address][0] == "ldt":
                patch_value = ldt
            
                        
            # First we need to determine the length of the original
            # opcode, if the length is greater than 5 bytes, we need to 
            # preserve the instruction that follows it, the reason is
            # our JMP [ALLOC_ADDRESS] is 5 bytes long
            saved_instructions    =    None
            nop_sled              =    None
            
            if opcode.getSize() < 5:
                new_opcode = self.imm.disasmForward(address)
                saved_instructions = new_opcode.getDisasm()
                self.imm.Log("The length is going ot be an issue: %d" % opcode.getSize(), address = address)
                self.imm.Log("About to clobber: %s" % new_opcode.getDisasm(),address = new_opcode.getAddress())
            
                # It seems to be easier to NOP everything out first before
                # we write out the patch
                nop_sled = "\x90" * (opcode.getSize() + new_opcode.getSize())
                self.imm.writeMemory(address,nop_sled)
                
            # Now let's write the detour JMP to our allocated memory page
            detour_jmp     = self.imm.Assemble("JMP 0x%08x" % stub_address,address = address)
            detour_jmp_len = len(detour_jmp)
            
            self.imm.writeMemory(address,detour_jmp)
            
            # Now write out the patch header, we are just going to do a MOV on
            # the original SIDT/SLDT/SGDT instruction, directly into it's operand
            operand = opcode.getDisasm()[5:]
            register = operand.split("[")[1].split("]")[0]
            
            if opcode.getMemType() == MEM_TYPE_WORD and patch_value == ldt:
                patch_header = "MOV WORD PTR [%s],0x0000 \n" % register
            else:
                patch_header = "MOV DWORD PTR [%s],0x%08x \n" % (register,patch_value)
            
            
            # Now if we need to preserve some instructions from the original
            # basic block (because we clobbered them with our detour JMP)
            # write them out after the patch header
            if saved_instructions is not None:
                patch_body = new_opcode.getDisasm() + "\n"
            else:
                patch_body = "\n"

            # Write the return address
            # Now we want to do the JMP back to the original function
            # plus the size of our detour JMP instruction
            if nop_sled is not None:
                detour_ret = address + len(nop_sled)
            else:
                detour_ret = address + detour_jmp_len
                
            self.imm.Log("Detour Return: 0x%08x" % detour_ret)
            ret_jmp = "JMP 0x%08x \n" % detour_ret
            
            
            
            # Assemble the final patch
            final_patch = self.imm.Assemble(patch_header + patch_body + ret_jmp, address = stub_address)
            self.imm.Log("Final Patch: %s" % final_patch.encode("HEX"))
            self.imm.writeMemory(stub_address,final_patch)
          
            