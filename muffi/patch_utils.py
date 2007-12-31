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

from mfx                   import *
from muffi_defines         import *
from patch_utils           import *
from immlib                import *


class patch_utils():
    """
    This high-level class exposes methods for various 
    patching and poly-patching routines. Unless specifically 
    stated otherwise, most of this is BoB's work.
    """
    
    def __init__(self):
        
        self.imm            = Debugger()
    
        
    def poly_eax_dword(self, value=GENERIC_PATCH_VALUE, flavor=0):
        """
        This function will create a polymorphic set of instructions
        to write out the opcode bytes that will set EAX to a DWORD
        value. The flavor parameter is important, the smaller the
        flavor index the smaller the size of the patch.
        
        @type  value:   DWORD
        @param value:   (Optional) The value that the DWORD in EAX should be.
        @type  flavor:  INTEGER
        @param flavor:  (Optional) The flavor dictates what style of DWORD patch should be applied. Randomized if left as default value.
        
        @raise mfx: An exception is raised on failure.
        
        @return:        Returns the instructions for poly-patching EAX.
        """       
        
        # If the flavor was untouched, then randomize the patch
        if flavor == 0:
            # If you add additional patches make sure to
            # increase the second parameter in randint()
            flavor = random.randint(1, 4)

        # Using a PUSH/POP routine for the patch.        
        # Size: 6 bytes
        if flavor == 1:
            return self.imm.Assemble( "Push 0x%08x\n Pop EAX\n" % value )

        # Using SUB/ADD to create the patch.
        # Size: 7 bytes
        if flavor == 2:
            if random.randint(1, 2) == 1:
                return self.imm.Assemble( "Sub EAX, EAX\n Add EAX, 0x%08x" % value )
            else:
                return self.imm.Assemble( "Sub EAX, EAX\n Sub EAX, -0x%08x" % value )
        
        # Use an optimized XChg routine
        # Size: 7 bytes
        if flavor == 3:
            return self.imm.Assemble( "XChg EAX, EDI\n DB 0xBF\n DD 0x%08x\n XChg EAX, EDI" % value )
        
        # Use a non-optimized XChg routine
        # Size: 8 bytes
        if flavor == 4:
            return self.imm.Assemble( "XChg EAX, EDI\n Mov EDI, 0x%08x\n XChg EAX, EDI" % value )

    
    def poly_eax_zero(self, flavor=0):
        '''
        This function creates a polymorphic set of instructions
        that zeroes out the EAX register.        
        
        @type  flavor:  INTEGER
        @param flavor:  (Optional) The flavor dictates what style of patch is generated to zero out EAX.
                
        @raise mfx: An exception is raised on failure.
        
        @return:        Returns the instructions for poly-patching an EAX = 0.
        '''   
        
        # check the flavor if it's untouched
        # then randomize it
        if flavor == 0:
            flavor = random.randint(1, 4)
        
        # Size: 2 bytes
        if flavor == 1:
            return self.imm.Assemble("Sub EAX, EAX")
        
        # Size: 3 bytes
        if flavor == 2:
            return self.imm.Assemble("DB 0x6A, 0x00\n Pop EAX")
        
        # Size: 4 bytes
        if flavor == 3:
            return self.imm.Assemble("XChg EAX, EDI\n Sub EDI, EDI\n XChg EAX, EDI")
        
        # Size: 6 bytes
        if flavor == 4:
            return self.imm.Assemble("Push 0\n Pop EAX")
        
        # With this flavor we simply call poly_eax_dword
        # with the patch value set to zero.
        # Size: variant
        if flavor == 5:
            return poly_eax_dword(value = 0)


    def harness(self):
        '''
        Standard harness for testing new functionality
        as we build it. This is kept in the final release
        so that developers can test their patches before
        we commit them.
        '''
        
        self.imm.Log("[*] Patch utilities harness function called.")
                              