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
from ctypes        import *

"""
General Purpose Constants
"""
DWORD_ZERO                 =    "\x00\x00\x00\x00"
FUNCTION_RETURN            =    "\xc3"

"""
Anti-Debug Constants
"""
GENERIC_PATCH_VALUE        =    0xB0B1560D            # When generically patching a DWORD use this value.
LDR_DEBUG_FILL             =    "\xFE\xEE\xFE\xEE"    # When a ring3 debugger is attached, the LDR_DATA has a pile of 0xFEEEFEEE bytes

"""
Virtual Machine Detection Constants
"""
SIDT_OPCODE                =    "\x0f\x01\x4c"
SGDT_OPCODE                =    "\x0f\x01\x44"
SLDT_OPCODE                =    "\x0f\x00\x44"
WINXP_2003_IDT             =    0x8003F400    # Native IDT in Win XP/2003
WINXP_2003_LDT             =    0xDEAD0000    # Native LDT in Win XP/2003
WINXP_2003_GDT             =    0x8003F000    # Native GDT in Win XP/2003
WIN2000_IDT                =    0x80036400    # Native IDT in Windows 2000
WIN2000_LDT                =    0xDEAD0000    # Native LDT in Windows 2000
WIN2000_GDT                =    0x80036000    # Native GDT in Windows 2000
