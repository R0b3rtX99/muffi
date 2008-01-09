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

class common_utils():
    """
    This class wraps a bunch of utilities that can be useful
    when analyzing binaries. All future utilities that are not
    patching utilities will be held here.
    """
    
    def __init__(self):
        
        self.imm        =    Debugger()
    
    
    def inject_dll(self,dll_path,hide_dll = False):
        """
        Pretty straightforward, this badboy will just inject a 
        DLL into the debuggee. We can also hide the DLL from the 
        debuggee, which is controlled by the optional hide_dll 
        parameter.
        
        @type    dll_path:    String
        @param   dll_path:    The path to the DLL you wish to inject, give full path with escaped slashes please.
        @type    hide_dll:    Boolean
        @param   hide_dll:    Whether to hide the DLL from the target process or not.
        
        @see: hide_dll()
        """
        
