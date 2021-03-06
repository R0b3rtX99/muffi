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

from anti_debug        import *
from immlib            import *
from mfx               import *
from muffi_defines     import *
from patch_utils       import *
from vm_detect         import *

class muffi():
    '''
    This is the parent class which simply instantiates
    the helper classes. It encapsulates all of the 
    functionality within the framework.
    '''
    
    def __init__(self):
        
        self.anti_debug            =    anti_debug()
        self.patch_utils           =    patch_utils()
        self.vm_detect             =    vm_detect()