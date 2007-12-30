'''
This is just a quick test to make sure the
core components are being initialized correctly.
'''

from immlib import *
from muffi  import *


def main(args):
    
    
    # Just instantiate muffi
    mf = muffi()
    
    mf.anti_debug.harness()
    mf.patch_utils.harness()
    
    return "Muffi Test Completed"