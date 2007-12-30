'''
This is just a quick test to make sure the
core components are being initialized correctly.
'''

from immlib import *
from muffi  import *

def test_poly_eax_dword(imm,mf):
    imm.Log("[Test] poly_eax_dword:")
        
    instructions = mf.patch_utils.poly_eax_dword(value=0)
    imm.Log("[Test] Output: %s" % instructions.encode("HEX"))
    instructions = mf.patch_utils.poly_eax_dword()
    imm.Log("[Test] Output: %s" % instructions.encode("HEX"))
    instructions = mf.patch_utils.poly_eax_dword(flavor=1)
    imm.Log("[Test] Output: %s" % instructions.encode("HEX"))
    instructions = mf.patch_utils.poly_eax_dword(flavor=2)
    imm.Log("[Test] Output: %s" % instructions.encode("HEX"))
    instructions = mf.patch_utils.poly_eax_dword(flavor=3)
    imm.Log("[Test] Output: %s" % instructions.encode("HEX"))
    instructions = mf.patch_utils.poly_eax_dword(flavor=4)
    imm.Log("[Test] Output: %s" % instructions.encode("HEX")) 

def test_poly_eax_zero(imm,mf):
    imm.Log("[Test] poly_eax_zero:")
    
    instructions = mf.patch_utils.poly_eax_zero()
    imm.Log("[Test] Output: %s" % instructions.encode("HEX"))
    instructions = mf.patch_utils.poly_eax_zero(flavor=1)
    imm.Log("[Test] Output: %s" % instructions.encode("HEX"))
    instructions = mf.patch_utils.poly_eax_zero(flavor=2)
    imm.Log("[Test] Output: %s" % instructions.encode("HEX"))
    instructions = mf.patch_utils.poly_eax_zero(flavor=3)
    imm.Log("[Test] Output: %s" % instructions.encode("HEX"))
    instructions = mf.patch_utils.poly_eax_zero(flavor=4)
    imm.Log("[Test] Output: %s" % instructions.encode("HEX"))

def test_is_debugger_present(imm, mf):
    imm.Log("[Test] is_debugger_present:")
    
    test = mf.anti_debug.is_debugger_present()
    
    if test == True:
        imm.Log("[Test] is_debugger_present returned true.")
    else:
        imm.Log("[Fail] is_debugger_present call failed.")
        
        
def main(args):
    imm = Debugger()
    
    # Just instantiate muffi
    mf = muffi()
    
    # Call the default harnesses
    mf.anti_debug.harness()
    mf.patch_utils.harness()
    
    # Add test cases here in the form of test_[function_name]
    # Your test function should take imm, and mf instances for parameters
    test_poly_eax_dword(imm,mf)
    test_poly_eax_zero(imm,mf)
    test_is_debugger_present(imm,mf)
    
    return "Muffi Test Completed"