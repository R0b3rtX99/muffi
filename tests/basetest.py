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
        
def test_patch_peb(imm,mf):
      
    imm.Log("[Test] patch_peb:")
    
    test = mf.anti_debug.patch_peb()
    
    if test == True:
        imm.Log("[Test] PEB patch succeeded")
    else:
        imm.Log("[Fail] PEB patch failed.")

def test_check_remote_debugger_present(imm,mf):
    
    imm.Log("[Test] check_remote_debugger_present:")
    
    test = mf.anti_debug.check_remote_debugger_present()
    
    if test == True:
        imm.Log("[Test] CheckRemoteDebuggerPresent patched successfully.")
    else:
        imm.Log("[Failed] CheckRemoteDebuggerPresent patch did not succeed.")      

def test_get_tick_count(imm,mf):
    
    imm.Log("[Test] get_tick_count:")
    
    test = mf.anti_debug.get_tick_count()
    
    if test == True:
        imm.Log("[Test] GetTickCount patched successfully.")
    else:
        imm.Log("[Failed] GetTickCount patch did not succeed.")

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
    test_patch_peb(imm,mf)
    test_check_remote_debugger_present(imm,mf)
    test_get_tick_count(imm,mf)
    
    return "Muffi Test Completed"