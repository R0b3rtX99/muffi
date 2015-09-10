# Introduction #

muffi is a framework for analyzing malware, bypassing anti-debugging techniques, and reversing packed executables. This is a simple walkthrough on how to get the muffi framework installed, and how to use a simple anti-debugging bypass.


## Requirements ##

[Immunity Debugger](http://debugger.immunityinc.com)

Python 2.5 (installer is included with Immunity Debugger)

## Installing muffi ##

The best option is to obtain the muffi framework from the SVN repository. When we have a stable release, it will be tagged in SVN and added to the Downloads page. Until then, grab the SVN trunk\muffi directory.

Once you have obtained the muffi directory, drop it in the PyCommands folder in %ImmunityDebuggerInstallPath%\PyCommands

## Using muffi ##

muffi is designed to allow the reverse engineer to easily create scripts specifically for analyzing malware or packed executables. The parent class is split into sub-classes which perform various tasks such as bypassing anti-debugging tricks, patching utilities, and many more features to come.

You write a muffi script just like any other PyCommand for Immunity Debugger. Below is an example of how to apply a polymorphic IsDebuggerPresent() patch:

```

from immlib import *
from muffi  import *

def main(args):
    
    # Instantiate the debugger
    imm = Debugger()

    # Instantiate muffi
    mf = muffi()

    # Apply the IsDebuggerPresent patch
    if mf.anti_debug.is_debugger_present():
        imm.Log("Successfully patched kernel32.IsDebuggerPresent")

    return "muffi - Patching complete."

```

Save this file as **muffi\_test.py** in your PyCommands directory. A test harness for this can be downloaded from [OpenRCE.org](http://www.openrce.org/) right [here](http://http://www.openrce.org/reference_library/files/anti_reversing/IsDebuggerPresent.zip).

Load the executable in Immunity Debugger, and from the command bar (located at the bottom of the debugger), issue

`!muffi_test`

Then run the executable, it should report that no debugger was detected.

Combining the power of immlib and muffi you are able to use any of the techniques from within hooks, or chain them together, or anything you choose! If you discover new techniques or wish to contribute to the project email Justin or BoB.