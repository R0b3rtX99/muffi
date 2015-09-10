# Introduction #

This is just a whiplist of how to effectively name things when writing patches to the core muffi framework, or for submitting scripts, etc. It's not hard and fast, but realize that we will change your code to make sure its muffi-ized!

## Conventions ##

**_Method Names_**

Name all methods with lowercase and underscores:

method\_name\_like\_this()

**_Detour Addresses_**

When allocating a detour page, or a block of memory where we will write instructions use:

stub\_address

**_Resolved Function Addresses_**

When you are doing an imm.getAddress("kernel32.IsDebuggerPresent") type call, name your returned address:

function\_address

**_Writing to Memory_**

For task critical memory writes, make sure that you do a length check afterwards. Something like this:

```

bytes_written = self.imm.writeMemory(function_address,patch_code)

if bytes_written < len(patch_code):
    raise mfx("The memory write failed.")
```

Use bytes\_written as the variable name for these checks.