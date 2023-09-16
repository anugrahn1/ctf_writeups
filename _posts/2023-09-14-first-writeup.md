---

title: "PatriotCTF 2023 Writeup"
permalink: "/pctf-2023-writeups"
---

Welcome to my first Writeup!

## PWN
---
<br/>
<br/>


# Guessing Game
Lets decompile using Ghidra and rename some variables:

![decompilation of binary](/assets/pctf2023/pwn/guessinggame/decompiled.png)

We can see that there is a vulnerable call to `gets` in line 13. We can also see in line 21 that the binary checks if `target` is not zero. If it isn't zero, we get the flag. 
<br/>
<br/>
`gets` will not check how long the user's input is and will store whatever input is given to it, on the [stack](https://eli.thegreenplace.net/2011/09/06/stack-frame-layout-on-x86-64/).  Since the `target` variable is on the stack as well, we can overwrite the variable and get the flag!
<br/>
<br/>
To find the number of characters we need to overwrite the `target` variable, we can look at the stack layout provided by Ghidra. To show this layout just click on any of the variables' declarations.

![stack layout of binary](/assets/pctf2023/pwn/guessinggame/stack_layout.png)
<br/>
<br/>

From this we can see that our input is stored at `$rbp-0x138` and `target` is stored at `$rbp-0xc`.
<br/>
<br/>
Subtracting 0xc from 0x140 gives us 308, which is how many bytes we need to write in order to overwrite the `target` variable. 
<br/>
<br/>

> ``NOTE:`` The `outputFlag()` function tries to open a file called flag.txt, so when testing locally, make sure to put a fake flag in the same directory as the binary.

Here is the final solve script:
<br/>
```
from pwn import *
context.binary = binary = ELF('./guessinggame')

#p = process()
p = remote('chal.pctf.competitivecyber.club', 9999)
payload = b'a'*308

p.sendline(payload)
p.interactive()
```

