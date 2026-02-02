# LEVEL0

## 1. Inspect The Executable

```
level0@RainFall:~$ ls -l
total 732
-rwsr-x---+ 1 level1 users 747441 Mar  6  2016 level0
```

We can see that the binary has the `s` bit set on the **execution permission** (instead of the usual `x`).

The **`s` bit** (setuid) means that during execution, the program **runs** with the **permissions** of its **owner**, here `level1` .
This is interesting because it allows us to potentially exploit the program to access files owned by `level1`.

```
level0@RainFall:~$ ./level0 
Segmentation fault (core dumped)
level0@RainFall:~$ ./level0 a
No !
level0@RainFall:~$ ./level0 test
No !
level0@RainFall:~$ ./level0 42
No !
```

The program expects **one argument**, and it appears that only a **specific value** is accepted.


## 2. Analyze The Executable

```
level0@RainFall:~$ strings level0 
-bash: /usr/bin/strings: Input/output error
level0@RainFall:~$ strace level0 
-bash: /usr/bin/strace: Input/output error
```

The VM (Virtual Machine) blocks several debugging and analysis tools such as `strings` and `strace`.

However, we can still use **gdb** (on the VM) and **Ghidra** (on the host machine) to **analyze** the binary.
- In **gdb**, we can **disassemble functions** using commands like `disas main`.
- In **Ghidra**, we can load the executable and obtain a **human-readable decompiled** version of the code in **pseudo-C**.

The full disassembly code is available in separate files:
- **Assembly code**: see the `gdb-dump` file.
- **Pseudo-C code**: see the `source` file.

### Program Behavior

The program takes the first argument (`argv[1]`), converts it to an integer using `atoi()`, and compares the result to a **constant value**.


If the result is equal to `0x1a7`, the program calls `execv()` with `/bin/sh`.
Because of the **setuid bit**, the shell is executed with **`level1` privileges**.
If the condition is not met, the program prints `"No !"` and exits.

## 3. Identify The Vulnerability

To read `/home/user/level1/.pass`, we need `level1` permissions, which we can obtain via the `execv()` call.
The **key condition** is the **comparison** before the `execv()` call.

In assembly:
```
0x08048ed9 <+25>:	cmp    $0x1a7,%eax
```

In pseudo-C:
```
  if (iVar1 == 0x1a7) {
```
(`iVar1` is the return value of `atoi(argv[1])`.)

Converting the hex value:
```
0x1a7 = 423
```
So the **program simply** expects the argument to be **423**.
This is known as a **magic number**: an arbitrary hardcoded constant and value used to control program flow or unlock specific functionality.

## 4. Capture The Flag

```
level0@RainFall:~$ ./level0 423
$ cat /home/user/level1/.pass
XXX
```