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

## Program Behavior

#### main function


The `main` function calls `v()` then return.

### v function 

The `v` function first calls `fgets()` on `stdout` to store the input in a local variable `level_20c` with a size limit of `0x200` (i.e 512 in hexadecimal).

Then it's check if a unknow variable (probably gobal) `m` is equal to `0x40` (i.e 64 in hexadecimal). If the condition is `true`, the program prints `Wait what?!\n` and call `system("/bin/sh")`.

Then returns.


## 3. Exploit Development

Here we cannot execute a overflow on the stack from the input, because of the `fgets()` that secure this sort of attack with a limited size.

Here we have to exploit `printf()`.

### Discover `printf` Exploit

The exploit is possible because of this line :
```c
  printf(local_20c);
```

By directly taking the variable in argument (instead of the usual in `printf("%s", local_20c);`), it is possible to put some "printf instruction".
For example : `%x` that prints and pops the first element in the stack.

---

### Exploit Principle

Here the exploit structure:
```
<memory address to update>	<buffer>	<%X\$n> (X being the place in the stack of the memory to affect)
						  |	total being value of the update	|
```

### Investigate

First we are gonna use the `%x` to found where in the stack is our input:
```bash
level3@RainFall:~$ python -c "print 'aaaa' + '%x %x %x %x %x %x' " | ./level3 
aaaa200 b7fd1ac0 b7ff37d0 61616161 25207825 78252078
```

`aaaa` in hexadecimal `61616161`, can be found at the 4th place.

Secondary, we need to found 



```s
   0x080484da <+54>:	mov    0x804988c,%eax
   0x080484df <+59>:	cmp    $0x40,%eax
```

## 3.

```
```

**Explanation:**
- ``				: blablabla.
- `` 				: blablabla.
- `` 				: blablabla.

## 4.

```
```

**Explanation:**
- ``				: blablabla.
- `` 				: blablabla.
- `` 				: blablabla.

## 4. Get The Flag

```bash
> su flagXX
Password: 
Don't forget to launch getflag !

> getflag
Check flag.Here is your token : XXX
```
