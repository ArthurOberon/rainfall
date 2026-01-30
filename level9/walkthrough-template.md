# LEVEL9

## 1. Inspect The Executable

```bash
level9@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 bonus0 users 6720 Mar  6  2016 level9
```

We can see that the binary has the `s` bit set on the **execution permission**, which means the program will run with bonus0 privileges.

```bash
level9@RainFall:~$ ./level9 
level9@RainFall:~$ ./level9 a
level9@RainFall:~$ ./level9 a a
level9@RainFall:~$ ./level9 aaaaaaaaaaaaa a
level9@RainFall:~$ ./level9 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa a
```

The program do nothing at first sights. 


```bash
level9@RainFall:~$ ./level9 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa a
level9@RainFall:~$ ./level9 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa a
level9@RainFall:~$ ./level9 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa a
Segmentation fault (core dumped)
```

These tests indicate a **buffer overflow vulnerability** (here triggered with 109 `a` characters), meaning there is probably **no protection** on the input buffer.

## 2. Analyze The Executable

```bash
(gdb) info functions
All defined functions:

Non-debugging symbols:
[...]
0x080485f4  main
[...]
0x080486f6  N::N(int)
0x080486f6  N::N(int)
0x0804870e  N::setAnnotation(char*)
0x0804873a  N::operator+(N&)
0x0804874e  N::operator-(N&)
[...]
```

Using the gdb command `info functions`, we can list all functions present in the binary.
Here, we find the `main function` and an important information, there is a class, this must be a C++ program.

This class is called `N`, and it gots 5 functions:
- `N::N(int)` : A ?
- `N::N(int)` : A ?
- `N::setAnnotation(char*)` : A method. 
- `N::operator+(N&)` : An operator + to add 2 class `N`.
- `N::operator-(N&)` : An operator - to reduce 2 class `N`.

### Program Behavior

#### main function

#### N(int) function

#### N:setAnnotation function

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
