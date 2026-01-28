# LEVEL6

## 1. Inspect The Executable

```bash
level6@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 level7 users 5274 Mar  6  2016 level6
```

We can see that the binary has the `s` bit set on the **execution permission**, which means the program will run with level7 privileges.

```bash
level6@RainFall:~$ ./level6 
Segmentation fault (core dumped)
level6@RainFall:~$ ./level6 a
Nope
level6@RainFall:~$ ./level6 a a
Nope
level6@RainFall:~$ ./level6 a a a
Nope
level6@RainFall:~$ ./level6 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Nope
```

The program takes the argument, and prints "Nope" most of the time. 

```bash
level6@RainFall:~$ ./level6 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Nope
level6@RainFall:~$ ./level6 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Segmentation fault (core dumped)
level6@RainFall:~$ ./level6 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Segmentation fault (core dumped)
```

These tests indicate a **buffer overflow vulnerability** (here triggered with 72 `a` characters), meaning there is **no protection** on the input buffer.

## 2. Analyze The Executable

blablabla

```
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
