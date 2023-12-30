# ASIS CTF Final 2023

I joined ASIS CTF Final 2023 as a member of Wani Hackase, solving problems in the reversing category.

## Easy Risky

Simply run the binary provided and the flag is printed, but "simply" is not so simple.

The "problem" is that the binary provided is for RISC-V architecture and I have no RISC-V computer. It would be possible to purchase a VisionFive 2, but it wouldn't arrive in time. Fortunately, [QEMU supports RISC-V](https://www.qemu.org/docs/master/about/emulation.html) and [Ubuntu provides pre-built images for RISC-V](https://ubuntu.com/download/risc-v), so all that is needed is to download the pre-built image for QEMU and follow the [instructions](https://wiki.ubuntu.com/RISC-V/QEMU) and we can get the flag.

Flag: `ASIS{7rY_tO_rUn_M3_oN_RISC-V64_m4cH!nE!!}`

## Dadci

This time we have a x86 binary. However, we do not need to run this binary.

Taking a look at the binary, we see that the binary makes use of a QR code generation library because of the error messages. (The function name below is changed manually.)

![Dadci Screenshot 1.png](Dadci%20Screenshot%201.png)

There are two difficult parts of this problem: the requirement to identify the source code of the QR code library, and to understand how the flag is transformed. The QR code library is probably [`nayuki/QR-Code-generator`](https://github.com/nayuki/QR-Code-generator/tree/master), which allows us to separate the code that is a part of the library and the code that is a part of the transformation.

After that, it is simply a matter of reading the `main` function and changing the variable to something that is readable. Several features used include

- <kbd>L</kbd> for changing variable names
- `Cmd+L` for changing variable types
- <kbd>;</kbd> for adding comments
- `Split Out As New Variable` for separating each use of reused variables
  which when used probably can help us obtain a readable decompiled result.

![Dadci Screenshot 2.png](Dadci%20Screenshot%202.png)

The transformation applied is then as follows:

- `flag` is read from `flag.txt`.
- `buf0` is the QR code generated from flag.
- `qrsize` is the size of the QR code.
- `buf1` is the QR code in `'0'` and `'1'`, but each character is duplicated.
- `buf2` is a pattern generated using `qrsize`.
- `buf3` is the XOR of `buf1` and `buf2`.
- `buf4` is the concatenated version of `buf3`.
- `buf5` is `buf4` with padding
- Each 8 bytes of `buf5`, containing only `'0'` and `'1'`, is parsed as a binary number and written to the output as `char`.

To reverse the process, we need to first find the size (side length) of the QR code. The output is 343 bytes, and $\sqrt{\frac{343 \cdot 8}{2}} \approx 37.04$ . We know that the size of the QR code must be odd, so 37 makes sense.

Then we write a Python script to reverse the entire process.

```python
with open("flag.enc", "rb") as f:
    flag_enc = f.read()

def genpattern(size):
    pat = []
    bn1 = 1 << (size - 1)
    for i in range(size):
        patline = []
        for j in range(2 * size - 1, -1, -1):
            patline.append(
                (bn1 >> j) & 1
            )
        pat.append(patline)
        bn2 = bn1 >> 1
        bn3 = bn1 << 1
        bn5 = bn1 | bn3
        bn1 = bn2 ^ bn5
    return pat

qrsize = 37

buf5 = [0] * (len(flag_enc) * 8)
buf4 = [0] * (qrsize * qrsize * 2)

for i in range(len(flag_enc)):
    for j in range(8):
        buf5[i * 8 + j] = (flag_enc[i] >> (7 - j)) & 1

rem = len(buf5) - len(buf4)
assert rem >= 0

buf4 = buf5[rem:]
assert len(buf4) == qrsize * qrsize * 2

buf3 = [[] for i in range(qrsize)]

for i in range(qrsize):
    buf3[i] = buf4[i * qrsize * 2 : (i + 1) * qrsize * 2]

buf2 = genpattern(qrsize)

assert len(buf2) == len(buf3)
assert len(buf2[0]) == len(buf3[0])

buf = [[] for i in range(qrsize)]
for i in range(qrsize):
    for j in range(len(buf2[0])):
        buf[i].append(buf2[i][j] ^ buf3[i][j])

for i in range(qrsize):
    for j in range(0, len(buf[0]), 2):
        assert buf[i][j] == buf[i][j + 1], f"buf[{i}][{j}] == buf[{i}][{j + 1}]"

qr = []
for i in range(qrsize):
    qr.append(buf[i][::2])

for i in range(qrsize):
    for j in range(qrsize):
        print("██" if qr[i][j] else "  ", end="")
    print("")
```

![Dadci QR code.png](./Dadci%20QR%20code.png)

Scan the QR code with any QR code reader, and the flag is `ASIS{X0R_1s_4m4z1n9_But_qR_1s_1337!X0R_w17h_qR_4nd_937_cr34t1v3!L3v3l_Up_w17h_1mp4ctful_t3xts!}`.

## Solron

Solron is an ARM binary. Fortunately, this problem is also doable without running the binary.

We read the binary, and see that the following transformation is applied:

- An array of numbers $A$ is generated.
- The flag $F$ is read from the file.
- Each 5 characters (40 bits) $F[5i], \dots, F[5i+4]$ of the flag corresponds to whether to add $A[i]$ to $B[i]$ or not.
- $A$ and $B$ are interleaved and output.

Here, we can see that $A$ is the basis and $B$ is an element of the space spanned by $A$ where the coordinates must be in $\{0, 1\}$. We need to recover the coordinates in order to recover the flag.

To recover the flag, first we use C++ to extract the coordinates. We use baby-step giant-step (maybe also meet in the middle?) to speed up the computation.

```c++
#include <bits/stdc++.h>
using namespace std;

long long output[] = {20482387330, 220179052945, 221599562964, 444619635947, 890659781913, 1792683643978, 2347216352402, 2609645511581, 3572582697785, 6032978850744, 6650475000967, 6897582192128, 7203406306349, 8152120364717, 8199094738496, 9471922805862, 11643743283942, 12368643406675, 13007638866703, 14034687311267, 14378402412318, 14879186769676, 16995696561353, 18193262052213, 20848327273257, 22561153986096, 23925295566415, 25808097631864, 28701550533997, 28771492424308, 28986927447714, 33047669078852, 34999786772450, 38696243811282, 38967439719263, 39401807925258, 39525984254490, 40196286962541, 44273488962403, 45844305601939, 299624312887295, 300168950700057, 310857710617980, 314186202343305, 317640875233415, 318132162847387, 324405153827667, 325423198510227, 337567063468323, 344134140428421, 346704121949466, 367271938492043, 379136577196018, 381976419575618, 391025233794614, 413813486118251};

typedef vector<pair<long long, int>> precomp;

precomp pre_left, pre_right;

precomp extend(precomp p, long long x, int shift) {
    long long N = p.size();
    for (int i = 0; i < N; i++) {
        p.push_back({ p[i].first + x, p[i].second | (1ll << shift) });
    }
    sort(p.begin(), p.end());
    for (int i = 0; i < 2 * N - 1; i++) {
        if (p[i].first == p[i + 1].first) {
            printf("Duplicate for %lld\n", i);
            exit(1);
        }
    }
    return p;
}


int main() {
    int N = sizeof(output) / sizeof(long long);
    pre_left.push_back({0, 0});
    pre_right.push_back({0, 0});
    for (int i = 0; i < N; i++) {
        long long t = output[i];
        auto ptr2 = pre_right.rbegin();

        precomp::iterator ans1;
        precomp::reverse_iterator ans2;
        bool found = false;

        for (auto ptr1 = pre_left.begin(); ptr1 != pre_left.end(); ptr1++) {
            while (ptr2 != pre_right.rend() && ptr1->first + ptr2->first > t) {
                ptr2++;
            }
            if (ptr2 == pre_right.rend()) {
                break;
            }
            if (ptr1->first + ptr2->first == t) {
                ans1 = ptr1;
                ans2 = ptr2;
                found = true;
                break;
            }
        }

        printf("%d / %d: ", i + 1, N);

        if (found) {
            printf("%lld is generated: %lld (%d), %lld (%d)\n", t, ans1->first, ans1->second, ans2->first, ans2->second);
        } else {
            printf("%lld is basis\n", t);
        }

        if (i % 2 == 0) {
            pre_left = extend(pre_left, t, i / 2);
        } else {
            pre_right = extend(pre_right, t, i / 2);
        }
    }
}
```

Then, we use Python to actually extract the flag.

```python
output = [220179052945, 221599562964, 444619635947, 344134140428421, 391025233794614, 890659781913, 1792683643978, 3572582697785, 413813486118251, 367271938492043, 381976419575618, 7203406306349, 337567063468323, 379136577196018, 324405153827667, 310857710617980, 14378402412318, 346704121949466, 28986927447714, 318132162847387, 299624312887295, 11643743283942, 23925295566415, 314186202343305, 2347216352402, 317640875233415, 6650475000967, 325423198510227, 300168950700057, 16995696561353, 38967439719263, 34999786772450, 33047669078852, 6032978850744, 28701550533997, 39525984254490, 39401807925258, 40196286962541, 20482387330, 6897582192128, 18193262052213, 14034687311267, 38696243811282, 28771492424308, 22561153986096, 12368643406675, 14879186769676, 44273488962403, 25808097631864, 9471922805862, 13007638866703, 2609645511581, 8199094738496, 20848327273257, 8152120364717, 45844305601939]

basis = [i for i in output if i <= 45844305601939]
sorted_basis = sorted(basis)
output = [i for i in output if i > 45844305601939]

basis1 = sorted_basis[::2]
basis2 = sorted_basis[1::2]

precomp = {
    299624312887295: (881581, 65750),
    300168950700057: (620230, 589992),
    310857710617980: (221102, 136118),
    314186202343305: (291638, 595874),
    317640875233415: (286582, 333700),
    318132162847387: (330519, 922546),
    324405153827667: (865171, 213140),
    325423198510227: (223046, 606842),
    337567063468323: (355252, 594834),
    344134140428421: (722826, 673528),
    346704121949466: (355638, 595874),
    367271938492043: (605082, 463604),
    379136577196018: (816626, 804568),
    381976419575618: (883084, 284578),
    391025233794614: (615219, 984924),
    413813486118251: (618703, 1003738),
}

def decode(t):
    mask1, mask2 = precomp[t]
    s = ["0"] * 40
    for i in range(len(basis1)):
        j = basis.index(basis1[i])
        if (mask1 >> i) & 1:
            s[j] = "1"
    for i in range(len(basis2)):
        j = basis.index(basis2[i])
        if (mask2 >> i) & 1:
            s[j] = "1"
    s = "".join(s)
    a, b, c, d, e = s[0:8], s[8:16], s[16:24], s[24:32], s[32:40]
    a = int(a, 2)
    b = int(b, 2)
    c = int(c, 2)
    d = int(d, 2)
    e = int(e, 2)
    return chr(a) + chr(b) + chr(c) + chr(d) + chr(e)

def is_sorted(l):
    return all(l[i] <= l[i+1] for i in range(len(l) - 1))

print("".join([decode(i) for i in output]))
```

The flag is `ASIS{Ling3r1n9_LuMin0u5_L4mpliGhtS_LaZ1ly_iLlum1nAtE_La8yr!nth1ne_L4ndscap3S!!!}`.
