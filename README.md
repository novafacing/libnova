# libnova
The novafacing standard library but this time it's on PyPi

## What is this for?

Mostly pwntools and angr wrapper stuff so I can avoid retyping things constantly.
I also now only write strongly typed Python and I don't use strings for paths,
which doesn't sound like a huge change but things don't play nice! So here's my
compatibility.

## Example?

```python
from logging import getLogger
from pathlib import Path
from libnova import PW, PWMode

l = getLogger(__name__).info


b = Path("../src/target/debug/src")

x = PW(binary=b, mode=PWMode.DEBUG)

l(f"Loaded with {len(x.elf.symbols)} symbols")

x.sendline(b":q")
x.precvall()
```

The nice part is we get some really nice output from *everything* (you can't see the colors but they are there!):

```
...
INFO     | /home/novafa...a/pwn/pwn.py:0237 | Checksec info for library: ld-2.31.so
INFO     | /home/novafa...a/pwn/pwn.py:0239 | RELRO:    Partial RELRO
INFO     | /home/novafa...a/pwn/pwn.py:0239 | Stack:    No canary found
INFO     | /home/novafa...a/pwn/pwn.py:0239 | NX:       NX enabled
INFO     | /home/novafa...a/pwn/pwn.py:0239 | PIE:      PIE enabled
INFO     | /home/novafa...a/pwn/pwn.py:0241 | Checksec info for main object: src
INFO     | /home/novafa...a/pwn/pwn.py:0243 | RELRO:    Full RELRO
INFO     | /home/novafa...a/pwn/pwn.py:0243 | Stack:    No canary found
INFO     | /home/novafa...a/pwn/pwn.py:0243 | NX:       NX enabled
INFO     | /home/novafa...a/pwn/pwn.py:0243 | PIE:      PIE enabled
INFO     |                    __main__:0012 | Loaded with 1260 symbols
INFO     | pwnlib.tubes...365646789552:0298 | Receiving all data
INFO     | pwnlib.tubes...365646789552:0298 | Receiving all data: 0B
INFO     | pwnlib.tubes...365646789552:0298 | Receiving all data: 108B
INFO     | pwnlib.tubes...365646789552:0298 | Receiving all data: 136B
INFO     | pwnlib.tubes...365646789552:0298 | Process '/usr/local/bin/gdbserver' stopped with exit code 0 (pid 419479)
INFO     | pwnlib.tubes...365646789552:0298 | Receiving all data: Done (136B)
b'Welcome to the embedded programming simulator!\nOf course, you can only code using vim if you are 133...\nex: \nChild exited with status 0\n'
```
