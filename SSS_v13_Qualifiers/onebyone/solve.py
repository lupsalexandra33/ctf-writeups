from pwn import *

# deactivate unnecessary log messages
context.log_level = 'error'

def solve():
    # loading the binary
    elf = ELF('./one_by_one')

    flag = {}

    # in this for loop, we are looking for all the symbols containing 'part'
    for sym_name in elf.symbols:
        if 'part' in sym_name:
            # extract the index
            try:
                idx = int(sym_name.replace('part', ''))
                # reading 1 byte from the address
                val = elf.read(elf.symbols[sym_name], 1)
                flag[idx] = chr(val[0])
            except:
                continue

    # sort after index to assemble the flag
    result = "".join([flag[i] for i in sorted(flag.keys())])
    print(f"Flag: {result}")

if __name__ == "__main__":
    solve()