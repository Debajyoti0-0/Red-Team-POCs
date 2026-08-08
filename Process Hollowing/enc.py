import sys
data = open('mimikatz.exe', 'rb').read()
enc = bytes([b ^ 0xBB for b in data])
open('mimikatz.exe.enc', 'wb').write(enc)
