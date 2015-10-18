#!/usr/bin/env python3
# Author: SuperVirus

import base64


challenge = """
O4NA2DZZCNHCEWABDNHDUUY5KZCAOB2OFBJR2DY4JANAOKS2DJERAIANDQUBEBYF
CAIQOGZ7CIEBUUIPKJHCKUYNDVPR4DI4PQDRKV2VBENROYCRDQHUAHAHL56QGQYP
KUEQAE6RV3ZOVLHU6TZNDLXS5KWPJ5HS2GXPF2VM6T2PFUNO6LVKZ5HU6LI254XK
VT2PJ4WRV3ZOVLHU6TZNDLXS5KWPJ5HS2GXPF2VM6T2PFUNO6LVKZ5HU6LI254XK
VT2PJ4WRV3ZOVLHU6TZNDLXS5KWPJ5HS2GXPF2VM6T2PFUNO6LVKZ5HU6LI254XK
VT2PJ4WRV3ZOVLHU6TZNDLXS5KWPJ5HS2GXPF2VM6T2PFUNO6LVKZ5HU6LI254XK
""".replace('\n', '')


# Step 1: undo the base32 encoding
encrypted = base64.b32decode(challenge)

# Step 2: get the XORed intermediate key, this is possible because the
# cleartext is followd by a (long) padding
intermediatekey = encrypted[-8:]

# Step 3: decrypt the cyphertext using the intermediate key
xortext = bytearray()
for i in range(len(encrypted)):
    xortext += bytearray([encrypted[i] ^ intermediatekey[i%8]])

# Step 4: detect the padding byte and length and remove it
xortext = xortext.rstrip(xortext[-1:])

# Last step: undo the XOR with the padding length
padlen = len(encrypted) - len(xortext)
decrypted = bytearray()
for c in xortext:
    decrypted += bytearray([c ^ padlen])

# And print the result
print(decrypted.decode('latin1'))
