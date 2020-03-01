#!/usr/bin/env python3
 
from hashlib import sha256, blake2b
from base58check import b58encode
import nacl.signing
from sys import argv

edsklongprefix = bytes.fromhex('2bf64e07') # decimal is { (byte) 43, (byte) 246, (byte) 78, (byte) 7 };
edpkPrefix = bytes.fromhex('0d0f25d9') # decimal is { (byte) 13, (byte) 15, (byte) 37, (byte) 217 };
tz1prefix =  bytes.fromhex('06a19f') # decimal is { (byte) 6, (byte) 161, (byte) 159 };

while 1:
    signing_key = nacl.signing.SigningKey.generate()
    publicbytes = signing_key.verify_key.encode()

    blake2bhash = blake2b(publicbytes, digest_size=20).digest()
    shabytes = sha256(sha256(tz1prefix + blake2bhash).digest()).digest()[:4]
    pkhash = b58encode(tz1prefix + blake2bhash + shabytes).decode()

    if pkhash[3:len(argv[1])+3] == argv[1]:
        privatebytes = signing_key.encode() + publicbytes
        prefixedprivatebytes = edsklongprefix + privatebytes
        shabytes = sha256(sha256(prefixedprivatebytes).digest()).digest()[:4]
        edsk = b58encode(prefixedprivatebytes+shabytes).decode()
        print(edsk)
        print(pkhash)
        break
