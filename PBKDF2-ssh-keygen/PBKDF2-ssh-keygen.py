#!/usr/bin/env python
# by xychix[at]hotmail.com 4 Nov 2016
#
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
import sys
from os import chmod
password = sys.argv[1]
salt = "VeryInsecure-sshkeygen"     # replace with random salt if you can store one
master_key = PBKDF2(password, salt, count=1000)  # bigger count = better
def my_rand(n):
    my_rand.counter+=1
    return PBKDF2(master_key, "my_rand:%s" % my_rand.counter, dkLen=n, count=1)
my_rand.counter = 0
print("""
This script wil generate an ssh key from a password. This way you can use key's on
non-persistent machines. However I've seen different keys from the same password.
Make sure you run this atleast once on a persistent (offline) machine to save the 
keys for emergency recovery.

""")
key = RSA.generate(2048, randfunc=my_rand,e=65537)
pubkey = key.publickey()
print("your public key:\n%s"%pubkey.exportKey('OpenSSH'))

with open("insecure_rsa", 'w') as content_file:
    chmod("insecure_rsa", 0600)
    content_file.write(key.exportKey('PEM'))
with open("insecure_rsa.pub", 'w') as content_file:
    content_file.write(pubkey.exportKey('OpenSSH'))



