import os
from qrcode import *
import argparse
import sys
import hmac, base64, struct, hashlib, time

def get_hotp_token(secret, intervals_no):
    key = base64.b32decode(secret, True)
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = ord(h[19]) & 15
    h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    return h

def get_totp_token(secret):
    return get_hotp_token(secret, intervals_no=int(time.time())//30)

def generate_qr():
    img = qrcode.make("text in here")
    #return

def get_otp():
    secret = 'MZXW633PN5XW6MZX'
    for i in range(0, 10):
        print (i, get_hotp_token(secret, intervals_no=i))

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("-qr", "--generate-qr", help="generate qr code", action="store_true")
    parser.add_argument("-otp", "--get-otp", help="get otp code", action="store_true")

    args = parser.parse_args

    if args.qr:
        generate_qr()
    if args.otp:
        get_otp()

if __name__ == "__main__":
    main()