#! /usr/bin/python3

from base64 import b64encode

def hexToB64(s):
    decoded = bytes.fromhex(s)
    return b64encode(decoded)

if __name__ == "__main__":
    hexstr = input("Enter binary string in hex: ")
    print(f'Base-64 encoded: {hexToB64(hexstr)}')
