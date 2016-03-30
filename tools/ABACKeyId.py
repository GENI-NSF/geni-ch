#!/usr/bin/python
import os
import subprocess
import sys
import tempfile

# Compute the ABAC keyid of a cert
# Compute the sha1 of the DER of bits of the public key in the cert
# Essentially, we're running this script:
#
# openssl x509 -pubkey -noout -in $1 > $1.pubkey.pem
# openssl asn1parse -in $1.pubkey.pem -strparse 18 -out $1.pubkey.der
# openssl sha1 $1.pubkey.der 
#
def compute_keyid(cert_filename):
#    print "FILENAME = " + cert_filename

    # Get the public key from the cert
    # Run openssl x509 -pubkey -noout -in cert_filename -out pubkey.out
    args = ['openssl', 'x509', '-pubkey', '-noout', '-in', cert_filename]
    public_key = subprocess.check_output(args)
#    print "PK = " + public_key
    keyfile = tempfile.NamedTemporaryFile(delete=False)
#    print "KEYFILE = " + keyfile.name
    keyfile.write(public_key)
    keyfile.close()

    # Parse the keyfile and determine where the bit string starts
    args = ['openssl', 'asn1parse', '-in', keyfile.name]
    output = subprocess.check_output(args)
#    print "OUTPUT = " + output
    lines = output.split("\n")
    bit_string_start = None
    for line in lines:
#        print " LINE = " + line
        if "BIT STRING" in line:
            parts = line.strip().split(':')
            bit_string_start = parts[0]
#            print "BIT_STRING_START = " + bit_string_start
            break

    if bit_string_start == None:
        print "Can't find start of bit string in key asn1parse output"
        sys.exit(0)

    # Parse the keyfile starting at the bit string start and save as der file
    derfile = tempfile.NamedTemporaryFile(delete=False)
#    print "DERFILE = " + derfile.name
    args = ['openssl',  'asn1parse', '-in', keyfile.name, '-strparse', bit_string_start, 
            '-out', derfile.name]
    output = subprocess.check_output(args)

    # Compute the SHA1 hash of the DER file of the public key bits
    args = ['openssl', 'sha1', '-c', derfile.name]
    output = subprocess.check_output(args)
    parts = output.strip().split("= ")
    keyid = parts[1]
    return keyid

    os.unlink(derfile.name)
    os.unlink(keyfile.name)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Usage: keyid.py x509cert.pem"
        sys.exit(0)
    keyid = compute_keyid(sys.argv[1])
    print "KEYID = " + keyid

