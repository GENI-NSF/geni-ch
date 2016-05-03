# ----------------------------------------------------------------------
# Copyright (c) 2016 Raytheon BBN Technologies
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and/or hardware specification (the "Work") to
# deal in the Work without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Work, and to permit persons to whom the Work
# is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Work.
#
# THE WORK IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE WORK OR THE USE OR OTHER DEALINGS
# IN THE WORK.
# ----------------------------------------------------------------------

import os
import subprocess
import sys
import tempfile
import time
from chapi_log import *


# Maintain a global cache of mappings of raw certs and cert files to keyid
class ABACKeyIdCache:

    def __init__(self):
        self.keyid_by_cert = {}
        self.keyid_by_cert_filename = {}
        self.timestamp_by_cert = {}
        self.timestamp_by_cert_filename = {}

    # Whether to print chapi_error log messages on cache actions
    VERBOSE = False

    # Max number of entries in either cache
    MAX_ENTRIES = 200

    # Max number of seconds since lookup we allow to remain in cache
    # (if we've gone past MAX_ENTRIES)
    CACHE_LIFETIME_SEC = 86400

    def dump(self):
        if ABACKeyIdCache.VERBOSE:
            chapi_error("KEY_ID", "KEYID_BY_CERT = %s" % self.keyid_by_cert)
            chapi_error("KEY_ID", "KEYID_BY_CERT_FILENAME = %s" % self.keyid_by_cert_filename)
            chapi_error("KEY_ID", "TS_BY_CERT = %s" % self.timestamp_by_cert)
            chapi_error("KEY_ID", "TS_BY_CERT_FILENAME = %s" % self.timestamp_by_cert_filename)

    # Prune entries in the given cache (cert or cert_filename)
    # If we have too many entries, delete all entries that haven't been looked up
    # in the last CACHE_LIFETIME_SEC seconds
    def prune(self, certkey_keyid_mapping, certkey_timestamp_mapping):
        # self.dump()
        certkey_to_delete = []
        time_limit = time.time() - ABACKeyIdCache.CACHE_LIFETIME_SEC
        if len(certkey_keyid_mapping) > ABACKeyIdCache.MAX_ENTRIES:
            for certkey in certkey_keyid_mapping:
                if certkey_timestamp_mapping[certkey] < time_limit:
                    certkey_to_delete.append(certkey)
        for certkey in certkey_to_delete:
            if ABACKeyIdCache.VERBOSE:
                chapi_error('KEY_ID', "Removing keyid from cache: %s" %
                            certkey_keyid_mapping[certkey])
                del certkey_keyid_mapping[certkey]
                del certkey_timestamp_mapping[certkey]

#        self.dump()

    # Lookup keyid from cert from cache. Return keyid or None if not cached
    def lookup_for_cert(self, cert):
        self.prune(self.keyid_by_cert, self.timestamp_by_cert)
        keyid = None
        if cert in self.keyid_by_cert:
            keyid = self.keyid_by_cert[cert]
            self.timestamp_by_cert[cert] = time.time()
            if ABACKeyIdCache.VERBOSE:
                chapi_error("KEY_ID", "Returning cached keyid : %s" % keyid)
        return keyid

    # Lookup keyid from cert_filename. Return keyid or None if not cached
    def lookup_for_cert_filename(self, cert_filename):
        self.prune(self.keyid_by_cert_filename, self.timestamp_by_cert_filename)
        keyid = None
        if cert_filename in self.keyid_by_cert_filename:
            keyid = self.keyid_by_cert_filename[cert_filename]
            self.timestamp_by_cert_filename[cert_filename] = time.time()
            if ABACKeyIdCache.VERBOSE:
                chapi_error("KEY_ID", "Returning cached keyid %s for file %s" %
                            (keyid, cert_filename))
        return keyid

    # Register relationship between raw cert and keyid
    def register_cert(self, cert, keyid):
        if ABACKeyIdCache.VERBOSE:
            chapi_error("KEY_ID", "Registering keyid %s for cert" % keyid)
        self.keyid_by_cert[cert] = keyid
        self.timestamp_by_cert[cert] = time.time()

    # Register relationship between cert_filename and keyid
    def register_cert_filename(self, cert_filename, keyid):
        if ABACKeyIdCache.VERBOSE:
            chapi_error("KEY_ID", "Registering keyid %s for certfile %s" %
                        (keyid, cert_filename))
        self.keyid_by_cert_filename[cert_filename] = keyid
        self.timestamp_by_cert_filename[cert_filename] = time.time()

ABAC_KEYID_CACHE = ABACKeyIdCache()  # Singleton instance


# Compute the ABAC keyid of a raw cert
# Check if cert is in cert, if so return kdyid
# Otherwise write cert to temp file, compute key id
# store keyid in cache by cert, return key_id
def compute_keyid_from_cert(cert, cert_filename):
    keyid = ABAC_KEYID_CACHE.lookup_for_cert(cert)
    if not keyid:
        keyid = compute_keyid_from_cert_file(cert_filename)
        ABAC_KEYID_CACHE.register_cert(cert, keyid)
    return keyid


# Compute the ABAC keyid of a cert file
# Compute the sha1 of the DER of bits of the public key in the cert
# Essentially, we're running this script:
#
# openssl x509 -pubkey -noout -in $1 > $1.pubkey.pem
# openssl asn1parse -in $1.pubkey.pem -strparse 18 -out $1.pubkey.der
#
def compute_keyid_from_cert_file(cert_filename):

    keyid = ABAC_KEYID_CACHE.lookup_for_cert_filename(cert_filename)
    if keyid:
        return keyid

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
        # print " LINE = " + line
        if "BIT STRING" in line:
            parts = line.strip().split(':')
            bit_string_start = parts[0]
#            print "BIT_STRING_START = " + bit_string_start
            break

    if bit_string_start is None:
        print "Can't find start of bit string in key asn1parse output"
        sys.exit(0)

    # Parse the keyfile starting at the bit string start and save as der file
    derfile = tempfile.NamedTemporaryFile(delete=False)
#    print "DERFILE = " + derfile.name
    args = ['openssl', 'asn1parse', '-in', keyfile.name, '-strparse',
            bit_string_start, '-out', derfile.name]
    output = subprocess.check_output(args)

    # Compute the SHA1 hash of the DER file of the public key bits
    args = ['openssl', 'sha1', '-c', derfile.name]
    output = subprocess.check_output(args)
    parts = output.strip().split("= ")
    keyid = parts[1]
    # Replace ':' separators if they are in the returned SHA
    keyid = keyid.replace(':', '')

    ABAC_KEYID_CACHE.register_cert_filename(cert_filename, keyid)

    os.unlink(derfile.name)
    os.unlink(keyfile.name)

    return keyid

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Usage: keyid.py x509cert.pem"
        sys.exit(0)
#    keyid = compute_keyid(sys.argv[1])
    print "KEYID = " + keyid
