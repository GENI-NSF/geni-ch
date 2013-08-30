#----------------------------------------------------------------------
# Copyright (c) 2011-2013 Raytheon BBN Technologies
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
#----------------------------------------------------------------------

import sfa.trust.certificate

# A set of utilities to pull infomration out of X509 certs

# Pull the certificate from the speaks-for credential
def get_cert_from_credential(cred):
    start_tag = '<X509Certificate>'
    end_tag = '</X509Certificate>'
    start_index = cred.find(start_tag)
    end_index = cred.find(end_tag)
    raw_cert = cred[start_index+len(start_tag):end_index]
    cert_string = '-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----' % raw_cert
    return cert_string

# Pull out the UUID from the certificate
def get_uuid_from_cert(cert):
    cert_object = sfa.trust.certificate.Certificate(string=cert)
    subject_alt_names = cert_object.get_extension('subjectAltName')
    san_parts = subject_alt_names.split(',')
    uuid = None
    for san_part in san_parts:
        san_part = san_part.strip()
        if san_part.startswith('URI:urn:uuid'):
            uuid = san_part[13:]
            break
    return uuid

# Pull out the URN from the certificate
def get_urn_from_cert(cert):
    cert_object = sfa.trust.certificate.Certificate(string=cert)
    subject_alt_names = cert_object.get_extension('subjectAltName')
    san_parts = subject_alt_names.split(',')
    urn = None
    for san_part in san_parts:
        san_part = san_part.strip()
        if san_part.startswith('URI:urn:publicid'):
            urn = san_part[4:]
            break
    return urn
