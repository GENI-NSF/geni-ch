#!/usr/bin/env python
# ----------------------------------------------------------------------
# Copyright (c) 2013-2016 Raytheon BBN Technologies
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

# A tool to extract values from JSON files
# Intended for facilitating unit testing (getting output from client.py, e.g.)
#
# Usage: json_extractor.py keys filename
# where
#  keys is a comma-separated list of
#      dictionary keys (Lookup the value for key f and continue)
#      key=value pairs (for finding a dictionary in a list of dictionaries)
#
# Thus for JSON containing:
#
# {"a": [{"name": "foo", "value": "bar"},
#        {"name": "boo", "value": "baz"}],
#  "b" : "3"}
#
# json_extractor.py a,name=foo,value => bar
# json_extractor.py b => 3

import json
import sys


def main():
    if len(sys.argv) <= 2:
        print "Usage: json_extractor.py keys filename"
        sys.exit(1)

    keys = sys.argv[1]  # Comma separated
    filename = sys.argv[2]

    data = open(filename).read()

#    print "DATA(%s) = %s" % (filename, data)

    jdata = json.loads(data)

    key_list = keys.split(',')
    result = jdata
    for key in key_list:
        if type(result) == dict:
            if key not in result:
                print "%s not in %s. Full JSON data: %s" % (key, result, jdata)
                sys.exit(1)
            result = result[key]
        elif type(result) == list:
            key_parts = key.split('=')
            key_name = key_parts[0]
            key_value = key_parts[1]
            found = None
            for entry in result:
                if str(entry[key_name]) == key_value:
                    found = entry
                    break
            if not found:
                print "%s=%s not found in %s. Full JSON data: %s" % \
                    (key_name, key_value, result, jdata)
                sys.exit(1)
            result = found

    print result
    return 0

if __name__ == "__main__":
    sys.exit(main())
