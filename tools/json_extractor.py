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

import json
import sys

def main():
    if len(sys.argv) <= 2:
        print "Usage: json_extractor.py field filename"
        sys.exit(0)

    fields = sys.argv[1] # Comma separated
    filename = sys.argv[2]

    data = open(filename).read()
    jdata = json.loads(data)

    field_list = fields.split(',')
    result = jdata
    for field in field_list:
        if type(result) == dict:
            result = result[field]
        elif type(result) == list:
            field_parts = field.split('=')
            field_name = field_parts[0]
            field_value = field_parts[1]
            for entry in result:
                if entry[field_name] == field_value:
                    result = entry
                    break
            
    print result



if __name__ == "__main__":
    sys.exit(main())
