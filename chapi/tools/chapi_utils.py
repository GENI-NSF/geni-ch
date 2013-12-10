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

# Utility functions

import smtplib
from email.mime.text import MIMEText
from chapi_log import *

def send_email(to_list,fromaddr,replyaddr,subject,msgbody,cc_list=None):
    if msgbody is None:
        msgbody = ""
    msg = MIMEText(msgbody)
    if subject is None:
        subject = ""
    msg['Subject'] = subject
    if not to_list or len(to_list) == 0:
        chapi_warn("SENDMAIL", "No to address for message with subject '%s'" % subject)
        return
    if replyaddr and replyaddr.strip() != "":
        msg['Reply-To'] = replyaddr

    to_hdr = ""
    for to in to_list:
        to_hdr += to + ","
    msg['To'] = to_hdr
    msg['Reply-To'] = replyaddr
    if cc_list != None and len(cc_addr) != 0:
        cc_hdr = ""
        for cc in cc_list:
            cc_hdr += cc + ","
        msg['Cc'] = cc_hdr
        toaddrs = to_list + cc_list 
    else:
        toaddrs = to_list
    msg['Precedence'] = "bulk"
    msg['Auto-Submitted'] = "auto-generated"
    s = smtplib.SMTP('localhost')
    s.sendmail(fromaddr,toaddrs,msg.as_string())
    s.quit()

