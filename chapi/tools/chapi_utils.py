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

def send_email(toaddr,fromaddr,replyaddr,subject,msgbody,ccaddr=None):
    msg = MIMEText(msgbody)
    msg['Subject'] = subject
    msg['To'] = toaddr
    msg['Reply-To'] = replyaddr
    if ccaddr != None:
        msg['Cc'] = ccaddr
        toaddrs = [toaddr,ccaddr] 
    else:
        toaddrs = [toaddr]
    msg['Precedence'] = "bulk"
    s = smtplib.SMTP('localhost')
    s.sendmail(fromaddr,toaddrs,msg.as_string())
    s.quit()

