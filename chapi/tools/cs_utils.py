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

# Helper methods for adding/removing attributes to cs_attribute table

# Add an attribute to CS_ATTRIBUTE table
def add_attribute(db, session, signer, principal, attribute, context_type, context):
    ins_stmt = db.CS_ASSERTION_TABLE.insert().values(
        signer=signer, principal=principal,attribute=attribute, \
            context_type=context_type, context=context)
    result = session.execute(ins_stmt)

# Remove an attribute from CS_ATTRIBUTE table
def delete_attribute(db, session, principal, context_type, context):
    q = session.query(db.CS_ASSERTION_TABLE)
    q = q.filter(db.CS_ASSERTION_TABLE.principal == principal)
    q = q.filter(db.CS_ASSERTION_TABLE.context_type == context_type)
    q = q.filter(db.CS_ASSERTION_TABLE.context == context)
    q = q.delete()


