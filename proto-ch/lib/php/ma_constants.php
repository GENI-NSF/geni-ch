<?php
//----------------------------------------------------------------------
// Copyright (c) 2012 Raytheon BBN Technologies
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and/or hardware specification (the "Work") to
// deal in the Work without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Work, and to permit persons to whom the Work
// is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Work.
//
// THE WORK IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE WORK OR THE USE OR OTHER DEALINGS
// IN THE WORK.
//----------------------------------------------------------------------

/* Set of constants for managing attributes of members in the 
 * GENI Clearinghouse Member Authority (MA)
 */

/* Set of arguments in calls to MA interface */
class MA_ARGUMENT {
  const MEMBER_ID = "member_id";
  const MEMBER_ID_KEY = "member_id_key";
  const MEMBER_ID_VALUE = "member_id_value";
  const SSH_KEY_ID = "ssh_key_id";
  const SSH_FILENAME = "ssh_filename";
  const SSH_DESCRIPTION = "ssh_description";
  const SSH_PUBLIC_KEY = "ssh_public_key";
  const SSH_PRIVATE_KEY = "ssh_private_key";
  const ATTRIBUTES = "attributes";
  const CLIENT_URN = "client_urn";
  const AUTHORIZE_SENSE = "authorize_sense";
  const PRIVILEGE_ID = "privilege_id";
  const CSR = "csr";
  const CERTIFICATE = "certificate";
  const PRIVATE_KEY = "private_key";
  const MEMBER_UUIDS = "member_uuids";
  const MEMBER_EMAILS = "member_emails";
}


class MA_ATTRIBUTE {
  const MEMBER_ID = "member_id";
  const NAME = "name";
  const VALUE = "value";
  const SELF_ASSERTED = "self_asserted";
}


class MA_ATTRIBUTE_NAME {
  const EMAIL_ADDRESS = "email_address";
  const FIRST_NAME = "first_name";
  const LAST_NAME = "last_name";
  const TELEPHONE_NUMBER = "telephone_number";
  const USERNAME = "username";
  const URN = "urn";
  const REFERENCE = "reference";
  const AFFILIATION = "affiliation";
  const DISPLAY_NAME = "displayName";
  const EPPN = "eppn";
}

class MA_PRIVILEGE {
  const PROJECT_LEAD = 1;
  const OPERATOR = 2;
}


/* Name of table containing per member attribute info */
$MA_MEMBER_TABLENAME = "ma_member";

/* Name of fields for member table */
class MA_MEMBER_TABLE_FIELDNAME {
  const ID = "id";
  const MEMBER_ID = MA_ARGUMENT::MEMBER_ID;
}


$MA_MEMBER_ATTRIBUTE_TABLENAME = "ma_member_attribute";

/* Name of fields for member table */
class MA_MEMBER_ATTRIBUTE_TABLE_FIELDNAME {
  const ID = "id";
  const MEMBER_ID = MA_ARGUMENT::MEMBER_ID;
  const NAME = "name";
  const VALUE = "value";
  const SELF_ASSERTED = "self_asserted";
}


$MA_PRIVILEGE_TABLENAME = "ma_privilege";

/* Name of fields for member table */
class MA_PRIVILEGE_TABLE_FIELDNAME {
  const ID = "id";
  const PRIVILEGE = "privilege";
}


$MA_MEMBER_PRIVILEGE_TABLENAME = "ma_member_privilege";

/* Name of fields for member table */
class MA_MEMBER_PRIVILEGE_TABLE_FIELDNAME {
  const ID = "id";
  const MEMBER_ID = MA_ARGUMENT::MEMBER_ID;
  const PRIVILEGE_ID = "privilege_id";
}


/* Name of table containing user SSH key info */
$MA_SSH_KEY_TABLENAME = "ma_ssh_key";

/* Name of fields of SSH key table */
class MA_SSH_KEY_TABLE_FIELDNAME {
  const ID = "id";
  const MEMBER_ID = "member_id";
  const FILENAME = "filename";
  const DESCRIPTION = "description";
  const PUBLIC_KEY = "public_key";
  const PRIVATE_KEY = "private_key";
}

/* Name of table containing registered MA clients (tools) */
$MA_CLIENT_TABLENAME = "ma_client";

/* Name of fields in MA_TABLE table */
class MA_CLIENT_TABLE_FIELDNAME {
  const ID = "id";
  const CLIENT_NAME = "client_name";
  const CLIENT_URN = "client_urn";
}

/* Name of table containing inside key info */
$MA_INSIDE_KEY_TABLENAME = "ma_inside_key";

/* Name of fields of INSIDE KEY table */
class MA_INSIDE_KEY_TABLE_FIELDNAME {
  const ID = "id";
  const CLIENT_URN = "client_urn";
  const MEMBER_ID = "member_id";
  const PRIVATE_KEY = "private_key";
  const CERTIFICATE = "certificate";
}

/* Name of table containing outside cert info */
$MA_OUTSIDE_CERT_TABLENAME = "ma_outside_cert";

/* Name of fields of MA_OUTSIDE_CERT table */
class MA_OUTSIDE_CERT_TABLE_FIELDNAME {
  const ID = "id";
  const MEMBER_ID = "member_id";
  const CERTIFICATE = "certificate";
  const PRIVATE_KEY = "private_key";
}

?>