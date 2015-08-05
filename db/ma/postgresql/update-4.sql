--------------------------------------------------------
---  Add index  by name AND value on ma_member_attribute
--------------------------------------------------------
CREATE INDEX ma_member_attribute_name_value 
  ON ma_member_attribute (name, value);
