--------------------------------------------------------
---  Add index  by time on logging entry
--------------------------------------------------------

CREATE INDEX logging_entry_event_time ON logging_entry(event_time);

--------------------------------------------------------
---  Add index  by event_id on logging entry_attribute
--------------------------------------------------------
CREATE INDEX logging_entry_attribute_event_id 
     ON logging_entry_attribute(event_id);


