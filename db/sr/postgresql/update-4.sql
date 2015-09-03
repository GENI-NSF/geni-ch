-- -------------------
-- Apply changes to add unique and no null and foreign key constraints, and related indices
-- See chapi #174, proto-ch #943, proto-ch #1081
-- -------------------

-- Somehow there are some rows with a null service_id. But that makes no sense: delete them
DELETE FROM service_registry_attribute where service_id is null;

ALTER TABLE service_registry_attribute 
    ALTER COLUMN service_id SET NOT NULL,
    ADD FOREIGN KEY (service_id) REFERENCES service_registry(id);