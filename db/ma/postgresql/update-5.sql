-- -------------------
-- Apply changes to add unique and no null and foreign key constraints, and related indices
-- See chapi #174, proto-ch #943, proto-ch #1081
-- -------------------

ALTER TABLE ma_member 
    ALTER COLUMN member_id SET NOT NULL;

-- Since the column is already unique this is un-necessary
DROP INDEX IF EXISTS ma_member_index_member_id;

-- Since the column is already unique this is un-necessary
DROP INDEX IF EXISTS ma_client_index_client_urn;

ALTER TABLE ma_inside_key 
    ALTER COLUMN member_id SET NOT NULL,
    ALTER COLUMN private_key SET NOT NULL,
    ALTER COLUMN certificate SET NOT NULL;