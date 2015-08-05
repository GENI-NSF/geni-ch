
-- -------------------------------------------------------------------
-- Add expiration column to certificate tables
-- -------------------------------------------------------------------

ALTER TABLE ma_outside_cert ADD COLUMN expiration TIMESTAMP;

ALTER TABLE ma_inside_key ADD COLUMN expiration TIMESTAMP;

-- ALTER TABLE ma_outside_cert DROP COLUMN expiration;
-- ALTER TABLE ma_inside_key DROP COLUMN expiration;
