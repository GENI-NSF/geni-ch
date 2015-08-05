-- -------------------
-- Apply changes to add unique and no null and foreign key constraints, and related indices
-- See chapi #174, proto-ch #943, proto-ch #1081
-- -------------------

ALTER TABLE cs_attribute
  ADD PRIMARY KEY (id),
  ALTER COLUMN name SET NOT NULL,
  ADD UNIQUE (name);

ALTER TABLE cs_privilege
  ADD PRIMARY KEY (id),
  ALTER COLUMN name SET NOT NULL,
  ADD UNIQUE (name);

ALTER TABLE cs_context_type
  ADD PRIMARY KEY (id),
  ALTER COLUMN name SET NOT NULL,
  ADD UNIQUE (name);

ALTER TABLE cs_action
  ADD PRIMARY KEY (id),
  ALTER COLUMN name SET NOT NULL,
  ALTER COLUMN context_type SET NOT NULL,
  ADD FOREIGN KEY (context_type) REFERENCES cs_context_type(id);

ALTER TABLE cs_assertion
  ALTER COLUMN principal SET NOT NULL,
  ALTER COLUMN attribute SET NOT NULL,
  ADD FOREIGN KEY (attribute) REFERENCES cs_attribute(id),
  ALTER COLUMN context_type SET NOT NULL,
  ADD FOREIGN KEY (context_type) REFERENCES cs_context_type(id);

ALTER TABLE cs_policy
  ADD PRIMARY KEY (id),
  ALTER COLUMN attribute SET NOT NULL,
  ADD FOREIGN KEY (attribute) REFERENCES cs_attribute(id),
  ALTER COLUMN context_type SET NOT NULL,
  ADD FOREIGN KEY (context_type) REFERENCES cs_context_type(id),
  ALTER COLUMN privilege SET NOT NULL,
  ADD FOREIGN KEY (privilege) REFERENCES cs_privilege(id);

