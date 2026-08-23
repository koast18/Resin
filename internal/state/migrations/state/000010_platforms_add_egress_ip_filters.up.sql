ALTER TABLE platforms
ADD COLUMN egress_ip_filters_json TEXT NOT NULL DEFAULT '[]';
