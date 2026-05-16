-- MirageTrap PostgreSQL schema
-- Generated from Flask-SQLAlchemy models and current migrations.
-- This file contains schema only; no application data is included.

DROP TABLE IF EXISTS "evidence_files" CASCADE;
DROP TABLE IF EXISTS "attack_events" CASCADE;
DROP TABLE IF EXISTS "honeypot_instances" CASCADE;
DROP TABLE IF EXISTS "attack_sessions" CASCADE;
DROP TABLE IF EXISTS "admin_users" CASCADE;


CREATE TABLE admin_users (
	id SERIAL NOT NULL, 
	username VARCHAR(64) NOT NULL, 
	password_hash VARCHAR(255) NOT NULL, 
	failed_login_attempts INTEGER NOT NULL, 
	locked_until TIMESTAMP WITH TIME ZONE, 
	last_login_at TIMESTAMP WITH TIME ZONE, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id)
);

CREATE UNIQUE INDEX ix_admin_users_username ON admin_users (username);


CREATE TABLE attack_sessions (
	session_id VARCHAR(64) NOT NULL, 
	source_ip VARCHAR(64) NOT NULL, 
	honeypot_type VARCHAR(16) NOT NULL, 
	honeypot_id VARCHAR(64), 
	start_time TIMESTAMP WITH TIME ZONE NOT NULL, 
	end_time TIMESTAMP WITH TIME ZONE, 
	event_count INTEGER NOT NULL, 
	risk_level VARCHAR(16) NOT NULL, 
	replay_status VARCHAR(32) NOT NULL, 
	pcap_object_key VARCHAR(255), 
	sample_count INTEGER NOT NULL, 
	summary TEXT, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (session_id)
);

CREATE INDEX ix_attack_sessions_honeypot_id ON attack_sessions (honeypot_id);
CREATE INDEX ix_attack_sessions_honeypot_type ON attack_sessions (honeypot_type);
CREATE INDEX ix_attack_sessions_source_ip ON attack_sessions (source_ip);


CREATE TABLE honeypot_instances (
	id SERIAL NOT NULL, 
	honeypot_id VARCHAR(64) NOT NULL, 
	name VARCHAR(128) NOT NULL, 
	honeypot_type VARCHAR(16) NOT NULL, 
	image_key VARCHAR(64) NOT NULL, 
	image_name VARCHAR(255) NOT NULL, 
	container_name VARCHAR(128) NOT NULL, 
	host_ip VARCHAR(64), 
	bind_host VARCHAR(64) NOT NULL, 
	exposed_port INTEGER NOT NULL, 
	container_port INTEGER NOT NULL, 
	honeypot_profile VARCHAR(32) NOT NULL, 
	desired_state VARCHAR(16) NOT NULL, 
	runtime_status VARCHAR(16) NOT NULL, 
	container_id VARCHAR(128), 
	last_heartbeat_at TIMESTAMP WITH TIME ZONE, 
	last_runtime_sync_at TIMESTAMP WITH TIME ZONE, 
	last_seen_ip VARCHAR(64), 
	last_error TEXT, 
	runtime_meta JSON NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (exposed_port)
);

CREATE UNIQUE INDEX ix_honeypot_instances_container_name ON honeypot_instances (container_name);
CREATE UNIQUE INDEX ix_honeypot_instances_honeypot_id ON honeypot_instances (honeypot_id);
CREATE INDEX ix_honeypot_instances_honeypot_type ON honeypot_instances (honeypot_type);
CREATE INDEX ix_honeypot_instances_runtime_status ON honeypot_instances (runtime_status);


CREATE TABLE attack_events (
	id SERIAL NOT NULL, 
	event_type VARCHAR(32) NOT NULL, 
	honeypot_type VARCHAR(16) NOT NULL, 
	honeypot_id VARCHAR(64), 
	source_ip VARCHAR(64) NOT NULL, 
	source_port INTEGER, 
	country VARCHAR(64), 
	country_code VARCHAR(8), 
	region VARCHAR(64), 
	region_code VARCHAR(32), 
	city VARCHAR(64), 
	timezone VARCHAR(64), 
	latitude FLOAT, 
	longitude FLOAT, 
	accuracy_radius INTEGER, 
	asn VARCHAR(64), 
	asn_org VARCHAR(255), 
	geo_source VARCHAR(32), 
	request_content TEXT, 
	response_content TEXT, 
	risk_level VARCHAR(16) NOT NULL, 
	risk_score INTEGER NOT NULL, 
	threat_tags JSON NOT NULL, 
	session_id VARCHAR(64), 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(session_id) REFERENCES attack_sessions (session_id)
);

CREATE INDEX ix_attack_events_event_type ON attack_events (event_type);
CREATE INDEX ix_attack_events_honeypot_id ON attack_events (honeypot_id);
CREATE INDEX ix_attack_events_honeypot_type ON attack_events (honeypot_type);
CREATE INDEX ix_attack_events_risk_level ON attack_events (risk_level);
CREATE INDEX ix_attack_events_session_id ON attack_events (session_id);
CREATE INDEX ix_attack_events_source_ip ON attack_events (source_ip);


CREATE TABLE evidence_files (
	id SERIAL NOT NULL, 
	session_id VARCHAR(64) NOT NULL, 
	file_type VARCHAR(32) NOT NULL, 
	object_key VARCHAR(255) NOT NULL, 
	sha256 VARCHAR(64) NOT NULL, 
	size INTEGER NOT NULL, 
	extra_data JSON NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(session_id) REFERENCES attack_sessions (session_id)
);

CREATE INDEX ix_evidence_files_file_type ON evidence_files (file_type);
CREATE INDEX ix_evidence_files_session_id ON evidence_files (session_id);
