CREATE TABLE threats (
 md5 TEXT PRIMARY KEY CHECK (md5 ~ '^[0-9a-f]{32}$'),
 name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 255),
 description TEXT CHECK (char_length(description) <= 4096),
 type TEXT NOT NULL DEFAULT 'unknown' CHECK (type IN ('trojan','worm','ransomware','spyware','adware','other','unknown')),
 severity TEXT NOT NULL DEFAULT 'unknown' CHECK (severity IN ('low','medium','high','critical','unknown')),
 platforms TEXT[] NOT NULL DEFAULT '{}' CHECK (platforms <@ ARRAY['windows','linux','arch','ubuntu','debian','fedora','macos','android','ios']::text[] AND array_position(platforms,NULL) IS NULL),
 first_seen_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 CHECK (NOT (platforms && ARRAY['arch','ubuntu','debian','fedora']::text[]) OR platforms @> ARRAY['linux']::text[])
);
CREATE INDEX idx_threats_platforms ON threats USING GIN (platforms);
CREATE INDEX idx_threats_page ON threats (created_at DESC, md5 ASC);
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO threat_app;
GRANT SELECT, INSERT, UPDATE ON threats TO threat_app;
