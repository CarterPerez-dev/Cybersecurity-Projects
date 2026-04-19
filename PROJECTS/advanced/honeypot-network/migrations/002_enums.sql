-- ©AngelaMos | 2026
-- 002_enums.sql

-- +goose Up
CREATE TYPE service_type AS ENUM (
    'ssh', 'http', 'ftp', 'smb', 'mysql', 'redis'
);

CREATE TYPE event_type AS ENUM (
    'connect',
    'disconnect',
    'login.success',
    'login.failed',
    'command.input',
    'command.output',
    'file.upload',
    'file.download',
    'request',
    'exploit.attempt',
    'scan.detected'
);

CREATE TYPE protocol_type AS ENUM ('tcp', 'udp');

CREATE TYPE ioc_type AS ENUM (
    'ipv4', 'ipv6', 'domain', 'url',
    'sha256', 'md5', 'ssh-key', 'user-agent', 'email'
);

-- +goose Down
DROP TYPE IF EXISTS ioc_type;
DROP TYPE IF EXISTS protocol_type;
DROP TYPE IF EXISTS event_type;
DROP TYPE IF EXISTS service_type;
