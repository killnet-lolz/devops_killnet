CREATE DATABASE DB_DATABASE;

CREATE USER DB_USER WITH REPLICATION ENCRYPTED PASSWORD 'DB_PASSWORD';
GRANT ALL PRIVILEGES ON DATABASE DB_DATABASE TO DB_USER;

CREATE USER DB_REPL_USER WITH REPLICATION ENCRYPTED PASSWORD 'DB_REPL_PASSWORD';

\connect DB_DATABASE;

CREATE TABLE IF NOT EXISTS emails (
    ID SERIAL PRIMARY KEY,
    email VARCHAR(100) NOT NULL
);

CREATE TABLE IF NOT EXISTS phone_numbers (
    id SERIAL PRIMARY KEY,
    phone_number VARCHAR(25) NOT NULL
);

INSERT INTO emails (email) VALUES ('ptstart@pt.start');
INSERT INTO phone_numbers (phone_number) VALUES ('+78242341245');