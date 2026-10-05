-- Durable call-end spool written by this operator's Kamailio instances.
-- Kamailio's role may only append; the receipt service (role "dots") reads.
-- Rows contain full numbers: this is the operator's own CDR store, subject
-- to its own retention policy, and never leaves the operator's network.
CREATE ROLE kamailio LOGIN PASSWORD 'kamailio-lab-only';
CREATE DATABASE kamailio OWNER dots;
\connect kamailio
CREATE TABLE call_end_spool (
    id          bigserial PRIMARY KEY,
    created_at  timestamptz NOT NULL DEFAULT now(),
    payload     jsonb NOT NULL
);
ALTER TABLE call_end_spool OWNER TO dots;
GRANT CONNECT ON DATABASE kamailio TO kamailio;
GRANT INSERT ON call_end_spool TO kamailio;
GRANT USAGE ON SEQUENCE call_end_spool_id_seq TO kamailio;
