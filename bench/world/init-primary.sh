#!/bin/bash
set -e
psql -v ON_ERROR_STOP=1 -U postgres -d postgres <<SQL
create role replicator with replication login password 'replpw';
create role app1 login password 'app1pw';
create role shahrah login superuser password 'dev';
create or replace function shahrah_get_auth(in wanted text,
                                            out username text, out verifier text)
returns record as \$\$
  select rolname::text, rolpassword::text from pg_authid where rolname = \$1
\$\$ language sql security definer;
revoke all on function shahrah_get_auth(text) from public;

create table accounts(aid bigint primary key, balance bigint not null default 0);
insert into accounts select g, g * 10 from generate_series(1, 50000) g;
create table shahrah_directory(shard_key bytea primary key,
                               home_region text not null, moving_to text);
grant all on accounts, shahrah_directory to app1;
SQL
echo "host replication replicator all scram-sha-256" >> "$PGDATA/pg_hba.conf"
