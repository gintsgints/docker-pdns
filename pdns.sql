create extension citext;

drop table if exists domains cascade;
create table domains (
  id                INTEGER PRIMARY KEY,
  name              citext,
  master            text,
  last_check        INTEGER DEFAULT NULL,
  type              text,
  notified_serial   INTEGER DEFAULT NULL, 
  account           text
);

drop sequence domain_id_seq;
create sequence domain_id_seq start 1;

CREATE UNIQUE INDEX name_index ON domains(name);

drop table if exists records cascade;
CREATE TABLE records (
  id              INTEGER PRIMARY KEY,
  domain_id       INTEGER DEFAULT NULL,
  name            citext, 
  type            text,
  content         text,
  ttl             INTEGER DEFAULT NULL,
  prio            INTEGER DEFAULT NULL,
  change_date     INTEGER DEFAULT NULL,
  disabled        BOOL DEFAULT 'f',
  ordername       VARCHAR(255),
  auth            BOOL DEFAULT 't'
);
              
CREATE INDEX rec_name_index ON records(name);
CREATE INDEX nametype_index ON records(name,type);
CREATE INDEX domain_id ON records(domain_id);
CREATE INDEX recordorder ON records (domain_id, ordername text_pattern_ops);

drop sequence record_id_seq;
create sequence record_id_seq start 1;

drop table if exists supermasters cascade;
create table supermasters (
  ip          text, 
  nameserver  citext, 
  account     text,
  PRIMARY KEY(ip, nameserver)
);

GRANT SELECT ON supermasters TO pdns;
GRANT ALL ON domains TO pdns;
GRANT ALL ON records TO pdns;

drop table if exists comments cascade;
CREATE TABLE comments (
  id                    SERIAL PRIMARY KEY,
  domain_id             INT NOT NULL,
  name                  VARCHAR(255) NOT NULL,
  type                  VARCHAR(10) NOT NULL,
  modified_at           INT NOT NULL,
  account               VARCHAR(40) DEFAULT NULL,
  comment               VARCHAR(65535) NOT NULL,
  CONSTRAINT domain_exists
  FOREIGN KEY(domain_id) REFERENCES domains(id)
  ON DELETE CASCADE,
  CONSTRAINT c_lowercase_name CHECK (((name)::TEXT = LOWER((name)::TEXT)))
);

CREATE INDEX comments_domain_id_idx ON comments (domain_id);
CREATE INDEX comments_name_type_idx ON comments (name, type);
CREATE INDEX comments_order_idx ON comments (domain_id, modified_at);


drop table if exists domainmetadata cascade;
CREATE TABLE domainmetadata (
  id                    SERIAL PRIMARY KEY,
  domain_id             INT REFERENCES domains(id) ON DELETE CASCADE,
  kind                  VARCHAR(32),
  content               TEXT
);

CREATE INDEX domainidmetaindex ON domainmetadata(domain_id);


drop table if exists cryptokeys cascade;
CREATE TABLE cryptokeys (
  id                    SERIAL PRIMARY KEY,
  domain_id             INT REFERENCES domains(id) ON DELETE CASCADE,
  flags                 INT NOT NULL,
  active                BOOL,
  content               TEXT
);

CREATE INDEX domainidindex ON cryptokeys(domain_id);


drop table if exists tsigkeys cascade;
CREATE TABLE tsigkeys (
  id                    SERIAL PRIMARY KEY,
  name                  VARCHAR(255),
  algorithm             VARCHAR(50),
  secret                VARCHAR(255),
  CONSTRAINT c_lowercase_name CHECK (((name)::TEXT = LOWER((name)::TEXT)))
);

CREATE UNIQUE INDEX namealgoindex ON tsigkeys(name, algorithm);

-- Define the domain
create or replace function create_domain(_name text, _type text, _account text) returns boolean as $$
begin
  INSERT INTO domains (id,name,type,account) VALUES (nextval('domain_id_seq'),_name,_type,_account);
  return found;
end
$$ language plpgsql;


-- SOA records
create or replace function create_soa( _domain text, _content text) returns boolean as $$
declare
  _domain_id integer;
begin
  select into _domain_id id from domains where name = _domain;
  insert into records (id, domain_id, name,type,content,ttl) values ( nextval('record_id_seq'), _domain_id, _domain, 'SOA', _content, 3600);
  return found;
end
$$ language plpgsql;

create or replace function delete_soa( _domain text ) returns boolean as $$
declare
  _domain_id integer;
begin
  select into _domain_id id from domains;
  delete from records where domain_id = id and type = 'SOA';
  return found;
end
$$ language plpgsql;

-- NAPTR records
create or replace function create_a( _domain text, _host text, _ipaddr text) returns boolean as $$
declare
  _domain_id integer;
begin
  perform delete_a(_domain,_host,_ipaddr);
  select into _domain_id id from domains where name = _domain;
  insert into records(id,domain_id, name,type, content, ttl) values (nextval('record_id_seq'), _domain_id, _host || '.' ||  _domain, 'NAPTR', _ipaddr, 3600);
  return found;
end
$$ language plpgsql;

create or replace function delete_a( _domain text, _host text, _ipaddr text) returns boolean as $$
declare
  _domain_id integer;
begin
  select into _domain_id id from domains where name = _domain;
  delete from records where domain_id = _domain_id and name = _host || '.' || _domain and content = _ipaddr and type = 'NAPTR';
  return found;
end
$$ language plpgsql;

-- A records
create or replace function create_a( _domain text, _host text, _ipaddr text) returns boolean as $$
declare
  _domain_id integer;
begin
  perform delete_a(_domain,_host,_ipaddr);
  select into _domain_id id from domains where name = _domain;
  insert into records(id,domain_id, name,type, content, ttl) values (nextval('record_id_seq'), _domain_id, _host || '.' ||  _domain, 'A', _ipaddr, 3600);
  return found;
end
$$ language plpgsql;

create or replace function delete_a( _domain text, _host text, _ipaddr text) returns boolean as $$
declare
  _domain_id integer;
begin
  select into _domain_id id from domains where name = _domain;
  delete from records where domain_id = _domain_id and name = _host || '.' || _domain and content = _ipaddr and type = 'A';
  return found;
end
$$ language plpgsql;

-- NS records
create or replace function create_ns( _domain text, _host text) returns boolean as $$
declare
  _domain_id integer;
begin
  perform delete_ns(_domain,_host);
  select into _domain_id id from domains where name = _domain;
  insert into records(id,domain_id, name,type, content, ttl) values (nextval('record_id_seq'), _domain_id,  _domain, 'NS', _host || '.' || _domain, 3600);
  return found;
end
$$ language plpgsql;

create or replace function delete_ns( _domain text, _host text) returns boolean as $$
declare
  _domain_id integer;
begin
  select into _domain_id id from domains where name = _domain;
  delete from records where domain_id = domain_id and type = 'NS' and content = _host || '.' || _domain;
  return found;
end
$$ language plpgsql;

-- CNAME records
create or replace function create_cname( _domain text, _host text, _alias text ) returns boolean as $$
declare
  _domain_id integer;
begin
  perform delete_cname(_domain,_host,_alias);
  select into _domain_id id from domains where name = _domain;
  insert into records(id,domain_id,name,type,content,ttl) values (nextval('record_id_seq'), _domain_id, _host || '.' || _domain , 'CNAME', _alias, 3600);
  return found;
end
$$ language plpgsql;

create or replace function delete_cname( _domain text, _host text, _alias text) returns boolean as $$
declare
  _domain_id integer;
begin
  select into _domain_id id from domains where name = _domain;
  delete from records where domain_id = _domain_id and name = _host || '.' || _domain and content = _alias and type = 'CNAME';  
  return found;
end
$$ language plpgsql;


-- TXT records
-- http://www.ietf.org/rfc/rfc1464.txt

create or replace function create_txt( _domain text, _host text, _txt text ) returns boolean as $$
declare
  _domain_id integer;
begin
  perform delete_txt(_domain,_host,_txt);
  select into _domain_id id from domains where name = _domain;
  insert into records(id,domain_id,name,type,content,ttl) values (nextval('record_id_seq'), _domain_id, _host || '.' || _domain, 'TXT', _txt, 3600);
  return found;
end
$$ language plpgsql;

create or replace function delete_txt( _domain text, _host text, _txt text ) returns boolean as $$
declare
  _domain_id integer;
begin
  select into _domain_id id from domains where name = _domain;
  delete from records where domain_id = _domain_id and name = _host || '.' || _domain and content = _txt and type = 'TXT';
  return found;
end
$$ language plpgsql;

-- SRV records
-- https://www.ietf.org/rfc/rfc2782.txt

create or replace function create_srv( _domain text, _host text, _txt text ) returns boolean as $$
declare
  _domain_id integer;
begin
  perform delete_srv(_domain,_host,_txt);
  select into _domain_id id from domains where name = _domain;
  insert into records(id,domain_id,name,type,content,ttl) values (nextval('record_id_seq'), _domain_id, _host || '.' || _domain, 'SRV', _txt, 3600);
  return found;
end
$$ language plpgsql;

create or replace function delete_srv( _domain text, _host text, _txt text ) returns boolean as $$
declare
  _domain_id integer;
begin
  select into _domain_id id from domains where name = _domain;
  delete from records where domain_id = _domain_id and name = _host || '.' || _domain and content = _txt and type = 'SRV';
  return found;
end
$$ language plpgsql;

-- list domain
create or replace function list_domain(_domain text) returns json as $$
declare
  _domain_id integer;
  _json json;
begin
  select into _domain_id id from domains where name = _domain;
  select into _json array_to_json(array_agg(foo)) as domain from ( select name,type,content from records where domain_id = _domain_id) as foo;
  return _json;
end
$$ language plpgsql;
