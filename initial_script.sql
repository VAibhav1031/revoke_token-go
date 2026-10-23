CREATE DATABASE revoke;

-- change to this database.  CAUSE WE Are going to create objects in this DB only ...
\c revoke

SET client_encodings='UTF8';

CREATE SCHEMA IF NOT EXISTS app;

-- Role Creation

-- User role
CREATE ROLE admin LOGIN PASSWORD 'super_secret_133';

-- groups role (role without the login  only privileges to the objects... which can be inherited to other temp user role)
CREATE ROLE app_user NOLOGIN;


GRANT CREATE,USAGE ON SCHEMA app TO admin;
GRANT USAGE ON SCHEMA app to app_user;


-- all future table object in the schema to these roles wouuld get these privileges implicitly noww.... 
ALTER DEFAULT PRIVILEGES IN SCHEMA app 
GRANT INSERT , SELECT, UPDATE, TRUNCATE , DELETE ON TABLES TO admin;

ALTER DEFAULT PRIVILEGES IN SCHEMA app
GRANT SELECT,INSERT,UPDATE ON TABLES to app_user;



CREATE ROLE real_app_user LOGIN PASSWORD 'temp_app_user';

--inheritingh all those privileges from the group level role..
GRANT app_user to real_app_user;



CREATE TABLE IF NOT EXISTS app.user(
    user_id INT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    username TEXT,
    PASSWORD TEXT,
    EMAIL TEXT
);


