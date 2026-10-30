CREATE DATABASE revoke_arena;

-- change to this database.  CAUSE WE Are going to create objects in this DB only ...
\c revoke_arena

SET client_encoding='UTF8';

CREATE SCHEMA IF NOT EXISTS app;

SET search_path=app,public;
--
-- Role Creation

-- User role
CREATE ROLE admin LOGIN PASSWORD 'super_secret_133';

-- groups role (role without the login  only privileges to the objects... which can be inherited to other temp user role)
CREATE ROLE app_user NOLOGIN;

-- Access to schema and all.  
GRANT CREATE,USAGE ON SCHEMA app TO admin;
GRANT USAGE ON SCHEMA app TO app_user;


CREATE ROLE real_app_user LOGIN PASSWORD 'tempSorcerer';

--inheriting all those privileges from the group level role..
GRANT app_user to real_app_user;


--- Give access to the connection of the DB
GRANT CONNECT ON DATABASE revoke_arena  TO admin;
GRANT CONNECT ON DATABASE revoke_arena  TO app_user;



-- all future table object in the schema to these roles wouuld get these privileges implicitly noww.... 
ALTER DEFAULT PRIVILEGES IN SCHEMA app 
GRANT INSERT , SELECT, UPDATE, TRUNCATE , DELETE ON TABLES TO admin;

ALTER DEFAULT PRIVILEGES IN SCHEMA app
GRANT SELECT,INSERT,UPDATE ON TABLES to app_user;


CREATE TABLE IF NOT EXISTS app.user(
    user_id INT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    username TEXT NOT NULL UNIQUE,
    hashed_password TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS app.posts(
    post_id INT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    user_id INT REFERENCES app.user(user_id) NOT NULL,
    post_title VARCHAR(100) NOT NULL,
    post_content VARCHAR(500) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
)


