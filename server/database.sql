

-- Create the database
CREATE DATABASE musicapp_auth_db;

-- Switch to the newly created database, do this manually via terminal
\c musicapp_auth_db;  

-- Create the users table
CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
);
