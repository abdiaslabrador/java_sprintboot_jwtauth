-- Drop tables if they exist
DROP TABLE IF EXISTS roles_users;
DROP TABLE IF EXISTS profiles;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS roles;

-- Create roles table
CREATE TABLE roles (
    id_role SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL
);

-- Create users table
CREATE TABLE users (
    id_user SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL
);

-- Create profiles table
CREATE TABLE profiles (
    id_profile SERIAL PRIMARY KEY,
    email VARCHAR(100) NOT NULL,
    address VARCHAR(100),
    user_id INT NOT NULL REFERENCES users(id_user)
);

-- Create roles_users table
CREATE TABLE roles_users (
    role_id INT NOT NULL REFERENCES roles(id_role),
    user_id INT NOT NULL REFERENCES users(id_user),
    PRIMARY KEY (role_id, user_id)
);
