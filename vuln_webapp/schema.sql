-- SQLite schema for VulnApp
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS comments;
DROP TABLE IF EXISTS uploads;

CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  password TEXT
);

CREATE TABLE comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  comment TEXT
);

CREATE TABLE uploads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  filename TEXT,
  content TEXT
);

-- Extra realism: Products table for storefront look
DROP TABLE IF EXISTS products;
CREATE TABLE products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  description TEXT,
  price REAL,
  image TEXT
);
