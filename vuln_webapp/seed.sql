-- Seed data for VulnApp
INSERT INTO users (username, password) VALUES
 ('admin', 'admin'),
 ('alice', 'password123'),
 ('bob', 'qwerty'),
 ('eve', 'letmein');

INSERT INTO comments (user_id, comment) VALUES
 (1, 'Welcome to VulnApp!'),
 (2, 'Hello world'),
 (3, 'Excited to be here!'),
 (4, 'Have a nice day!');

INSERT INTO uploads (filename, content) VALUES
 ('hello.txt', 'This is a sample file.'),
 ('note.html', '<h1>HTML Content</h1>');

INSERT INTO products (name, description, price, image) VALUES
 ('Cyber Hoodie', 'Comfy hoodie with premium fabric and clean fit.', 49.99, '/assets/hoodie.png'),
 ('Pentest Mug', 'Ceramic mug with a stylish print for late-night sessions.', 12.50, '/assets/mug.png'),
 ('Sticker Pack', 'Glossy stickers to customize your laptop and desk.', 5.00, '/assets/stickers.png'),
 ('Web Exploit Book', 'A practical guide with hands-on web techniques.', 29.00, '/assets/book.png');
