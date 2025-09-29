<?php
// Intentionally insecure configuration for local security testing
// Uses a single SQLite database file in the project folder

session_start();

$DB_FILE = __DIR__ . DIRECTORY_SEPARATOR . 'vulnapp.db';

try {
    // Using PDO for convenience, but queries in this app deliberately avoid prepared statements
    $pdo = new PDO('sqlite:' . $DB_FILE);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (Throwable $e) {
    http_response_code(500);
    echo '<h1>Database connection failed</h1>';
    echo '<p>' . $e->getMessage() . '</p>';
    exit;
}

function db() {
    // Helper to get the PDO instance
    global $pdo;
    return $pdo;
}

function current_user() {
    return isset($_SESSION['user']) ? $_SESSION['user'] : null;
}

function nav() {
    $u = current_user();
    echo '<nav class="nav"><div class="nav-inner">';
    echo '<div class="brand"><div class="logo"></div><a href="/index.php">VulnStore</a></div>';
    echo '<div class="nav-links">';
    echo '<a href="/index.php">Home</a>';
    echo '<a href="/products.php">Products</a>';
    echo '<a href="/cart.php">Cart</a>';
    echo '<a href="/search.php">Search</a>';
    echo '<a href="/upload.php">Uploads</a>';
    echo '<a href="/admin.php">Admin</a>';
    echo '<a href="/exec.php">Exec</a>';
    echo '</div>';
    if ($u) {
        echo '<span class="user">Logged in as ' . $u['username'] . ' · <a href="/login.php?logout=1">Logout</a></span>';
    } else {
        echo '<span class="user"><a href="/login.php">Login</a></span>';
    }
    echo '</div></nav>';
}

function footer_note() {
    echo '<footer class="footer"><div class="container">© VulnStore 2025</div></footer>';
}

?>
