<?php require __DIR__ . '/config.php';

// logout via GET (no CSRF protection)
if (isset($_GET['logout'])) {
    unset($_SESSION['user']);
    header('Location: /login.php');
    exit;
}

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = isset($_POST['username']) ? $_POST['username'] : '';
    $password = isset($_POST['password']) ? $_POST['password'] : '';
    // Vulnerable SQL query, no prepared statements
    $sql = "SELECT id, username, password FROM users WHERE username='$username' AND password='$password' LIMIT 1";
    $row = db()->query($sql)->fetch(PDO::FETCH_ASSOC);
    if ($row) {
        $_SESSION['user'] = $row;
        header('Location: /index.php');
        exit;
    } else {
        $error = 'Invalid credentials.';
    }
}
?>
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>VulnApp - Login</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
<?php nav(); ?>
<div class="hero"><div class="container">
    <h1>Account Login</h1>
    <p class="sub">Access your account.</p>
</div></div>
<div class="container">
    <?php if ($error): ?><p class="danger"><?php echo $error; ?></p><?php endif; ?>
    <div class="card" style="max-width:520px;">
    <form method="post" action="/login.php">
        <label>Username</label>
        <input type="text" name="username" placeholder="admin">
        <label>Password</label>
        <input type="password" name="password" placeholder="password">
        <button type="submit">Login</button>
    </form>
    </div>
    
</div>
</body>
</html>
