<?php require __DIR__ . '/config.php';

$q = isset($_GET['q']) ? $_GET['q'] : '';
$sql = 'SELECT id, username, password FROM users';
if ($q !== '') {
    // vulnerable: direct concatenation
    $sql .= " WHERE username LIKE '%$q%' OR id='$q'";
}
$sql .= ' ORDER BY id ASC';

$rows = [];
try {
    $rows = db()->query($sql)->fetchAll(PDO::FETCH_ASSOC);
} catch (Throwable $e) {
    $rows = [];
    $err = $e->getMessage();
}
?>
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>VulnApp - Search</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
<?php nav(); ?>
<div class="hero"><div class="container">
    <h1>Search Users</h1>
    <p class="sub">Find users by name.</p>
</div></div>
<div class="container">
    <div class="card">
        <form method="get" action="/search.php">
            <input type="text" name="q" placeholder="Search query" value="<?php echo $q; ?>">
            <button type="submit">Search</button>
        </form>
    </div>
    <?php if (isset($err)): ?><p class="danger"><?php echo $err; ?></p><?php endif; ?>
    <table>
        <thead><tr><th>ID</th><th>Username</th></tr></thead>
        <tbody>
        <?php foreach ($rows as $r): ?>
            <tr>
                <td><?php echo $r['id']; ?></td>
                <td><?php echo $r['username']; // XSS intended ?></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    
</div>
</body>
</html>
