<?php require __DIR__ . '/config.php';

// No authentication for simplicity; this is intentionally exposed.
$notice = '';

// Deletion via GET (CSRF and SQLi)
if (isset($_GET['delete_user'])) {
    $id = $_GET['delete_user'];
    try {
        db()->exec("DELETE FROM users WHERE id = $id");
        $notice = '<p class="success">User deleted.</p>';
    } catch (Throwable $e) { $notice = '<p class="danger">' . $e->getMessage() . '</p>'; }
}

if (isset($_GET['delete_comment'])) {
    $id = $_GET['delete_comment'];
    try {
        db()->exec("DELETE FROM comments WHERE id = $id");
        $notice = '<p class="success">Comment deleted.</p>';
    } catch (Throwable $e) { $notice = '<p class="danger">' . $e->getMessage() . '</p>'; }
}

// Deletion via POST (also vulnerable, no CSRF tokens)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['user_id'])) {
        $id = $_POST['user_id'];
        db()->exec("DELETE FROM users WHERE id = $id");
        $notice = '<p class="success">User deleted via POST.</p>';
    }
    if (isset($_POST['comment_id'])) {
        $id = $_POST['comment_id'];
        db()->exec("DELETE FROM comments WHERE id = $id");
        $notice = '<p class="success">Comment deleted via POST.</p>';
    }
}

$users = db()->query('SELECT id, username FROM users ORDER BY id')->fetchAll(PDO::FETCH_ASSOC);
$comments = db()->query('SELECT id, comment FROM comments ORDER BY id')->fetchAll(PDO::FETCH_ASSOC);
?>
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>VulnApp - Admin</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
<?php nav(); ?>
<div class="hero"><div class="container">
    <h1>Admin Panel</h1>
    <p class="sub">Manage users and comments.</p>
</div></div>
<div class="container">
    <?php echo $notice; ?>
    <div class="card">
        <h3>Delete via GET</h3>
        <p>
            Users:
            <?php foreach ($users as $u): ?>
                <a href="/admin.php?delete_user=<?php echo $u['id']; ?>">delete user #<?php echo $u['id']; ?></a>
            <?php endforeach; ?>
        </p>
        <p>
            Comments:
            <?php foreach ($comments as $c): ?>
                <a href="/admin.php?delete_comment=<?php echo $c['id']; ?>">delete comment #<?php echo $c['id']; ?></a>
            <?php endforeach; ?>
        </p>
    </div>

    <div class="card">
        <h3>Delete via POST</h3>
        <form method="post" action="/admin.php">
            <label>User ID</label>
            <input type="text" name="user_id" placeholder="e.g., 1">
            <button type="submit">Delete User</button>
        </form>
        <form method="post" action="/admin.php">
            <label>Comment ID</label>
            <input type="text" name="comment_id" placeholder="e.g., 1">
            <button type="submit">Delete Comment</button>
        </form>
    </div>

    
</div>
</body>
</html>
