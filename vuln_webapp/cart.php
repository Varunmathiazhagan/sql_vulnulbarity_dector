<?php require __DIR__ . '/config.php';

// Simulate a very naive cart in DB (no user scoping, no CSRF)
db()->exec('CREATE TABLE IF NOT EXISTS cart (id INTEGER PRIMARY KEY AUTOINCREMENT, product_id INTEGER, note TEXT)');

$notice = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $pid = isset($_POST['product_id']) ? $_POST['product_id'] : '';
    $note = isset($_POST['note']) ? $_POST['note'] : '';
    try {
        db()->exec("INSERT INTO cart (product_id, note) VALUES ($pid, '$note')"); // SQLi + stored XSS
        $notice = '<p class="success">Added to cart.</p>';
    } catch (Throwable $e) { $notice = '<p class="danger">' . $e->getMessage() . '</p>'; }
}

// Vulnerable clear action via GET
if (isset($_GET['clear'])) {
    db()->exec('DELETE FROM cart');
    $notice = '<p class="success">Cart cleared.</p>';
}

$rows = db()->query('SELECT c.id, c.note, p.name, p.price FROM cart c LEFT JOIN products p ON p.id = c.product_id ORDER BY c.id DESC')->fetchAll(PDO::FETCH_ASSOC);
?>
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>VulnStore - Cart</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
<?php nav(); ?>
<div class="hero"><div class="container">
    <h1>Your Cart</h1>
    <p class="sub">Review your items.</p>
</div></div>
<div class="container">
    <?php echo $notice; ?>
    <div class="card" style="max-width: 760px;">
        <form method="post" action="/cart.php">
            <label>Product ID</label>
            <input type="text" name="product_id" placeholder="e.g., 1">
            <label>Note</label>
            <input type="text" name="note" placeholder="optional note">
            <button type="submit">Add Arbitrary Item</button>
        </form>
        <a class="btn-outline" href="/cart.php?clear=1">Clear Cart (GET)</a>
    </div>

    <div class="card">
        <h3>Items</h3>
        <table>
            <thead><tr><th>ID</th><th>Product</th><th>Price</th><th>Note</th></tr></thead>
            <tbody>
                <?php foreach ($rows as $r): ?>
                <tr>
                    <td><?php echo $r['id']; ?></td>
                    <td><?php echo $r['name']; ?></td>
                    <td>$<?php echo number_format((float)$r['price'], 2); ?></td>
                    <td><?php echo $r['note']; // stored XSS ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>
<?php footer_note(); ?>
</body>
</html>
