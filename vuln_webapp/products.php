<?php require __DIR__ . '/config.php';

$q = isset($_GET['q']) ? $_GET['q'] : '';
$sql = 'SELECT id, name, description, price, image FROM products';
if ($q !== '') {
    $sql .= " WHERE name LIKE '%$q%' OR description LIKE '%$q%'"; // vulnerable SQLi
}
$sql .= ' ORDER BY id ASC';
$rows = [];
try { $rows = db()->query($sql)->fetchAll(PDO::FETCH_ASSOC); } catch (Throwable $e) { $err = $e->getMessage(); }
?>
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>VulnStore - Products</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
<?php nav(); ?>
<div class="hero"><div class="container">
    <h1>Products</h1>
    <p class="sub">Browse the catalog.</p>
</div></div>
<div class="container">
    <div class="card">
        <form method="get" action="/products.php">
            <input type="text" name="q" placeholder="Search products" value="<?php echo $q; ?>">
            <button type="submit">Search</button>
        </form>
        <?php if (isset($err)): ?><p class="danger"><?php echo $err; ?></p><?php endif; ?>
    </div>

    <div class="product-grid">
        <?php foreach ($rows as $p): ?>
            <div class="product-card">
                <div class="product-title"><?php echo $p['name']; // XSS intended ?></div>
                <div class="muted">$<?php echo number_format((float)$p['price'], 2); ?></div>
                <div style="margin:8px 0;">
                    <?php echo $p['description']; // XSS intended ?>
                </div>
                <form method="post" action="/cart.php">
                    <input type="hidden" name="product_id" value="<?php echo $p['id']; ?>">
                    <button type="submit">Add to Cart</button>
                </form>
            </div>
        <?php endforeach; ?>
    </div>
</div>
<?php footer_note(); ?>
</body>
</html>
