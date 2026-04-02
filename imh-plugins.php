<?php
//This file is used to dynamically generate the admin panel menu for IMH plugins

$plugin_dir = '/usr/local/cwpsrv/htdocs/resources/admin/modules/';
$plugins = [];

foreach (glob($plugin_dir . 'imh-*.php') as $filename) {
    $system = basename($filename, '.php');
    // Get the second line from the file (title)
    $lines = file($filename);
    // Try to extract title from PHP comment on line 2
    $title = $system;
    if (isset($lines[1])) {
        $line = trim($lines[1]);
        // Match "// Title" pattern
        if (preg_match('/^\/\/\s*(.+)$/', $line, $m)) {
            $title = trim($m[1]);
        }
    }
    $plugins[] = [
        'system' => $system,
        'title' => $title
    ];
}
?>

<script type="text/javascript">
    $(document).ready(function() {
        var newButtons = '' +
            ' <li>' +
            ' <a href="#" class="hasUl"><span aria-hidden="true" class="icon16 icomoon-icon-hammer"></span>IMH Plugins<span class="hasDrop icon16 icomoon-icon-arrow-down-2"></span></a>' +
            '      <ul class="sub">';
        <?php foreach ($plugins as $plugin): ?>
            newButtons += '<li><a href="index.php?module=<?php echo $plugin['system']; ?>"><span class="icon16 icomoon-icon-arrow-right-3"></span><?php echo htmlspecialchars($plugin['title']); ?></a></li>';
        <?php endforeach; ?>
        newButtons += '      </ul>' +
            '</li>';
        $(".mainnav > ul").append(newButtons);
    });
</script>