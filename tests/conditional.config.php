<?php

declare(strict_types=1);

/* Conditional configuration for phpstan.neon file. This is needed since some files cannot be analyzed on php7.4, but
   must be analyzed on php8 or higher */

$config = [];

if (PHP_VERSION_ID < 80000) {
    // These files are php8 only. Don't check on 7.4
    $config['parameters']['excludes_analyse'][] = 'src/Service/Cms/NativeService.php';
    $config['parameters']['excludes_analyse'][] = 'src/Service/Signature/NativeService.php';
}

return $config;
