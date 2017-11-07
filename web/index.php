<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

if (is_readable(__DIR__ . '/../.env')) {
    $dotenv = new Dotenv\Dotenv(__DIR__, '/../.env');
    $dotenv->overload();
    $dotenv->required([
        'OAUTH_DBHOST',
        'OAUTH_DBNAME',
        'OAUTH_DBUSER',
        'OAUTH_DBPASS',
        'USER_DBHOST',
        'USER_DBNAME',
        'USER_DBUSER',
        'USER_DBPASS',
    ]);
}

$app = require_once __DIR__ . '/../src/app.php';

if (isset($app['session'])) {
    $app['session']->start();
}

$app->run();
