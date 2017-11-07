<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

if (is_readable(__DIR__ . '/.env')) {
    $dotenv = new Dotenv\Dotenv(__DIR__, '/.env');
    $dotenv->overload();
    $dotenv->required(['OAUTH_DB_HOST', 'OAUTH_DB_DBNAME', 'OAUTH_DB_USER', 'OAUTH_DB_PASSWORD']);
}
