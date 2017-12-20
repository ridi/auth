<?php
declare(strict_types=1);

use Ridibooks\Auth\Controller\AuthControllerProvider;
use Ridibooks\Auth\Services\OAuth2ServiceProvider;
use Silex\Application;
use Silex\Provider\SessionServiceProvider;
use Silex\Provider\TwigServiceProvider;
use Symfony\Component\HttpFoundation\RedirectResponse;

$app = new Application([
    'debug' => $_ENV['DEBUG'],
]);

$app->register(new TwigServiceProvider(), [
    'twig.options' => [
        'cache' => __DIR__ . '/../var/cache',
        'auto_reload' => true,
    ],
    'twig.path' => [
        __DIR__ . '/../views',
    ],
]);

$app->register(new OAuth2ServiceProvider(), [
    'oauth2.db' => [
        'default' => [
            'host' => $_ENV['OAUTH_DBHOST'],
            'port' => (getenv('OAUTH_DBPORT') === false) ? 3306 : $_ENV['OAUTH_DBPORT'],
            'dbname' => $_ENV['OAUTH_DBNAME'],
            'user' => $_ENV['OAUTH_DBUSER'],
            'password' => $_ENV['OAUTH_DBPASS'],
            'driver' => 'pdo_mysql',
            'charset' => 'utf8',
        ],
        'user_credential' => [
            'host' => $_ENV['USER_DBHOST'],
            'port' => (getenv('USER_DBPORT') === false) ? 3306 : $_ENV['USER_DBPORT'],
            'dbname' => $_ENV['USER_DBNAME'],
            'user' => $_ENV['USER_DBUSER'],
            'password' => $_ENV['USER_DBPASS'],
            'driver' => 'pdo_mysql',
            'charset' => 'utf8',
        ],
    ]
]);

$app->register(new SessionServiceProvider(), [
    'session.storage.save_path' => __DIR__ . '/../var/sessions',
    'session.storage.options' => [
        'cookie_lifttime' => 60 * 60 * 24 * 90,
        'cookie_path' => '/',
        'cookie_domain' => $_ENV['OAUTH_DOMAIN'],
    ],
]);

$app->get('/', function (Application $app) {
    return new RedirectResponse('https://ridibooks.com');
});

$app->mount('/auth', new AuthControllerProvider());

return $app;
