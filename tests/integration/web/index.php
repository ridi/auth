<?php
declare(strict_types=1);

use Ridibooks\Auth\Library\UserCredentialStorage;
use Silex\Application;
use Ridibooks\Auth\Library\MiddlewareFactory;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

require_once __DIR__ . '/../../bootstrap.php';
$app = require_once __DIR__ . '/../../../src/app.php';



// End points for test

$app->post('/auth/test-login', function (Application $app, Request $request) {
    $user_id = $request->get('user_id');
    $password_to_check = $request->get('password');

    /** @var UserCredentialStorage $user_credential_storage */
    $user_credential_storage = $app['oauth2.storage']['user_credentials'];
    if (!$user_credential_storage->checkUserCredentials($user_id, $password_to_check)) {
        return $app->json(['message' => 'wrong credential'], Response::HTTP_INTERNAL_SERVER_ERROR);
    }

    $user = $user_credential_storage->getUserDetails($user_id);
    $app['session']->set('user_idx', (int) $user['idx']);
    $app['session']->set('user_id', $user['id']);

    return $app->json(['cookie' => session_name() . '=' . session_id()]);
});

$app->match('/auth/test-resource', function (Application $app, Request $request) {
    return $app->json([
        'client_id' => $request->attributes->get('client_id'),
        'user_idx' => $request->attributes->get('user_idx'),
    ]);
})->before(MiddlewareFactory::validateOAuth2Token());



if (isset($app['session'])) {
    $app['session']->start();
}

$app->run();
