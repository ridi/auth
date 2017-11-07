<?php
declare(strict_types=1);

namespace Ridibooks\Auth\Controller;

use Ridibooks\Auth\Library\UserCredentialStorage;
use Silex\Application;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class PasswordAuthController
{
    public function login(Request $request, Application $app)
    {
        $return_url = $request->get('return_url', '/');
        return $app['twig']->render('login.twig', [
            'return_url' => $return_url
        ]);
    }

    public function loginFormSubmit(Request $request, Application $app)
    {
        $user_id = $request->get('user_id');
        $password_to_check = $request->get('password');
        $return_url = $request->get('return_url', '/');

        /** @var UserCredentialStorage $user_credential_storage */
        $user_credential_storage = $app['oauth2.storage']['user_credentials'];
        if (!$user_credential_storage->checkUserCredentials($user_id, $password_to_check)) {
            return new Response('wrong credential', Response::HTTP_FORBIDDEN);
        }

        $user = $user_credential_storage->getUserDetails($user_id);
        $app['session']->set('user_idx', intval($user['idx']));
        $app['session']->set('user_id', $user['id']);
        $app['session']->set('user_name', $user['name']);
        return new RedirectResponse($return_url);
    }

    public function logout(Application $app)
    {
        $app['session']->invalidate();
        return new RedirectResponse('/');
    }
}
