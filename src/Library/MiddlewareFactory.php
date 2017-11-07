<?php
declare(strict_types=1);

namespace Ridibooks\Auth\Library;

use Silex\Application;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class MiddlewareFactory
{
    public static function validateOAuth2Token(): \Closure
    {
        return function (Request $request, Application $app) {
            $oauth2_service = $app['oauth2'];
            $token_data = $oauth2_service->getTokenData($request);
            if (!$token_data) {
                return $oauth2_service->getResponse();
            }

            $request->attributes->set('user_idx', $token_data['user_id']);
            $request->attributes->set('client_id', $token_data['client_id']);
            return null;
        };
    }

    public static function validateLogin(): \Closure
    {
        return function (Request $request, Application $app) {
            $user_id = $app['session']->get('user_id');
            if (!isset($user_id)) {
                $return_url = '/auth/login?return_url=' . urlencode($request->getRequestUri());
                return new RedirectResponse($return_url, Response::HTTP_FOUND);
            }

            return null;
        };
    }
}
