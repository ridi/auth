<?php
declare(strict_types=1);

namespace Ridibooks\Auth\Library;

use Ridibooks\Auth\Services\OAuth2Service;
use Silex\Application;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class MiddlewareFactory
{
    public static function validateOAuth2Token(): \Closure
    {
        return function (Request $request, Application $app) {
            // Verify token
            /* @var $oauth2_service OAuth2Service */
            $oauth2_service = $app['oauth2'];
            if (!$oauth2_service->verifyResourceRequest($request)) {
                return $oauth2_service->getResponse();
            }

            // Check revoked
            $token_param = $oauth2_service->getTokenParam($request);
            if ($oauth2_service->getConfig('use_jwt_access_tokens')) {
                $token_data = $oauth2_service->getIntrospectionWithJWT($token_param);
            } else {
                $token_data = $oauth2_service->getIntrospection($token_param);
            }

            if ($token_data['active'] === false) {
                return JsonResponse::create([
                    'error' => 'invalid_token',
                    'error_description' => 'The access token provided is invalid',
                ], Response::HTTP_UNAUTHORIZED);
            }

            $request->attributes->set('user_idx', $token_data['sub'] ?? null);
            $request->attributes->set('client_id', $token_data['aud'] ?? null);
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
