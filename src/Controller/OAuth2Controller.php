<?php
declare(strict_types=1);

namespace Ridibooks\Auth\Controller;

use Ridibooks\Auth\Services\OAuth2Service;
use Silex\Application;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

class OAuth2Controller
{
    public function authorize(Request $request, Application $app)
    {
        /** @var OAuth2Service $oauth2_service */
        $oauth2_service = $app['oauth2'];

        if (!$oauth2_service->validateAuthorizeRequest($request)) {
            return $app['oauth2']->getResponse();
        }

        $user_idx = $app['session']->get('user_idx');
        $user_id = $app['session']->get('user_id');
        $client_id = $request->get('client_id');

        if ($oauth2_service->isGrantedClient($user_idx, $client_id)) {
            return $oauth2_service->handleAuthorizeRequest($request, $user_idx, true);
        }

        return $app['twig']->render('agreement.twig', [
            'user_id' => $user_id,
            'client_name' => $client_id,
        ]);
    }

    public function authorizeFormSubmit(Request $request, Application $app)
    {
        /** @var OAuth2Service $oauth2_service */
        $oauth2_service = $app['oauth2'];

        if (!$oauth2_service->validateAuthorizeRequest($request)) {
            return $oauth2_service->getResponse();
        }

        $user_idx = $app['session']->get('user_idx');
        $client_id = $request->get('client_id');
        $is_agreed = (bool) $request->get('agree', false);

        if ($is_agreed) {
            $oauth2_service->grant($user_idx, $client_id);
        } else {
            $oauth2_service->deny($user_idx, $client_id);
        }

        return $oauth2_service->handleAuthorizeRequest($request, $user_idx, $is_agreed);
    }

    public function token(Request $request, Application $app)
    {
        /** @var OAuth2Service $oauth2_service */
        $oauth2_service = $app['oauth2'];
        return $oauth2_service->handleTokenRequest($request);
    }

    public function tokenInfo(Request $request, Application $app)
    {
        /** @var OAuth2Service $oauth2_service */
        $oauth2_service = $app['oauth2'];
        $token_data = $oauth2_service->getTokenData($request);
        if (!$token_data) {
            return $oauth2_service->getResponse();
        }

        return JsonResponse::create([
            'token_type' => $token_data['token_type'],
            'client_id' => $token_data['client_id'],
            'user_idx' => $token_data['user_id'],
            'scope' => $token_data['scope'],
            'expires' => $token_data['expires'],
        ]);
    }

    public function revoke(Request $request, Application $app)
    {
        /** @var OAuth2Service $oauth2_service */
        $oauth2_service = $app['oauth2'];
        return $oauth2_service->handleRevokeRequest($request);
    }
}
