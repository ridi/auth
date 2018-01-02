<?php
declare(strict_types=1);

namespace Ridibooks\Auth\Controller;

use Ridibooks\Auth\Library\MiddlewareFactory;
use Silex\Api\ControllerProviderInterface;
use Silex\Application;
use Silex\ControllerCollection;

class AuthControllerProvider implements ControllerProviderInterface
{
    public function connect(Application $app)
    {
        /** @var ControllerCollection $controllers */
        $controllers = $app['controllers_factory'];

        $oauth2 = new OAuth2Controller();
        $controllers->get('/oauth2/authorize', [$oauth2, 'authorize'])
            ->before(MiddlewareFactory::validateLogin());
        $controllers->post('/oauth2/authorize', [$oauth2, 'authorizeFormSubmit'])
            ->before(MiddlewareFactory::validateLogin());
        $controllers->post('/oauth2/token', [$oauth2, 'token']);
        $controllers->post('/oauth2/revoke', [$oauth2, 'revoke']);
        $controllers->post('/oauth2/tokeninfo', [$oauth2, 'tokenInfo']);

        $password_auth = new PasswordAuthController();
        $controllers->get('/login', [$password_auth, 'login']);
        $controllers->post('/login', [$password_auth, 'loginFormSubmit']);
        $controllers->get('/logout', [$password_auth, 'logout']);

        return $controllers;
    }
}
