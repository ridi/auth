<?php
declare(strict_types=1);

namespace Ridibooks\Tests\Auth\Services;

use Pimple\Container;
use Ridibooks\Auth\Services\OAuth2ServiceProvider;
use Ridibooks\Tests\Auth\TestBase;

class OAuth2ServiceProviderTest extends TestBase
{
    public function testRegister()
    {
        $app = new Container([
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

        $service_provider = new OAuth2ServiceProvider();
        $service_provider->register($app);

        $this->assertArrayHasKey('oauth2.storage', $app);
        $oauth2_storage = $app['oauth2.storage'];

        $this->assertArrayHasKey('access_token', $oauth2_storage);
        $this->assertNull($oauth2_storage['access_token']);
        $this->assertInstanceOf('\OAuth2\Storage\AuthorizationCodeInterface', $oauth2_storage['authorization_code']);
        $this->assertInstanceOf('\OAuth2\Storage\ClientCredentialsInterface', $oauth2_storage['client_credentials']);
        $this->assertInstanceOf('\OAuth2\Storage\ClientInterface', $oauth2_storage['client']);
        $this->assertInstanceOf('\OAuth2\Storage\RefreshTokenInterface', $oauth2_storage['refresh_token']);
        $this->assertInstanceOf('\Ridibooks\Auth\Library\UserCredentialStorage', $oauth2_storage['user_credentials']);
        $this->assertInstanceOf('\OAuth2\OpenID\Storage\UserClaimsInterface', $oauth2_storage['user_claims']);
        $this->assertInstanceOf('\OAuth2\Storage\PublicKeyInterface', $oauth2_storage['public_key']);
        $this->assertInstanceOf('\OAuth2\Storage\JWTBearerInterface', $oauth2_storage['jwt_bearer']);
        $this->assertInstanceOf('\OAuth2\Storage\ScopeInterface', $oauth2_storage['scope']);

        $this->assertArrayHasKey('oauth2.server', $app);
        $this->assertInstanceOf('\OAuth2\Server', $app['oauth2.server']);

        $this->assertArrayHasKey('oauth2.client_grant', $app);
        $this->assertInstanceOf('\Ridibooks\Auth\Services\OAuth2ClientGrantService', $app['oauth2.client_grant']);

        $this->assertArrayHasKey('oauth2', $app);
        $this->assertInstanceOf('\Ridibooks\Auth\Services\OAuth2Service', $app['oauth2']);
    }
}
