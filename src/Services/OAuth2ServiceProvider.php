<?php
declare(strict_types=1);

namespace Ridibooks\Auth\Services;

use Doctrine\DBAL\Configuration;
use Doctrine\DBAL\DriverManager;
use OAuth2\GrantType\AuthorizationCode;
use OAuth2\GrantType\ClientCredentials;
use OAuth2\GrantType\RefreshToken;
use OAuth2\GrantType\UserCredentials;
use OAuth2\Server as OAuth2Server;
use OAuth2\Storage\Pdo as DefaultStorage;
use Pimple\Container;
use Pimple\ServiceProviderInterface;
use Ridibooks\Auth\Library\UserCredentialStorage;

class OAuth2ServiceProvider implements ServiceProviderInterface
{
    private function getConnection(array $db)
    {
        $config = new Configuration();
        return DriverManager::getConnection($db, $config);
    }

    private function getPDO(array $db)
    {
        $dsn = 'mysql:dbname=' . $db['dbname'] . ';';
        $dsn .= 'host=' . $db['host'] . ';';
        return new \PDO($dsn, $db['user'], $db['password']);
    }

    public function register(Container $app)
    {
        $app['oauth2.storage'] = function ($app) {
            $default_db = $app['oauth2.db']['default'];
            $default_storage = new DefaultStorage($this->getPDO($default_db));

            $user_credential_db = $app['oauth2.db']['user_credential'];
            $user_credential_db = isset($user_credential_db) ? $user_credential_db : $default_db;
            $user_credential_storage = new UserCredentialStorage($user_credential_db);

            return [
                'access_token' => null, // !! AccessToken storage is removed (Datas are stored in JWT token)
                'authorization_code' => $default_storage, // OAuth2\Storage\AuthorizationCodeInterface
                'client_credentials' => $default_storage, // OAuth2\Storage\ClientCredentialsInterface
                'client' => $default_storage, // OAuth2\Storage\ClientInterface
                'refresh_token' => $default_storage, // OAuth2\Storage\RefreshTokenInterface
                'user_credentials' => $user_credential_storage, // OAuth2\Storage\UserCredentialsInterface
                'user_claims' => $default_storage, // OAuth2\OpenID\Storage\UserClaimsInterface
                'public_key' => $default_storage, // OAuth2\Storage\PublicKeyInterface
                'jwt_bearer' => $default_storage, // OAuth2\Storage\JWTBearerInterface
                'scope' => $default_storage, // OAuth2\Storage\ScopeInterface
            ];
        };

        $app['oauth2.server'] = function ($app) {
            $storage = $app['oauth2.storage'];
            $server = new OAuth2Server($storage, [
                'auth_code_lifetime' => $_ENV['OAUTH_CODE_LIFETIME'],
                'access_lifetime' => $_ENV['OAUTH_ACCESS_LIFETIME'],
                'refresh_token_lifetime' => $_ENV['OAUTH_REFRESH_TOKEN_LIFETIME'],
                'use_jwt_access_tokens' => true,
                'store_encrypted_token_string' => true,
                'enforce_state' => true,
                'require_exact_redirect_uri' => true,
            ]);

            $server->addGrantType(new AuthorizationCode($storage['authorization_code']));
            $server->addGrantType(new ClientCredentials($storage['client_credentials']));
            $server->addGrantType(new UserCredentials($storage['user_credentials']));
            $server->addGrantType(new RefreshToken($storage['refresh_token'], [
                'always_issue_new_refresh_token' => true
            ]));

            return $server;
        };

        $app['oauth2.link_state'] = function ($app) {
            $connection = $this->getConnection($app['oauth2.db']['default']);
            return new OAuth2ClientGrantService($connection);
        };

        $app['oauth2'] = function ($app) {
            $connection = $this->getConnection($app['oauth2.db']['default']);
            return new OAuth2Service($connection, $app['oauth2.server'], $app['oauth2.link_state']);
        };
    }
}
