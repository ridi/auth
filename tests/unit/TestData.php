<?php
declare(strict_types=1);

namespace Ridibooks\Tests\Auth;

use Doctrine\DBAL\Configuration;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Types\Type;
use OAuth2\GrantType\AuthorizationCode;
use OAuth2\GrantType\RefreshToken;
use OAuth2\GrantType\UserCredentials;
use OAuth2\Server as OAuth2Server;
use OAuth2\Storage\Pdo as DefaultStorage;
use Ridibooks\Auth\Library\UserCredentialStorage;
use Ridibooks\Auth\Services\OAuth2ClientGrantService;
use Ridibooks\Auth\Services\OAuth2Service;
use Symfony\Component\HttpFoundation\Request;

class TestData
{
    const AUTHORIZE_PATH = 'http://ridibooks.com/auth/oauth2/authorize';
    const TOKEN_PATH = 'http://ridibooks.com/auth/oauth2/token';
    const REVOKE_PATH = 'http://ridibooks.com/auth/oauth2/revoke';
    const RESOURCE_PATH = 'http://ridibooks.com/api/some/resource';
    const CLIENT_REDIRECT_URI = 'http://fake.com/receive';
    const AUTHORIZE_STATE = 'test_state';

    public $authorize_path;
    public $token_path;
    public $revoke_path;
    public $resource_path;

    public $client_redirect_uri;
    public $authorize_state;
    public $token_type;

    public $user_id;
    public $user_idx;
    public $user_idx_old;
    public $user_idx_new;
    public $user_pass;

    public $client_id;
    public $client_id_old;
    public $client_id_new;
    public $client_secret;

    public $authorize_code_normal;
    public $authorize_code_expired;
    public $access_token_normal;
    public $access_token_expired;
    public $refresh_token_normal;
    public $refresh_token_expired;

    public function __construct()
    {
        $this->authorize_path = 'http://ridibooks.com/auth/oauth2/authorize';
        $this->token_path = 'http://ridibooks.com/auth/oauth2/token';
        $this->revoke_path = 'http://ridibooks.com/auth/oauth2/revoke';
        $this->resource_path = 'http://ridibooks.com/api/some/resource';

        $this->client_redirect_uri = 'http://fake.com/receive';
        $this->authorize_state = 'test_state';
        $this->token_type = 'Bearer';

        $this->user_id = 'testuser';
        $this->user_idx = 1;
        $this->user_idx_old = 11111111;
        $this->user_idx_new = 22222222;
        $this->user_pass = '112233';

        $this->client_id = 'test_client';
        $this->client_id_old = 'test_client_id_old';
        $this->client_id_new = 'test_client_id_new';
        $this->client_secret = 'test_client_pass';

        $this->authorize_code_normal = 'test_authorize_code';
        $this->authorize_code_expired = 'test_authorize_code_expired';
        $this->access_token_normal = 'test_access_token';
        $this->access_token_expired = 'test_access_token_expired';
        $this->refresh_token_normal = 'test_refresh_token';
        $this->refresh_token_expired = 'test_refresh_token_expired';
    }

    public function setUp()
    {
        $this->createAuthorizeCode();
        $this->createToken();
        $this->createRefreshToken();
        $this->createClientGrant();
    }

    public function tearDown()
    {
        $this->cleanClientGrant();
        $this->cleanRefreshTokens();
        $this->cleanTokens();
        $this->cleanAuthorizeCodes();
    }

    public function getDB()
    {
        return [
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
            ]
        ];
    }

    public function getConnection($index)
    {
        $db = $this->getDB();
        $config = new Configuration();
        return DriverManager::getConnection($db[$index], $config);
    }

    public function getPDO(array $db)
    {
        $dsn = 'mysql:dbname=' . $db['dbname'] . ';';
        $dsn .= 'host=' . $db['host'] . ';';
        return new \PDO($dsn, $db['user'], $db['password']);
    }

    public function getOAuth2Config()
    {
        return [
            'auth_code_lifetime' => $_ENV['OAUTH_CODE_LIFETIME'],
            'access_lifetime' => $_ENV['OAUTH_ACCESS_LIFETIME'],
            'refresh_token_lifetime' => $_ENV['OAUTH_REFRESH_TOKEN_LIFETIME'],
            'enforce_state' => true,
            'require_exact_redirect_uri' => true,
        ];
    }

    public function createOAuth2Server(): OAuth2Server
    {
        $storage = $this->createStorage();

        $config = $this->getOAuth2Config();
        $server = new OAuth2Server($storage, $config);
        $server->addGrantType(new AuthorizationCode($storage['authorization_code']));
        $server->addGrantType(new UserCredentials($storage['user_credentials']));
        $server->addGrantType(new RefreshToken($storage['refresh_token'], [
            'always_issue_new_refresh_token' => true
        ]));

        return $server;
    }

    public function createOAuth2Service(): OAuth2Service
    {
        $server = $this->createOAuth2Server();
        $connection = $this->getConnection('default');
        $client_grant = new OAuth2ClientGrantService($connection);
        return new OAuth2Service($connection, $server, $client_grant);
    }

    public function createStorage(): array
    {
        $db = $this->getDB();
        $default_connection = $this->getPDO($db['default']);
        $default_storage = new DefaultStorage($default_connection);

        $user_credential_db = isset($db['user_credential']) ? $db['user_credential'] : $db['default'];
        $user_credential_storage = new UserCredentialStorage($user_credential_db);

        return [
            'access_token' => $default_storage, // OAuth2\Storage\AccessTokenInterface
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
    }

    public function createClient()
    {
        $this->cleanClient();

        $db = $this->getConnection('default');
        $db->insert(
            'oauth_clients',
            [
                'client_id' => $this->client_id,
                'client_secret' => $this->client_secret,
                'redirect_uri' => $this->client_redirect_uri,
            ],
            [Type::STRING, Type::STRING, Type::STRING]
        );
    }

    public function createClientGrant()
    {
        $this->cleanClientGrant();

        $db = $this->getConnection('default');
        $db->insert(
            'oauth_client_grants',
            [
                'user_idx' => $this->user_idx_old,
                'client_id' => $this->client_id_old,
            ],
            [Type::INTEGER, Type::STRING]
        );
    }

    public function cleanClientGrant()
    {
        $db = $this->getConnection('default');
        $db->executeQuery(
            "DELETE FROM oauth_client_grants WHERE user_idx IN (?)",
            [[$this->user_idx_old, $this->user_idx_new]],
            [Connection::PARAM_STR_ARRAY]
        );
    }

    public function createAuthorizeCode()
    {
        $this->cleanAuthorizeCodes();

        $db = $this->getConnection('default');
        $db->insert(
            'oauth_authorization_codes',
            [
                'authorization_code' => $this->authorize_code_normal,
                'client_id' => $this->client_id,
                'user_id' => $this->user_idx,
                'redirect_uri' => $this->client_redirect_uri,
                'expires' => new \DateTime('2020-01-01 00:00:00'),
            ],
            [Type::STRING, Type::STRING, Type::INTEGER, Type::STRING, Type::DATETIME]
        );

        $db->insert(
            'oauth_authorization_codes',
            [
                'authorization_code' => $this->authorize_code_expired,
                'client_id' => $this->client_id,
                'user_id' => $this->user_idx,
                'redirect_uri' => $this->client_redirect_uri,
                'expires' => new \DateTime('2017-01-01 00:00:00'),
            ],
            [Type::STRING, Type::STRING, Type::INTEGER, Type::STRING, Type::DATETIME]
        );
    }

    public function createToken()
    {
        $this->cleanTokens();

        $db = $this->getConnection('default');
        $db->insert(
            'oauth_access_tokens',
            [
                'access_token' => $this->access_token_normal,
                'client_id' => $this->client_id,
                'user_id' => $this->user_idx,
                'expires' => new \DateTime('2020-01-01 00:00:00'),
            ],
            [Type::STRING, Type::STRING, Type::INTEGER, Type::DATETIME]
        );

        $db->insert(
            'oauth_access_tokens',
            [
                'access_token' => $this->access_token_expired,
                'client_id' => $this->client_id,
                'user_id' => $this->user_idx,
                'expires' => new \DateTime('2017-01-01 00:00:00'),
            ],
            [Type::STRING, Type::STRING, Type::INTEGER, Type::DATETIME]
        );
    }

    public function createRefreshToken()
    {
        $this->cleanRefreshTokens();

        $db = $this->getConnection('default');
        $db->insert(
            'oauth_refresh_tokens',
            [
                'refresh_token' => $this->refresh_token_normal,
                'client_id' => $this->client_id,
                'user_id' => $this->user_idx,
                'expires' => new \DateTime('2020-01-01 00:00:00'),
            ],
            [Type::STRING, Type::STRING, Type::INTEGER, Type::DATETIME]
        );

        $db->insert(
            'oauth_refresh_tokens',
            [
                'refresh_token' => $this->refresh_token_expired,
                'client_id' => $this->client_id,
                'user_id' => $this->user_idx,
                'expires' => new \DateTime('2017-01-01 00:00:00'),
            ],
            [Type::STRING, Type::STRING, Type::INTEGER, Type::DATETIME]
        );
    }

    public function cleanTokens()
    {
        $db = $this->getConnection('default');
        $db->delete(
            'oauth_access_tokens',
            [
                'user_id' => $this->user_idx,
                'client_id' => $this->client_id,
            ],
            [Type::INTEGER, Type::STRING]
        );
    }

    public function cleanRefreshTokens()
    {
        $db = $this->getConnection('default');
        $db->delete(
            'oauth_refresh_tokens',
            [
                'user_id' => $this->user_idx,
                'client_id' => $this->client_id,
            ],
            [Type::INTEGER, Type::STRING]
        );
    }

    public function cleanAuthorizeCodes()
    {
        $db = $this->getConnection('default');
        $db->delete(
            'oauth_authorization_codes',
            [
                'user_id' => $this->user_idx,
                'client_id' => $this->client_id,
            ],
            [Type::INTEGER, Type::STRING]
        );
    }

    public function cleanClient()
    {
        $db = $this->getConnection('default');
        $db->delete(
            'oauth_clients',
            [
                'client_id' => $this->client_id,
            ],
            [Type::STRING]
        );
    }

    public function getAuthorizationCodes($user_idx, $client_id)
    {
        $db = $this->getConnection('default');
        $rows = $db->fetchAll(
            "SELECT * FROM oauth_authorization_codes WHERE user_id=? AND client_id=?",
            [$user_idx, $client_id],
            [Type::INTEGER, Type::STRING]
        );

        return $rows;
    }

    public function getAccessTokens($user_idx, $client_id)
    {
        $db = $this->getConnection('default');
        $rows = $db->fetchAll(
            "SELECT * FROM oauth_access_tokens WHERE user_id=? AND client_id=?",
            [$user_idx, $client_id],
            [Type::INTEGER, Type::STRING]
        );

        return $rows;
    }

    public function getClientGrants($user_idx, $client_id)
    {
        $db = $this->getConnection('default');
        $rows = $db->fetchAll(
            "SELECT * FROM oauth_client_grants WHERE user_idx=? AND client_id=? AND deleted_at is null",
            [$user_idx, $client_id],
            [Type::INTEGER, Type::STRING]
        );

        return $rows;
    }

    public function createAuthorizeRequest($param = []): Request
    {
        $default = [
            'response_type' => 'code',
            'client_id' => $this->client_id,
            'redirect_uri' => $this->client_redirect_uri,
            'state' => $this->authorize_state,
        ];

        $param = array_merge($default, $param);
        return Request::create($this->authorize_path, 'GET', $param);
    }

    public function createTokenRequestWithAuthorizationCode($param = []): Request
    {
        $default = [
            'grant_type' => 'authorization_code',
            'client_id' => $this->client_id,
            'client_secret' => $this->client_secret,
            'code' => $this->authorize_code_normal,
            'redirect_uri' => $this->client_redirect_uri,
        ];

        $param = array_merge($default, $param);
        return Request::create($this->token_path, 'POST', $param);
    }

    public function createTokenRequestWithUserCredentials($param = []): Request
    {
        $default = [
            'grant_type' => 'password',
            'client_id' => $this->client_id,
            'client_secret' => $this->client_secret,
            'username' => $this->user_id,
            'password' => $this->user_pass,
        ];

        $param = array_merge($default, $param);
        return Request::create($this->token_path, 'POST', $param);
    }

    public function createTokenRequestWithRefreshToken($param = []): Request
    {
        $default = [
            'grant_type' => 'refresh_token',
            'client_id' => $this->client_id,
            'client_secret' => $this->client_secret,
            'refresh_token' => $this->refresh_token_normal,
        ];

        $param = array_merge($default, $param);
        return Request::create($this->token_path, 'POST', $param);
    }

    public function createRevokeRequest($param): Request
    {
        $default = [
            'token_type_hint' => 'access_token',
            'token' => $this->access_token_normal,
        ];

        $param = array_merge($default, $param);
        return Request::create($this->revoke_path, 'POST', $param);
    }

    public function createResourceRequest($access_token): Request
    {
        return Request::create($this->resource_path, 'POST', [
            'access_token' => $access_token,
        ]);
    }

    public function createMockOAuth2Data()
    {
        return [
            'access_token' => $this->access_token_normal,
            'client_id' => $this->client_id,
            'user_id' => $this->user_idx,
            'expires' => 1600000000,
            'scope' => null,
        ];
    }

    public function createMockIntropect()
    {
        return [
            'id' => $this->access_token_normal,
            'jti' => $this->access_token_normal,
            'iss' => $_ENV['OAUTH_DOMAIN'],
            'aud' => $this->client_id,
            'sub' => $this->user_idx,
            'exp' => 1600000000,
            'token_type' => $this->token_type,
            'scope' => null,
        ];
    }
}
