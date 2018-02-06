<?php
declare(strict_types=1);

namespace Ridibooks\Tests\Auth;

use OAuth2\Encryption\Jwt;
use OAuth2\Storage\Pdo as DefaultStorage;
use Ridibooks\Auth\Library\UserCredentialStorage;

class TestDataWithRS256JWT extends TestData
{
    public function __construct()
    {
        parent::__construct();
        $this->client_id = 'test_client_rs256_jwt';
        $this->client_secret = 'test_client_pass_rs256_jwt';
        $this->token_type = 'bearer';
    }

    public function getOAuth2Config()
    {
        return [
            'auth_code_lifetime' => $_ENV['OAUTH_CODE_LIFETIME'],
            'access_lifetime' => $_ENV['OAUTH_ACCESS_LIFETIME'],
            'refresh_token_lifetime' => $_ENV['OAUTH_REFRESH_TOKEN_LIFETIME'],
            'enforce_state' => true,
            'use_jwt_access_tokens' => true,
            'issuer' => $_ENV['OAUTH_DOMAIN'],
            'require_exact_redirect_uri' => true,
        ];
    }

    public function createStorage(): array
    {
        $db = $this->getDB();
        $default_connection = $this->getPDO($db['default']);
        $default_storage = new DefaultStorage($default_connection);

        $user_credential_db = isset($db['user_credential']) ? $db['user_credential'] : $db['default'];
        $user_credential_storage = new UserCredentialStorage($user_credential_db);

        return [
            'access_token' => null,
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

    public function createMockIntropect()
    {
        return [
            'id' => $this->access_token_normal,
            'jti' => $this->access_token_normal,
            'iss' => $_ENV['OAUTH_DOMAIN'],
            'aud' => $this->client_id,
            'sub' => $this->user_idx,
            'iat' => 1500000000,
            'exp' => 1600000000,
            'token_type' => $this->token_type,
            'scope' => null,
        ];
    }

    public function createMockJwt($payload = null): string
    {
        $private_key = file_get_contents(__DIR__ . '/../id_rsa');
        $algorithm = 'RS256';
        $jwt = new Jwt();

        if (!isset($payload)) {
            $payload = $this->createMockIntropect();
        } else {
            $payload = array_merge($this->createMockIntropect(), $payload);
        }

        return $jwt->encode($payload, $private_key, $algorithm);
    }
}
