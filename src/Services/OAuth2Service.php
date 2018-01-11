<?php
declare(strict_types=1);

namespace Ridibooks\Auth\Services;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Types\Type;
use OAuth2\Encryption\Jwt;
use OAuth2\HttpFoundationBridge\Request as BridgeRequest;
use OAuth2\HttpFoundationBridge\Response as BridgeResponse;
use OAuth2\ResponseInterface;
use OAuth2\Server as OAuth2Server;
use OAuth2\TokenType\Bearer;
use Symfony\Component\HttpFoundation\Request;

class OAuth2Service
{
    /** @var Connection $db */
    private $connection;

    /** @var OAuth2Server $server */
    private $server;

    /** @var OAuth2ClientGrantService $link_state */
    private $link_state;

    public function __construct(Connection $connection, OAuth2Server $server, OAuth2ClientGrantService $link_state)
    {
        $this->connection = $connection;
        $this->server = $server;
        $this->link_state = $link_state;
    }

    public function setTokenStorage($storage)
    {
        $this->server->addStorage($storage, 'access_token');
    }

    public function setKeyStorage($storage)
    {
        $this->server->addStorage($storage, 'public_key');
    }

    public function validateAuthorizeRequest(Request $request): bool
    {
        $request = BridgeRequest::createFromRequest($request);
        $response = BridgeResponse::create();
        return $this->server->validateAuthorizeRequest($request, $response);
    }

    public function handleAuthorizeRequest(Request $request, int $user_id, bool $is_authorized): ResponseInterface
    {
        $request = BridgeRequest::createFromRequest($request);
        $response = BridgeResponse::create();
        if (!$this->server->validateAuthorizeRequest($request, $response)) {
            return $this->server->getResponse();
        }

        return $this->server->handleAuthorizeRequest($request, $response, $is_authorized, $user_id);
    }

    public function handleTokenRequest(Request $request): ResponseInterface
    {
        $bridge_request = BridgeRequest::createFromRequest($request);
        $bridge_response = BridgeResponse::create();
        return $this->server->handleTokenRequest($bridge_request, $bridge_response);
    }

    public function handleRevokeRequest(Request $request): ResponseInterface
    {
        $bridge_request = BridgeRequest::createFromRequest($request);
        $bridge_response = BridgeResponse::create();
        return $this->server->handleRevokeRequest($bridge_request, $bridge_response);
    }

    public function verifyResourceRequest(Request $request)
    {
        $bridge_request = BridgeRequest::createFromRequest($request);
        $bridge_response = BridgeResponse::create();
        return $this->server->verifyResourceRequest($bridge_request, $bridge_response);
    }

    public function getTokenParam(Request $request): string
    {
        $bridge_request = BridgeRequest::createFromRequest($request);
        $bridge_response = BridgeResponse::create();

        $bearer = new Bearer([
            'token_param_name' => 'access_token',
            'token_bearer_header_name' => 'Bearer',
        ]);

        return (string)$bearer->getAccessTokenParameter($bridge_request, $bridge_response);
    }

    /* @see https://tools.ietf.org/html/rfc7662#section-2.2 */
    public function getIntrospect(string $token_param): array
    {
        $active = true;
        $token_data = null;

        // Check revoked
        if ($active) {
            $token_storage = $this->server->getStorage('access_token');
            $token_data = $token_storage->getAccessToken($token_param);
            if (!$token_data) {
                $active = false;
            }
        }

        // Check time validity
        if ($active) {
            $now = time();
            if ($token_data['expires'] < $now) {
                $active = false;
            }
        }

        if ($active) {
            return [
                'active' => true,
                'client_id' => $token_data['client_id'],
                'token_type' => 'Bearer',
                'exp' => $token_data['expires'],
                'sub' => $token_data['user_id'],
                'aud' => $token_data['client_id'],
                'iss' => $_ENV['OAUTH_DOMAIN'],
            ];
        } else {
            return [
                'active' => false
            ];
        }
    }

    /* @see https://tools.ietf.org/html/rfc7662#section-2.2 */
    public function getIntrospectWithJWT(string $token_param): array
    {
        $active = true;

        $jwt = new Jwt();
        $token_data = $jwt->decode($token_param, null, false);

        // Malformed token param
        if ($token_data === false) {
            $active = false;
        }

        // Revoked
        if ($active) {
            $token_storage = $this->server->getStorage('access_token');
            if (!$token_storage->getAccessToken($token_param)) {
                $active = false;
            }
        }

        // Check time validity
        if ($active) {
            $now = time();
            if ($now < $token_data['iat'] || $token_data['exp'] < $now) {
                $active = false;
            }
        }

        if ($active) {
            $client_id = $token_data['aud'];
            $key_storage = $this->server->getStorage('public_key');
            $public_key = $key_storage->getPublicKey($client_id);
            $algorithm = $key_storage->getEncryptionAlgorithm($client_id);
            $token_data = $jwt->decode($token_param, $public_key, [$algorithm]);
            if ($token_data === false) {
                $active = false;
            }
        }

        if ($active) {
            return [
                'active' => true,
                'client_id' => $token_data['aud'],
                'token_type' => 'Bearer',
                'exp' => $token_data['exp'],
                'iat' => $token_data['iat'],
                'sub' => $token_data['sub'],
                'aud' => $token_data['aud'],
                'iss' => $token_data['iss'],
            ];
        } else {
            return [
                'active' => false
            ];
        }
    }

    public function getResponse(): ResponseInterface
    {
        return $this->server->getResponse();
    }

    public function isGrantedClient(int $user_id, string $client_id): bool
    {
        return $this->link_state->isGrantedClient($user_id, $client_id);
    }

    public function grant(int $user_id, string $client_id)
    {
        $this->link_state->grant($user_id, $client_id);
    }

    public function deny(int $user_id, string $client_id)
    {
        $this->link_state->deny($user_id, $client_id);
        $this->revokeAllAuthorizationCode($user_id, $client_id);
        $this->revokeAllToken($user_id, $client_id);
    }

    private function revokeAllAuthorizationCode(int $user_id, string $client_id)
    {
        $this->connection->delete('oauth_authorization_codes', [
            'user_id' => $user_id,
            'client_id' => $client_id,
        ], [Type::STRING, Type::STRING]);
    }

    private function revokeAllToken(int $user_id, string $client_id)
    {
        $this->connection->delete('oauth_access_tokens', [
            'user_id' => $user_id,
            'client_id' => $client_id,
        ], [Type::STRING, Type::STRING]);
        $this->connection->delete('oauth_refresh_tokens', [
            'user_id' => $user_id,
            'client_id' => $client_id,
        ], [Type::STRING, Type::STRING]);
    }
}
