<?php
declare(strict_types=1);

namespace Ridibooks\Tests\Auth\Services;

use Ridibooks\Auth\Services\OAuth2ClientGrantService;
use Ridibooks\Auth\Services\OAuth2Service;
use Ridibooks\Tests\Auth\OAuth2TestBase;
use Symfony\Component\HttpFoundation\Response;

class OAuth2ServiceTest extends OAuth2TestBase
{
    public function setUp()
    {
        self::createClient();
        self::createAuthorizeCode();
        self::createToken();
        self::createRefreshToken();
    }

    public function tearDown()
    {
        self::cleanRefreshTokens();
        self::cleanTokens();
        self::cleanAuthorizeCodes();
        self::cleanClient();
    }

    /**
     * @dataProvider validateAuthorizeRequestProvider
     */
    public function testValidateAuthorizeRequest($param, $expected)
    {
        $request = $this->createAuthorizeRequest($param);

        $service = $this->createOAuth2Service();
        $actual = $service->validateAuthorizeRequest($request);
        $this->assertSame($expected, $actual);
    }

    public function validateAuthorizeRequestProvider()
    {
        $default_param = [
            'client_id' => self::CLIENT_ID,
            'redirect_uri' => self::CLIENT_REDIRECT_URI,
            'state' => self::AUTHORIZE_STATE,
        ];

        return [
            'normal' => [
                $default_param,
                true,
            ],
            'empty client_id' => [
                array_merge($default_param, ['client_id' => null]),
                false,
            ],
            'wrong client_id' => [
                array_merge($default_param, ['client_id' => 'wrong_client_id']),
                false,
            ],
            'empty redirect_uri' => [
                array_merge($default_param, ['redirect_uri' => null]),
                true,
            ],
            'wrong redirect_uri' => [
                array_merge($default_param, ['redirect_uri' => 'wrong_redirect_uri']),
                false,
            ],
            'redirect_uri with param' => [
                array_merge($default_param, ['redirect_uri' => self::CLIENT_REDIRECT_URI . '?foo=bar']),
                false,
            ],
            'empty state' => [
                array_merge($default_param, ['state' => null]),
                false,
            ],
        ];
    }

    /**
     * @dataProvider handleAuthorizeRequestProvider
     * @depends testValidateAuthorizeRequest
     */
    public function testHandleAuthorizeRequest($param, $expected)
    {
        $request = $this->createAuthorizeRequest($param['request']);

        /* @var Response $response */
        $service = $this->createOAuth2Service();
        $response = $service->handleAuthorizeRequest($request, $param['user_id'], $param['is_authorized']);

        $actual_redirect = $response->headers->get('location');
        if ($actual_redirect) {
            $this->assertContains($expected['redirect'], $actual_redirect);

            parse_str(parse_url($actual_redirect, PHP_URL_QUERY), $actual);
            $this->assertSame($expected['code_exists'], !empty($actual['code']));
            $this->assertSame($expected['state'], empty($actual['state']) ? null : $actual['state']);
            $this->assertSame($expected['error'], empty($actual['error']) ? null : $actual['error']);
            $this->assertSame($expected['error_description'], empty($actual['error_description']) ? null : $actual['error_description']);
        } else {
            $this->assertSame($expected['redirect'], $actual_redirect);
        }
    }

    public function handleAuthorizeRequestProvider()
    {
        $default_param = [
            'request' => [
                'client_id' => self::CLIENT_ID,
                'redirect_uri' => self::CLIENT_REDIRECT_URI,
                'state' => self::AUTHORIZE_STATE,
            ],
            'user_id' => self::USER_IDX,
            'is_authorized' => true,
        ];

        $default_expected = [
            'redirect' => self::CLIENT_REDIRECT_URI,
            'code_exists' => true,
            'state' => self::AUTHORIZE_STATE,
            'error' => null,
            'error_description' => null,
        ];

        return [
            'authorized' => [
                $default_param,
                $default_expected,
            ],
            'denied' => [
                array_merge($default_param, ['is_authorized' => false]),
                array_merge($default_expected, [
                    'code_exists' => false,
                    'error' => 'access_denied',
                    'error_description' => 'The user denied access to your application',
                ]),
            ],
            'empty client_id' => [
                array_merge($default_param, ['request' => ['client_id' => null]]),
                array_merge($default_expected, ['redirect' => null]),
            ],
            'wrong client_id' => [
                array_merge($default_param, ['request' => ['client_id' => 'wrong_client_id']]),
                array_merge($default_expected, ['redirect' => null]),
            ],
            'empty redirect_uri' => [
                array_merge($default_param, ['request' => ['redirect_uri' => null]]),
                $default_expected,
            ],
            'wrong redirect_uri' => [
                array_merge($default_param, ['request' => ['redirect_uri' => 'wrong_redirect_uri']]),
                array_merge($default_expected, ['redirect' => null]),
            ],
            'redirect_uri with param' => [
                array_merge($default_param, ['request' => ['redirect_uri' => self::CLIENT_REDIRECT_URI . '?foo=bar']]),
                array_merge($default_expected, ['redirect' => null]),
            ],
            'empty state' => [
                array_merge($default_param, ['request' => ['state' => null]]),
                array_merge($default_expected, [
                    'code_exists' => false,
                    'state' => null,
                    'error' => 'invalid_request',
                    'error_description' => 'The state parameter is required',
                ]),
            ],
        ];
    }

    /**
     * @dataProvider handleTokenRequestProviderWithAuthrizationCode
     */
    public function testHandleTokenRequestWithAuthrizationCode($param, $expected)
    {
        $request = $this->createTokenRequestWithAuthorizationCode($param);

        /* @var Response $response */
        $service = $this->createOAuth2Service();
        $response = $service->handleTokenRequest($request);
        $actual = json_decode((string) $response->getContent(), true);

        $this->assertSame($expected['token_exists'], !empty($actual['access_token']));
        $this->assertSame($expected['refresh_token_exists'], !empty($actual['refresh_token']));
        $this->assertSame($expected['expires_in'], empty($actual['expires_in']) ? null : $actual['expires_in']);
        $this->assertSame($expected['token_type'], empty($actual['token_type']) ? null : $actual['token_type']);
        $this->assertSame($expected['scope'], empty($actual['scope']) ? null : $actual['scope']);
        $this->assertSame($expected['error'], empty($actual['error']) ? null : $actual['error']);
        $this->assertSame($expected['error_description'], empty($actual['error_description']) ? null : $actual['error_description']);
    }

    public function handleTokenRequestProviderWithAuthrizationCode()
    {
        $default_expected = [
            'token_exists' => true,
            'refresh_token_exists' => true,
            'expires_in' => '604800',
            'token_type' => 'Bearer',
            'scope' => null,
            'error' => null,
            'error_description' => null,
        ];

        $error_default_expected = [
            'token_exists' => false,
            'refresh_token_exists' => false,
            'expires_in' => null,
            'token_type' => null,
            'scope' => null,
            'error' => 'error',
            'error_description' => 'error_description',
        ];

        return [
            'normal' => [
                [],
                $default_expected
            ],
            'empty code' => [
                ['code' => null],
                array_merge($error_default_expected, [
                    'error' => 'invalid_request',
                    'error_description' => 'Missing parameter: "code" is required',
                ]),
            ],
            'wrong code' => [
                ['code' => 'wrong_code'],
                array_merge($error_default_expected, [
                    'error' => 'invalid_grant',
                    'error_description' => 'Authorization code doesn\'t exist or is invalid for the client',
                ]),
            ],
            'expired code' => [
                ['code' => self::AUTHORIZE_CODE_EXPIRED],
                array_merge($error_default_expected, [
                    'error' => 'invalid_grant',
                    'error_description' => 'The authorization code has expired',
                ]),
            ],
            'empty client' => [
                ['client_id' => null],
                array_merge($error_default_expected, [
                    'error' => 'invalid_client',
                    'error_description' => 'Client credentials were not found in the headers or body',
                ]),
            ],
            'wrong client' => [
                ['client_id' => 'wrong_client_id'],
                array_merge($error_default_expected, [
                    'error' => 'invalid_client',
                    'error_description' => 'The client credentials are invalid',
                ]),
            ],
            'empty client_secret' => [
                ['client_secret' => null],
                array_merge($error_default_expected, [
                    'error' => 'invalid_client',
                    'error_description' => 'This client is invalid or must authenticate using a client secret',
                ]),
            ],
            'wrong client_secret' => [
                ['client_secret' => 'wrong_client_secret'],
                array_merge($error_default_expected, [
                    'error' => 'invalid_client',
                    'error_description' => 'The client credentials are invalid',
                ]),
            ],
            'empty redirect_uri' => [
                ['redirect_uri' => null],
                array_merge($error_default_expected, [
                    'error' => 'redirect_uri_mismatch',
                    'error_description' => 'The redirect URI is missing or do not match',
                ]),
            ],
            'wrong redirect_uri' => [
                ['redirect_uri' => 'wrong_redirect_uri'],
                array_merge($error_default_expected, [
                    'error' => 'redirect_uri_mismatch',
                    'error_description' => 'The redirect URI is missing or do not match',
                ]),
            ],
            'redirect_uri with param' => [
                ['redirect_uri' => self::CLIENT_REDIRECT_URI . '?foo=bar'],
                array_merge($error_default_expected, [
                    'error' => 'redirect_uri_mismatch',
                    'error_description' => 'The redirect URI is missing or do not match',
                ]),
            ],
        ];
    }

    /**
     * @dataProvider handleTokenRequestProviderWithUserCredentials
     */
    public function testHandleTokenRequestWithUserCredentials($param, $expected)
    {
        $request = $this->createTokenRequestWithUserCredentials($param);

        /* @var Response $response */
        $service = $this->createOAuth2Service();
        $response = $service->handleTokenRequest($request);
        $actual = json_decode((string) $response->getContent(), true);

        $this->assertSame($expected['token_exists'], !empty($actual['access_token']));
        $this->assertSame($expected['refresh_token_exists'], !empty($actual['refresh_token']));
        $this->assertSame($expected['expires_in'], empty($actual['expires_in']) ? null : $actual['expires_in']);
        $this->assertSame($expected['token_type'], empty($actual['token_type']) ? null : $actual['token_type']);
        $this->assertSame($expected['scope'], empty($actual['scope']) ? null : $actual['scope']);
        $this->assertSame($expected['error'], empty($actual['error']) ? null : $actual['error']);
        $this->assertSame($expected['error_description'], empty($actual['error_description']) ? null : $actual['error_description']);
    }

    public function handleTokenRequestProviderWithUserCredentials()
    {
        $default_expected = [
            'token_exists' => true,
            'refresh_token_exists' => true,
            'expires_in' => '604800',
            'token_type' => 'Bearer',
            'scope' => null,
            'error' => null,
            'error_description' => null,
        ];

        $error_default_expected = [
            'token_exists' => false,
            'refresh_token_exists' => false,
            'expires_in' => null,
            'token_type' => null,
            'scope' => null,
            'error' => 'error',
            'error_description' => 'error_description',
        ];

        return [
            'normal' => [
                [],
                $default_expected
            ],
            'empty username' => [
                ['username' => null],
                array_merge($error_default_expected, [
                    'error' => 'invalid_request',
                    'error_description' => 'Missing parameters: "username" and "password" required',
                ]),
            ],
            'empty password' => [
                ['password' => null],
                array_merge($error_default_expected, [
                    'error' => 'invalid_request',
                    'error_description' => 'Missing parameters: "username" and "password" required',
                ]),
            ],
            'wrong username' => [
                ['username' => 'usernotexists'],
                array_merge($error_default_expected, [
                    'error' => 'invalid_grant',
                    'error_description' => 'Invalid username and password combination',
                ]),
            ],
            'wrong password' => [
                ['password' => 'passnotmatched'],
                array_merge($error_default_expected, [
                    'error' => 'invalid_grant',
                    'error_description' => 'Invalid username and password combination',
                ]),
            ],
            'empty client_id' => [
                ['client_id' => null],
                array_merge($error_default_expected, [
                    'error' => 'invalid_client',
                    'error_description' => 'Client credentials were not found in the headers or body',
                ]),
            ],
            'wrong client_id' => [
                ['client_id' => 'wrong_client_id'],
                array_merge($error_default_expected, [
                    'error' => 'invalid_client',
                    'error_description' => 'The client credentials are invalid',
                ]),
            ],
            'empty client_secret' => [
                ['client_secret' => null],
                array_merge($error_default_expected, [
                    'error' => 'invalid_client',
                    'error_description' => 'This client is invalid or must authenticate using a client secret',
                ]),
            ],
            'wrong client_secret' => [
                ['client_secret' => 'wrong_client_secret'],
                array_merge($error_default_expected, [
                    'error' => 'invalid_client',
                    'error_description' => 'The client credentials are invalid',
                ]),
            ],
        ];
    }

    /**
     * @dataProvider handleTokenRequestWithRefreshTokenProvider
     */
    public function testHandleTokenRequestWithRefreshToken($param, $expected)
    {
        $request = $this->createTokenRequestWithRefreshToken($param);

        /* @var Response $response */
        $service = $this->createOAuth2Service();
        $response = $service->handleTokenRequest($request);
        $actual = json_decode((string) $response->getContent(), true);

        $this->assertSame($expected['token_exists'], !empty($actual['access_token']));
        $this->assertSame($expected['refresh_token_exists'], !empty($actual['refresh_token']));
        $this->assertSame($expected['expires_in'], empty($actual['expires_in']) ? null : $actual['expires_in']);
        $this->assertSame($expected['token_type'], empty($actual['token_type']) ? null : $actual['token_type']);
        $this->assertSame($expected['scope'], empty($actual['scope']) ? null : $actual['scope']);
        $this->assertSame($expected['error'], empty($actual['error']) ? null : $actual['error']);
        $this->assertSame($expected['error_description'], empty($actual['error_description']) ? null : $actual['error_description']);
    }

    public function handleTokenRequestWithRefreshTokenProvider()
    {
        $default_expected = [
            'token_exists' => true,
            'refresh_token_exists' => true,
            'expires_in' => '604800',
            'token_type' => 'Bearer',
            'scope' => null,
            'error' => null,
            'error_description' => null,
        ];

        $error_default_expected = [
            'token_exists' => false,
            'refresh_token_exists' => false,
            'expires_in' => null,
            'token_type' => null,
            'scope' => null,
            'error' => 'error',
            'error_description' => 'error_description',
        ];

        return [
            'normal' => [
                [],
                $default_expected
            ],
            'empty refresh_token' => [
                ['refresh_token' => null],
                array_merge($error_default_expected, [
                    'error' => 'invalid_request',
                    'error_description' => 'Missing parameter: "refresh_token" is required',
                ]),
            ],
            'wrong refresh_code' => [
                ['refresh_token' => 'wrong_refresh_token'],
                array_merge($error_default_expected, [
                    'error' => 'invalid_grant',
                    'error_description' => 'Invalid refresh token',
                ]),
            ],
            'expired refresh_code' => [
                ['refresh_token' => self::REFRESH_TOKEN_EXPIRED],
                array_merge($error_default_expected, [
                    'error' => 'invalid_grant',
                    'error_description' => 'Refresh token has expired',
                ]),
            ],
            'empty client' => [
                ['client_id' => null],
                array_merge($error_default_expected, [
                    'error' => 'invalid_client',
                    'error_description' => 'Client credentials were not found in the headers or body',
                ]),
            ],
            'wrong client' => [
                ['client_id' => 'wrong_client_id'],
                array_merge($error_default_expected, [
                    'error' => 'invalid_client',
                    'error_description' => 'The client credentials are invalid',
                ]),
            ],
            'empty client_secret' => [
                ['client_secret' => null],
                array_merge($error_default_expected, [
                    'error' => 'invalid_client',
                    'error_description' => 'This client is invalid or must authenticate using a client secret',
                ]),
            ],
            'wrong client_secret' => [
                ['client_secret' => 'wrong_client_secret'],
                array_merge($error_default_expected, [
                    'error' => 'invalid_client',
                    'error_description' => 'The client credentials are invalid',
                ]),
            ],
        ];
    }

    /**
     * @dataProvider getTokenDataProvider
     */
    public function testGetTokenData($access_token, $expected)
    {
        $request = $this->createResourceRequest($access_token);

        $service = $this->createOAuth2Service();
        $actual = $service->getTokenData($request);

        $this->assertSame($expected['data_exists'], !empty($actual));
        if ($actual) {
            $this->assertSame($expected['access_token'], empty($actual['access_token']) ? null : $actual['access_token']);
            $this->assertSame($expected['client_id'], empty($actual['client_id']) ? null : $actual['client_id']);
            $this->assertSame($expected['user_id'], empty($actual['user_id']) ? null : $actual['user_id']);
            $this->assertSame($expected['expires'], empty($actual['expires']) ? null : $actual['expires']);
        }
    }

    public function getTokenDataProvider()
    {
        $default_expected = [
            'data_exists' => true,
            'access_token' => self::ACCESS_TOKEN,
            'client_id' => self::CLIENT_ID,
            'user_id' => strval(self::USER_IDX),
            'expires' => 1577836800,
        ];

        return [
            'normal' => [
                self::ACCESS_TOKEN,
                $default_expected,
            ],
            'empty token' => [
                null,
                ['data_exists' => false],
            ],
            'wrong token' => [
                'wrong token',
                ['data_exists' => false],
            ],
            'expired token' => [
                self::ACCESS_TOKEN_EXPIRED,
                ['data_exists' => false],
            ],
        ];
    }

    /**
     * @dataProvider handleRevokeRequestProvider
     */
    public function testHandleRevokeRequest($param, $expected)
    {
        $request = $this->createRevokeRequest($param);

        /* @var Response $response */
        $service = $this->createOAuth2Service();
        $response = $service->handleRevokeRequest($request);
        $actual = json_decode((string) $response->getContent(), true);

        $this->assertSame($expected['revoked'], empty($actual['revoked']) ? null : $actual['revoked']);
    }

    public function handleRevokeRequestProvider()
    {
        $default_expected = [
            'revoked' => true,
        ];

        return [
            'access token type' => [
                [],
                $default_expected,
            ],
            'refresh token type' => [
                ['token_type_hint' => 'refresh_token'],
                $default_expected,
            ],
            'empty token type hint' => [
                ['token_type_hint' => null],
                $default_expected,
            ],
            'wrong token type hint' => [
                ['token_type_hint' => 'wrong_token_type'],
                ['revoked' => null],
            ],
            'empty token' => [
                ['token' => null],
                ['revoked' => null],
            ],
            'wrong token' => [
                ['token' => 'wrong_token'],
                $default_expected,
            ],
        ];
    }
}
