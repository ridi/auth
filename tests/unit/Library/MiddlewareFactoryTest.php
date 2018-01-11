<?php
declare(strict_types=1);

namespace Ridibooks\Tests\Auth\Library;

use Ridibooks\Auth\Library\MiddlewareFactory;
use Ridibooks\Tests\Auth\OAuth2ServiceTestBase;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class MiddlewareFactoryTest extends OAuth2ServiceTestBase
{
    /**
     * @dataProvider validateOAuth2TokenProvider
     */
    public function testValidateOAuth2Token($request, $token, $expected)
    {
        $validator = MiddlewareFactory::validateOAuth2Token();

        if ($expected['status'] === null) {
            $payload = $this->createMockOAuth2Data();
        } else {
            $payload = false;
        }

        $mock_storage = $this->createMockObject('\OAuth2\Storage\AccessTokenInterface', [
            'getAccessToken' => ['input' => $token, 'output' => $payload],
        ]);

        $oauth2_service = $this->createOAuth2Service(false);
        $oauth2_service->setTokenStorage($mock_storage);
        $container = new Application([
            'oauth2' => $oauth2_service,
        ]);

        $actual_result = $validator($request, $container);

        $actual_content = null;
        $actual_status = null;
        if ($actual_result instanceof Response) {
            $actual_content = $actual_result->getContent();
            $actual_status = $actual_result->getStatusCode();
        }

        $this->assertSame($expected['response'], $actual_content);
        $this->assertSame($expected['status'], $actual_status);
    }

    public function validateOAuth2TokenProvider()
    {
        $token = self::ACCESS_TOKEN;

        $default_token_param = ['access_token' => $token];
        $wrong_token_param = ['access_token' => 'wrong_token'];
        $default_token_header = ['HTTP_AUTHORIZATION' => 'Bearer ' . $token];
        $wrong_token_header = ['HTTP_AUTHORIZATION' => 'Bearer wrong_token'];

        $expect_success = [
            'response' => null,
            'status' => null,
        ];
        $expect_empty_token = [
            'response' => '{}',
            'status' => Response::HTTP_UNAUTHORIZED
        ];
        $expect_wrong_token = [
            'response' => '{"error":"invalid_token","error_description":"The access token provided is invalid"}',
            'status' => Response::HTTP_UNAUTHORIZED
        ];
        $expect_both_token = [
            'response' => '{"error":"invalid_request","error_description":"Only one method may be used to authenticate at a time (Auth header, GET or POST)"}',
            'status' => Response::HTTP_BAD_REQUEST
        ];

        return [
            'GET: success with param' => [
                Request::create(self::RESOURCE_PATH, 'GET', $default_token_param),
                $token,
                $expect_success,
            ],
            'GET: success with header' => [
                Request::create(self::RESOURCE_PATH, 'GET', [], [], [], $default_token_header),
                $token,
                $expect_success,
            ],
            'POST: success with param' => [
                Request::create(self::RESOURCE_PATH, 'POST', $default_token_param),
                $token,
                $expect_success,
            ],
            'POST: success with header' => [
                Request::create(self::RESOURCE_PATH, 'POST', [], [], [], $default_token_header),
                $token,
                $expect_success,
            ],
            'GET: empty token' => [
                Request::create(self::RESOURCE_PATH, 'GET'),
                $token,
                $expect_empty_token,
            ],
            'POST: empty token' => [
                Request::create(self::RESOURCE_PATH, 'POST'),
                $token,
                $expect_empty_token,
            ],
            'GET: wrong token with param' => [
                Request::create(self::RESOURCE_PATH, 'GET', $wrong_token_param),
                'wrong_token',
                $expect_wrong_token,
            ],
            'GET: wrong token with header' => [
                Request::create(self::RESOURCE_PATH, 'GET', [], [], [], $wrong_token_header),
                'wrong_token',
                $expect_wrong_token,
            ],
            'POST: wrong token with param' => [
                Request::create(self::RESOURCE_PATH, 'POST', $wrong_token_param),
                'wrong_token',
                $expect_wrong_token,
            ],
            'POST: wrong token with header' => [
                Request::create(self::RESOURCE_PATH, 'POST', [], [], [], $wrong_token_header),
                'wrong_token',
                $expect_wrong_token,
            ],
            'GET: token with param and header both' => [
                Request::create(self::RESOURCE_PATH, 'GET', $default_token_param, [], [], $default_token_header),
                $token,
                $expect_both_token,
            ],
            'POST: token with param and header both' => [
                Request::create(self::RESOURCE_PATH, 'POST', $default_token_param, [], [], $default_token_header),
                $token,
                $expect_both_token,
            ],
        ];
    }

    /**
     * @dataProvider validateOAuth2TokenWithJWTProvider
     */
    public function testValidateOAuth2TokenWithJWT($request, $token, $expected)
    {
        $validator = MiddlewareFactory::validateOAuth2Token();

        if ($expected['status'] === null) {
            $payload = $this->createMockJWTOAuth2Data(true);
        } else {
            $payload = false;
        }

        $mock_storage = $this->createMockObject('\OAuth2\Storage\AccessTokenInterface', [
            'getAccessToken' => ['input' => $token, 'output' => $payload],
        ]);

        $oauth2_service = $this->createOAuth2Service(true);
        $oauth2_service->setTokenStorage($mock_storage);
        $container = new Application([
            'oauth2' => $oauth2_service,
        ]);

        $actual_result = $validator($request, $container);

        $actual_content = null;
        $actual_status = null;
        if ($actual_result instanceof Response) {
            $actual_content = $actual_result->getContent();
            $actual_status = $actual_result->getStatusCode();
        }

        $this->assertSame($expected['response'], $actual_content);
        $this->assertSame($expected['status'], $actual_status);
    }

    public function validateOAuth2TokenWithJWTProvider()
    {
        $token = $this->createMockJwt();

        $default_token_param = ['access_token' => $token];
        $wrong_token_param = ['access_token' => 'wrong_token'];
        $default_token_header = ['HTTP_AUTHORIZATION' => 'Bearer ' . $token];
        $wrong_token_header = ['HTTP_AUTHORIZATION' => 'Bearer wrong_token'];

        $expect_success = [
            'response' => null,
            'status' => null,
        ];
        $expect_empty_token = [
            'response' => '{}',
            'status' => Response::HTTP_UNAUTHORIZED
        ];
        $expect_wrong_token = [
            'response' => '{"error":"invalid_token","error_description":"The access token provided is invalid"}',
            'status' => Response::HTTP_UNAUTHORIZED
        ];
        $expect_both_token = [
            'response' => '{"error":"invalid_request","error_description":"Only one method may be used to authenticate at a time (Auth header, GET or POST)"}',
            'status' => Response::HTTP_BAD_REQUEST
        ];

        return [
            'GET: success with param' => [
                Request::create(self::RESOURCE_PATH, 'GET', $default_token_param),
                $token,
                $expect_success,
            ],
            'GET: success with header' => [
                Request::create(self::RESOURCE_PATH, 'GET', [], [], [], $default_token_header),
                $token,
                $expect_success,
            ],
            'POST: success with param' => [
                Request::create(self::RESOURCE_PATH, 'POST', $default_token_param),
                $token,
                $expect_success,
            ],
            'POST: success with header' => [
                Request::create(self::RESOURCE_PATH, 'POST', [], [], [], $default_token_header),
                $token,
                $expect_success,
            ],
            'GET: empty token' => [
                Request::create(self::RESOURCE_PATH, 'GET'),
                $token,
                $expect_empty_token,
            ],
            'POST: empty token' => [
                Request::create(self::RESOURCE_PATH, 'POST'),
                $token,
                $expect_empty_token,
            ],
            'GET: wrong token with param' => [
                Request::create(self::RESOURCE_PATH, 'GET', $wrong_token_param),
                'wrong_token',
                $expect_wrong_token,
            ],
            'GET: wrong token with header' => [
                Request::create(self::RESOURCE_PATH, 'GET', [], [], [], $wrong_token_header),
                'wrong_token',
                $expect_wrong_token,
            ],
            'POST: wrong token with param' => [
                Request::create(self::RESOURCE_PATH, 'POST', $wrong_token_param),
                'wrong_token',
                $expect_wrong_token,
            ],
            'POST: wrong token with header' => [
                Request::create(self::RESOURCE_PATH, 'POST', [], [], [], $wrong_token_header),
                'wrong_token',
                $expect_wrong_token,
            ],
            'GET: token with param and header both' => [
                Request::create(self::RESOURCE_PATH, 'GET', $default_token_param, [], [], $default_token_header),
                $token,
                $expect_both_token,
            ],
            'POST: token with param and header both' => [
                Request::create(self::RESOURCE_PATH, 'POST', $default_token_param, [], [], $default_token_header),
                $token,
                $expect_both_token,
            ],
        ];
    }
}
