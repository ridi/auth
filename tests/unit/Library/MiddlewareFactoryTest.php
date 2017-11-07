<?php
declare(strict_types=1);

namespace Ridibooks\Tests\Auth\Services;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Types\Type;
use PHPUnit\Framework\TestCase;
use Ridibooks\Auth\Library\MiddlewareFactory;
use Ridibooks\Tests\Auth\OAuth2TestBase;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class MiddlewareFactoryTest extends OAuth2TestBase
{
    const RESOURCE_PATH = 'http://ridibooks.com/api/some/resource';
    const ACCESS_TOKEN = 'test_access_token';
    const ACCESS_TOKEN_EXPIRED = 'test_access_token_expired';

    public static function setUpBeforeClass()
    {
        self::createAccessToken();
    }

    public static function tearDownAfterClass()
    {
        self::cleanAccessToken();
    }

    public static function createAccessToken()
    {
        self::cleanAccessToken();

        $db = self::getConnection('default');
        $db->insert(
            'oauth_access_tokens',
            [
                'access_token' => self::ACCESS_TOKEN,
                'client_id' => OAuth2TestBase::CLIENT_ID,
                'user_id' => OAuth2TestBase::USER_IDX,
                'expires' => new \DateTime('2020-01-01 00:00:00'),
            ],
            [Type::STRING, Type::STRING, Type::STRING, Type::DATETIME]
        );
        $db->insert(
            'oauth_access_tokens',
            [
                'access_token' => self::ACCESS_TOKEN_EXPIRED,
                'client_id' => OAuth2TestBase::CLIENT_ID,
                'user_id' => OAuth2TestBase::USER_IDX,
                'expires' => new \DateTime('2001-01-01 00:00:00'),
            ],
            [Type::STRING, Type::STRING, Type::STRING, Type::DATETIME]
        );
    }

    public static function cleanAccessToken()
    {
        $db = self::getConnection('default');
        $db->executeQuery(
            'DELETE FROM oauth_access_tokens WHERE access_token IN (?)',
            [[self::ACCESS_TOKEN, self::ACCESS_TOKEN_EXPIRED]],
            [Connection::PARAM_STR_ARRAY]
        );
    }

    /**
     * @dataProvider validateOAuth2TokenProvider
     */
    public function testValidateOAuth2Token($request_method, $token_param, $token_header, $expected)
    {
        $validator = MiddlewareFactory::validateOAuth2Token();
        $request = Request::create(self::RESOURCE_PATH, $request_method, $token_param, [], [], $token_header);

        $container = new Application([
            'oauth2' => static::createOAuth2Service(),
        ]);

        $actual_result = $validator($request, $container);
        if ($actual_result instanceof Response) {
            $actual_content = $actual_result->getContent();
            $actual_status = $actual_result->getStatusCode();
            $this->assertSame($expected['response'], $actual_content);
            $this->assertSame($expected['status'], $actual_status);
        } else {
            $this->assertSame($expected['response'], $actual_result);
        }
    }

    public function validateOAuth2TokenProvider()
    {
        $default_token_param = ['access_token' => self::ACCESS_TOKEN];
        $wrong_token_param = ['access_token' => 'wrong_token'];
        $default_token_header = ['HTTP_AUTHORIZATION' => 'Bearer ' . self::ACCESS_TOKEN];
        $wrong_token_header = ['HTTP_AUTHORIZATION' => 'Bearer wrong_token'];

        $expect_success = ['response' => null];
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
            'GET: token with param' => ['GET', $default_token_param, [], $expect_success],
            'GET: token with header' => ['GET', [], $default_token_header, $expect_success],
            'POST: success with param' => ['POST', $default_token_param, [], $expect_success],
            'POST: success with header' => ['POST', [], $default_token_header, $expect_success],
            'GET: empty token' => ['GET', [], [], $expect_empty_token],
            'POST: empty token' => ['POST', [], [], $expect_empty_token],
            'GET: wrong token with param' => ['GET', $wrong_token_param, [], $expect_wrong_token],
            'GET: wrong token with header' => ['GET', [], $wrong_token_header, $expect_wrong_token],
            'POST: wrong token with param' => ['POST', $wrong_token_param, [], $expect_wrong_token],
            'POST: wrong token with header' => ['POST', [], $wrong_token_header, $expect_wrong_token],
            'GET: token with param and header both' => ['GET', $default_token_param, $default_token_header, $expect_both_token],
            'POST: token with param and header both' => ['POST', $default_token_param, $default_token_header, $expect_both_token],
        ];
    }
}
