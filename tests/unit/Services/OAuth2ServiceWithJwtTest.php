<?php
declare(strict_types=1);

namespace Ridibooks\Tests\Auth\Services;

use Ridibooks\Tests\Auth\TestDataWithRS256JWT;

class OAuth2ServiceWithJwtTest extends OAuth2ServiceTest
{
    protected function setTestDataFactory()
    {
        $this->data = new TestDataWithRS256JWT();
    }

    /**
     * @dataProvider getIntrospectionProvider
     */
    public function testGetIntrospection($access_token, $token_data, $expected)
    {
        $payload = $this->data->createMockOAuth2Data();
        $mock_storage = $this->createMockObject('\OAuth2\Storage\AccessTokenInterface', [
            'getAccessToken' => ['input' => $access_token, 'output' => $payload],
        ]);

        $service = $this->data->createOAuth2Service();
        $service->setTokenStorage($mock_storage);

        $actual = $service->getIntrospectionWithJWT($access_token);

        $this->assertSame($expected['active'], $actual['active']);
        $this->assertSame($expected['scope'] ?? null, $actual['scope'] ?? null);
        $this->assertSame($expected['client_id'] ?? null, $actual['aud'] ?? null);
        $this->assertSame($expected['token_type'] ?? null, $actual['token_type'] ?? null);
        $this->assertSame($expected['exp'] ?? null, $actual['exp'] ?? null);
        $this->assertSame($expected['iat'] ?? null, $actual['iat'] ?? null);
        $this->assertSame($expected['sub'] ?? null, $actual['sub'] ?? null);
        $this->assertSame($expected['aud'] ?? null, $actual['aud'] ?? null);
        $this->assertSame($expected['iss'] ?? null, $actual['iss'] ?? null);
    }

    public function getIntrospectionProvider()
    {
        $expired_payload = [
            'iat' => 9800000000,
            'exp' => 9900000000,
        ];

        $before_issued_payload = [
            'iat' => 1000000000,
            'exp' => 1000000001,
        ];

        $payload = $this->data->createMockIntropect();

        return [
            'normal' => [
                $this->data->createMockJwt(),
                null,
                array_merge($payload, [
                    'active' => true,
                    'client_id' => $payload['aud'],
                ]),
            ],
            'expired' => [
                $this->data->createMockJwt($expired_payload),
                null,
                [
                    'active' => false,
                ],
            ],
            'before issued' => [
                $this->data->createMockJwt($before_issued_payload),
                null,
                [
                    'active' => false,
                ],
            ],
        ];
    }
}
