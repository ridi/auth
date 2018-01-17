<?php
declare(strict_types=1);

namespace Ridibooks\Tests\Auth\Controller;

use Ridibooks\Auth\Controller\OAuth2Controller;
use Ridibooks\Tests\Auth\ControllerTestBase;

class OAuth2ControllerTest extends ControllerTestBase
{
    public function setUp()
    {
        parent::setUp();
    }

    public function testAuthorize()
    {
        $mock_request = $this->createMockObject('\Symfony\Component\HttpFoundation\Request', [
            'get' => [
                ['input' => 'client_id', 'output' => $this->test_client_id],
            ],
        ]);

        $mock_session = $this->createMockObject('\Symfony\Component\HttpFoundation\Session\Session', [
            'get' => [
                ['input' => 'user_idx', 'output' => $this->test_user['idx']],
                ['input' => 'user_id', 'output' => $this->test_user['id']],
            ],
        ]);
        $this->setSession($mock_session);

        $mock_oauth2 = $this->createMockObject('\Ridibooks\Auth\Services\OAuth2Service', [
            'validateAuthorizeRequest' => [
                ['input' => $mock_request, 'output' => true],
            ],
            'isGrantedClient' => [
                ['input' => [$this->test_user['idx'], $this->test_client_id], 'output' => false],
            ],
        ]);
        $this->setOAuth2($mock_oauth2);

        $controller = new OAuth2Controller();
        $actual = $controller->authorize($mock_request, $this->test_app);
        $expected = $this->test_app['twig']->render('agreement.twig', [
            'user_id' => $this->test_user['id'],
            'client_name' => $this->test_client_id,
        ]);
        $this->assertEquals($expected, $actual);
    }

    public function testAuthorizeFormSubmitAgree()
    {
        $mock_request = $this->createMockObject('\Symfony\Component\HttpFoundation\Request', [
            'get' => [
                ['input' => 'client_id', 'output' => $this->test_client_id],
                ['input' => 'agree', 'output' => 1],
            ],
        ]);

        $mock_session = $this->createMockObject('\Symfony\Component\HttpFoundation\Session\Session', [
            'get' => [
                ['input' => 'user_idx', 'output' => $this->test_user['idx']],
            ],
        ]);
        $this->setSession($mock_session);

        $mock_oauth2 = $this->createMockObject('\Ridibooks\Auth\Services\OAuth2Service', [
            'validateAuthorizeRequest' => [
                ['input' => $mock_request, 'output' => true],
            ],
            'grant' => [
                ['input' => $this->test_user['idx'], 'output' => $this->test_client_id],
            ],
            'handleAuthorizeRequest' => [
                ['input' => [$mock_request, $this->test_user['idx'], true], 'output' => null],
            ],
        ]);
        $this->setOAuth2($mock_oauth2);

        $controller = new OAuth2Controller();
        $controller->authorizeFormSubmit($mock_request, $this->test_app);
    }

    public function testAuthorizeFormSubmitDeny()
    {
        $mock_request = $this->createMockObject('\Symfony\Component\HttpFoundation\Request', [
            'get' => [
                ['input' => 'client_id', 'output' => $this->test_client_id],
                ['input' => 'agree', 'output' => 0],
            ],
        ]);

        $mock_session = $this->createMockObject('\Symfony\Component\HttpFoundation\Session\Session', [
            'get' => [
                ['input' => 'user_idx', 'output' => $this->test_user['idx']],
            ],
        ]);
        $this->setSession($mock_session);

        $mock_oauth2 = $this->createMockObject('\Ridibooks\Auth\Services\OAuth2Service', [
            'validateAuthorizeRequest' => [
                ['input' => $mock_request, 'output' => true],
            ],
            'deny' => [
                ['input' => $this->test_user['idx'], 'output' => $this->test_client_id],
            ],
            'handleAuthorizeRequest' => [
                ['input' => [$mock_request, $this->test_user['idx'], false], 'output' => null],
            ],
        ]);
        $this->setOAuth2($mock_oauth2);

        $controller = new OAuth2Controller();
        $controller->authorizeFormSubmit($mock_request, $this->test_app);
    }

    public function testToken()
    {
        $mock_request = $this->createMockObject('\Symfony\Component\HttpFoundation\Request');
        $mock_oauth2 = $this->createMockObject('\Ridibooks\Auth\Services\OAuth2Service', [
            'handleTokenRequest' => [
                ['input' => $mock_request, 'output' => null],
            ],
        ]);
        $this->setOAuth2($mock_oauth2);

        $controller = new OAuth2Controller();
        $controller->token($mock_request, $this->test_app);
    }

    public function testTokenIntrospect()
    {
        $mock_active_token = 'some_active_token';
        $mock_request = $this->createMockObject('\Symfony\Component\HttpFoundation\Request', [
            'get' => [
                ['input' => 'token', 'output' => $mock_active_token],
            ]
        ]);

        $mock_token_data = [
            'active' => true,
            'scope' => null,
            'client_id' => 'test_client',
            'token_type' => 'Bearer',
            'exp' => 1515480000,
            'iat' => 1515470000,
            'sub' => 1,
            'aud' => 'test_client',
            'iss' => 'localhost',
        ];

        $mock_oauth2 = $this->createMockObject('\Ridibooks\Auth\Services\OAuth2Service', [
            'getIntrospection' => [
                ['input' => $mock_active_token, 'output' => $mock_token_data],
            ],
        ]);
        $this->setOAuth2($mock_oauth2);

        $controller = new OAuth2Controller();
        $actual = $controller->tokenIntrospect($mock_request, $this->test_app);
        $json_response = json_decode($actual->getContent(), true);

        $this->assertEquals($mock_token_data['active'], $json_response['active']);
        $this->assertEquals($mock_token_data['scope'], $json_response['scope']);
        $this->assertEquals($mock_token_data['client_id'], $json_response['client_id']);
        $this->assertEquals($mock_token_data['token_type'], $json_response['token_type']);
        $this->assertEquals($mock_token_data['exp'], $json_response['exp']);
        $this->assertEquals($mock_token_data['iat'], $json_response['iat']);
        $this->assertEquals($mock_token_data['sub'], $json_response['sub']);
        $this->assertEquals($mock_token_data['aud'], $json_response['aud']);
        $this->assertEquals($mock_token_data['iss'], $json_response['iss']);
    }

    public function testRevoke()
    {
        $mock_request = $this->createMockObject('\Symfony\Component\HttpFoundation\Request');
        $mock_oauth2 = $this->createMockObject('\Ridibooks\Auth\Services\OAuth2Service', [
            'handleRevokeRequest' => [
                ['input' => $mock_request, 'output' => null],
            ],
        ]);
        $this->setOAuth2($mock_oauth2);

        $controller = new OAuth2Controller();
        $controller->revoke($mock_request, $this->test_app);
    }
}
