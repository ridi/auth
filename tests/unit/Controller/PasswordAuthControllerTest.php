<?php
declare(strict_types=1);

namespace Ridibooks\Tests\Auth\Controller;

use Ridibooks\Auth\Controller\PasswordAuthController;
use Ridibooks\Tests\Auth\TestBase;
use Symfony\Component\HttpFoundation\Response;

class PasswordAuthControllerTest extends TestBase
{
    private $test_app;
    private $test_user;
    private $test_client_id;
    private $test_return_url;

    protected function setUp()
    {
        $this->test_app = require __DIR__ . '/../../../src/app.php';
        $this->test_user = [
            'idx' => 1,
            'id' => 'test_id',
            'name' => 'test_name',
            'passwd' => 'test_passwd'
        ];
        $this->test_client_id = 'test_client_rs256_jwt';
        $this->test_return_url = 'test_return_url';
    }

    public function testLogin()
    {
        $mock_request = $this->createMockObject('\Symfony\Component\HttpFoundation\Request', [
            'get' => [
                ['input' => 'return_url', 'output' => $this->test_return_url]
            ]
        ]);

        $controller = new PasswordAuthController();
        $actual = $controller->login($mock_request, $this->test_app);
        $expected = $this->test_app['twig']->render('login.twig', ['return_url' => $this->test_return_url]);
        $this->assertEquals($expected, $actual);
    }

    public function testLoginFormSubmit()
    {
        $mock_request = $this->createMockObject('\Symfony\Component\HttpFoundation\Request', [
            'get' => [
                ['input' => 'user_id', 'output' => $this->test_user['id']],
                ['input' => 'password', 'output' => $this->test_user['passwd']],
                ['input' => 'return_url', 'output' => $this->test_return_url],
            ]
        ]);

        $mock_session = $this->createMockObject('\Symfony\Component\HttpFoundation\Session\Session', [
            'set' => [
                ['input' => 'user_idx', 'output' => $this->test_user['idx']],
                ['input' => 'user_id', 'output' => $this->test_user['id']],
                ['input' => 'user_name', 'output' => $this->test_user['name']],
            ]
        ]);

        $mock_storage = $this->createMockObject('\Ridibooks\Auth\Library\UserCredentialStorage', [
            'checkUserCredentials' => [
                ['input' => null, 'output' => true]
            ],
            'getUserDetails' => [
                ['input' => null, 'output' => $this->test_user]
            ],
        ]);

        $this->test_app['session'] = $mock_session;
        $this->test_app['oauth2.storage'] = ['user_credentials' => $mock_storage];

        $controller = new PasswordAuthController();
        $response = $controller->loginFormSubmit($mock_request, $this->test_app);

        $this->assertInstanceOf('\Symfony\Component\HttpFoundation\RedirectResponse', $response);
        $this->assertEquals(Response::HTTP_FOUND, $response->getStatusCode());
        $this->assertEquals($this->test_return_url, $response->headers->get('location'));
    }

    public function testLogout()
    {
        $mock_session = $this->createMockObject('\Symfony\Component\HttpFoundation\Session\Session', [
            'invalidate' => [
                ['input' => null, 'output' => null]
            ]
        ]);

        $this->test_app['session'] = $mock_session;

        $controller = new PasswordAuthController();
        $response = $controller->logout($this->test_app);

        $this->assertInstanceOf('\Symfony\Component\HttpFoundation\RedirectResponse', $response);
        $this->assertEquals(Response::HTTP_FOUND, $response->getStatusCode());
        $this->assertEquals('/', $response->headers->get('location'));
    }
}
