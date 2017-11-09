<?php
declare(strict_types=1);

namespace Ridibooks\Tests\Auth\Controller;

use Ridibooks\Auth\Controller\PasswordAuthController;
use Ridibooks\Tests\Auth\ControllerTestBase;
use Symfony\Component\HttpFoundation\Response;

class PasswordAuthControllerTest extends ControllerTestBase
{
    private $test_return_url;

    public function setUp()
    {
        parent::setUp();
        $this->test_return_url = 'test_return_url';
    }

    public function testLogin()
    {
        $mock_request = $this->createMockObject('\Symfony\Component\HttpFoundation\Request', [
            'get' => [
                ['return_url', $this->test_return_url]
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
                ['user_id', $this->test_user['id']],
                ['password', $this->test_user['passwd']],
                ['return_url', $this->test_return_url],
            ]
        ]);

        $mock_session = $this->createMockObject('\Symfony\Component\HttpFoundation\Session\Session', [
            'set' => [
                ['user_idx', $this->test_user['idx']],
                ['user_id', $this->test_user['id']],
                ['user_name', $this->test_user['name']],
            ]
        ]);
        $this->setSession($mock_session);

        $mock_storage = $this->createMockObject('\Ridibooks\Auth\Library\UserCredentialStorage', [
            'checkUserCredentials' => [
                [null, true]
            ],
            'getUserDetails' => [
                [null, $this->test_user]
            ],
        ]);
        $this->setUserCredentialStorage($mock_storage);

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
                [null, null]
            ]
        ]);
        $this->setSession($mock_session);

        $controller = new PasswordAuthController();
        $response = $controller->logout($this->test_app);

        $this->assertInstanceOf('\Symfony\Component\HttpFoundation\RedirectResponse', $response);
        $this->assertEquals(Response::HTTP_FOUND, $response->getStatusCode());
        $this->assertEquals('/', $response->headers->get('location'));
    }
}
