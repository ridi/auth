<?php
declare(strict_types=1);

namespace Ridibooks\Tests\Auth\Controller;

use PHPUnit\Framework\TestCase;
use Ridibooks\Auth\Controller\PasswordAuthController;
use Symfony\Component\HttpFoundation\Response;

class PasswordAuthControllerTest extends TestCase
{
    private $app;
    private $test_user;
    private $return_url;

    public function setUp()
    {
        $this->test_user = [
            'idx' => 1,
            'id' => 'test_id',
            'name' => 'test_name',
            'passwd' => 'test_passwd'
        ];

        $this->return_url = 'test_url';

        $mock_storage = $this->getMockBuilder('\Ridibooks\Auth\Library\UserCredentialStorage')
            ->disableOriginalConstructor()
            ->getMock();
        $mock_storage->method('checkUserCredentials')
            ->will($this->returnValue(true));
        $mock_storage->method('getUserDetails')
            ->will($this->returnValue($this->test_user));

        $this->app = require __DIR__ . '/../../../src/app.php';
        $this->app['oauth2.storage'] = [ 'user_credentials' => $mock_storage ];
    }

    public function testLogin()
    {
        $mock_request = $this->createMockRequest([ 'return_url' => $this->return_url ]);
        $controller = new PasswordAuthController();
        $actual = $controller->login($mock_request, $this->app);
        $expected = $this->app['twig']->render('login.twig', [ 'return_url' => $this->return_url ]);
        $this->assertEquals($expected, $actual);
    }

    public function testLoginFormSubmit()
    {
        $mock_request = $this->createMockRequest([
            'user_id' => $this->test_user['id'],
            'password' => $this->test_user['passwd'],
            'return_url' => $this->return_url,
        ]);

        // Mock session
        $mock_session = $this->getMockBuilder('\Symfony\Component\HttpFoundation\Session\Session')
            ->disableOriginalConstructor()
            ->getMock();
        $mock_session->expects($this->exactly(3))
            ->method('set')
            ->withConsecutive(
                [$this->equalTo('user_idx'), $this->equalTo($this->test_user['idx'])],
                [$this->equalTo('user_id'), $this->equalTo($this->test_user['id'])],
                [$this->equalTo('user_name'), $this->equalTo($this->test_user['name'])]
            );
        $this->app['session'] = $mock_session;

        $controller = new PasswordAuthController();
        $response = $controller->loginFormSubmit($mock_request, $this->app);

        $this->assertInstanceOf('\Symfony\Component\HttpFoundation\RedirectResponse', $response);
        $this->assertEquals(Response::HTTP_FOUND, $response->getStatusCode());
        $this->assertEquals($this->return_url, $response->headers->get('location'));
    }

    public function testLogout()
    {
        // Mock session
        $mock_session = $this->getMockBuilder('\Symfony\Component\HttpFoundation\Session\Session')
            ->disableOriginalConstructor()
            ->getMock();
        $mock_session->expects($this->once())
            ->method('invalidate');
        $this->app['session'] = $mock_session;

        $controller = new PasswordAuthController();
        $response = $controller->logout($this->app);

        $this->assertInstanceOf('\Symfony\Component\HttpFoundation\RedirectResponse', $response);
        $this->assertEquals(Response::HTTP_FOUND, $response->getStatusCode());
        $this->assertEquals('/', $response->headers->get('location'));
    }

    private function createMockRequest(array $param)
    {
        $mock_request = $this->getMockBuilder('\Symfony\Component\HttpFoundation\Request')
            ->disableOriginalConstructor()
            ->getMock();

        $i = 0;
        foreach ($param as $name => $value) {
            $mock_request->expects($this->at($i))
                ->method('get')
                ->with($name, $this->anything())
                ->will($this->returnValue($value));
            ++$i;
        }

        return $mock_request;
    }
}
