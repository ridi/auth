<?php
declare(strict_types=1);

namespace Ridibooks\Tests\Auth;

abstract class ControllerTestBase extends TestBase
{
    protected $test_app;
    protected $test_user;
    protected $test_client_id;

    protected function setUp()
    {
        $this->test_app = require __DIR__ . '/../../src/app.php';
        $this->test_user = [
            'idx' => 1,
            'id' => 'test_id',
            'name' => 'test_name',
            'passwd' => 'test_passwd'
        ];
        $this->test_client_id = 'test_client_id';
    }

    protected function setOAuth2($oauth2)
    {
        $this->test_app['oauth2'] = $oauth2;
    }

    protected function setUserCredentialStorage($storage)
    {
        $this->test_app['oauth2.storage'] = ['user_credentials' => $storage];
    }

    protected function setSession($session)
    {
        $this->test_app['session'] = $session;
    }
}
