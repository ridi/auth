<?php
declare(strict_types=1);

namespace Ridibooks\Tests\Auth;

use PHPUnit\Framework\TestCase;

abstract class ControllerTestBase extends TestCase
{
    protected $test_app;
    protected $test_user;
    protected $test_client_id;

    public function setUp()
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

    protected function createMockObject($class_name, $param = null)
    {
        $mock = $this->getMockBuilder($class_name)
            ->disableOriginalConstructor()
            ->getMock();

        $at = 0;
        if (isset($param)) {
            foreach ($param as $method_name => $input_outputs) {
                for ($i = 0; $i < count($input_outputs); ++$i) {
                    $method = $mock->expects($this->at($at))->method($method_name);
                    ++$at;
                    $input = $input_outputs[$i][0];
                    if ($input !== null) {
                        if (is_array($input)) {
                            $method = $method->with(...$input);
                        } else {
                            $method = $method->with($input);
                        }
                    }

                    $output = $input_outputs[$i][1];
                    if ($output !== null) {
                        $method->will($this->returnValue($output));
                    }
                }
            }
        }

        return $mock;
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
