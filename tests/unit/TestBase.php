<?php
declare(strict_types=1);

namespace Ridibooks\Tests\Auth;

use PHPUnit\Framework\TestCase;

abstract class TestBase extends TestCase
{
    // param = [ 'method_name' => array( [ input, [...outputs] ] ) ] => check call index
    // param = [ 'method_name' => [ input, [...outputs] ] ] => ignore call index
    protected function createMockObject($class_name, $param = null)
    {
        $mock = $this->getMockBuilder($class_name)
            ->disableOriginalConstructor()
            ->getMock();

        $at = 0;
        if (isset($param)) {
            foreach ($param as $method_name => $input_outputs) {
                if ($this->hasStringKeys($input_outputs)) { // Ignore call index
                    $method = $mock->method($method_name);
                    $input = $input_outputs['input'];
                    if (isset($input)) {
                        if (is_array($input)) { // Multiple input
                            $method = $method->with(...$input);
                        } else {
                            $method = $method->with($input);
                        }
                    }

                    $output = $input_outputs['output'];
                    if (isset($output)) {
                        $method->will($this->returnValue($output));
                    }
                } else { // Expects call index
                    for ($i = 0; $i < count($input_outputs); ++$i) {
                        $method = $mock->expects($this->at($at))->method($method_name);
                        ++$at;
                        $input = $input_outputs[$i]['input'];
                        if (isset($input)) {
                            if (is_array($input)) { // Multiple input
                                $method = $method->with(...$input);
                            } else {
                                $method = $method->with($input);
                            }
                        }

                        $output = $input_outputs[$i]['output'];
                        if (isset($output)) {
                            $method->will($this->returnValue($output));
                        }
                    }
                }
            }
        }

        return $mock;
    }

    private function hasStringKeys(array $array) {
        return count(array_filter(array_keys($array), 'is_string')) > 0;
    }
}
