<?php
declare(strict_types=1);

namespace Ridibooks\Tests\Auth\Services;

use Ridibooks\Auth\Services\OAuth2ClientGrantService;
use Ridibooks\Tests\Auth\TestBase;
use Ridibooks\Tests\Auth\TestData;

class OAuth2ClientGrantServiceTest extends TestBase
{
    /** @var TestData $data */
    protected $data;

    public function __construct(?string $name = null, array $data = [], string $dataName = '')
    {
        parent::__construct($name, $data, $dataName);
        $this->setTestDataFactory();
    }

    protected function setTestDataFactory()
    {
        $this->data = new TestData();
    }

    protected function setUp()
    {
        $this->data->setUp();
    }

    protected function tearDown()
    {
        $this->data->tearDown();
    }

    /**
     * @dataProvider isExistProvider
     */
    public function testIsExists($user_idx, $client_id, $expected)
    {
        $db = $this->data->getConnection('default');
        $state_service = new OAuth2ClientGrantService($db);
        $actual = $state_service->isGrantedClient($user_idx, $client_id);
        $this->assertSame($expected, $actual);
    }

    public function isExistProvider()
    {
        $user_idx_old = $this->data->user_idx_old;
        $user_idx_new = $this->data->user_idx_new;
        $client_id_old = $this->data->client_id_old;
        $client_id_new = $this->data->client_id_new;

        return [
            'normal' => [$user_idx_old, $client_id_old, true],
            'wrong user id' => [$user_idx_new, $client_id_old, false],
            'wrong client id' => [$user_idx_old, $client_id_new, false],
            'wrong user id and client id' => [$user_idx_new, $client_id_new, false],
        ];
    }

    /**
     * @dataProvider grantProvider
     */
    public function testGrant($user_idx, $client_id, $expected)
    {
        $db = $this->data->getConnection('default');
        $grant_service = new OAuth2ClientGrantService($db);

        $grant_service->grant($user_idx, $client_id);
        $grants = $this->data->getClientGrants($user_idx, $client_id);
        $actual = count($grants);
        $this->assertSame($expected, $actual);
    }

    public function grantProvider()
    {
        $user_idx_old = $this->data->user_idx_old;
        $user_idx_new = $this->data->user_idx_new;
        $client_id_old = $this->data->client_id_old;
        $client_id_new = $this->data->client_id_new;

        return [
            'Grant successfully' => [$user_idx_new, $client_id_new, 1],
            'Not changed (old user_id, old client_id pair)' => [$user_idx_old, $client_id_old, 1],
            'Grant successfully (new client_id with old user_id)' => [$user_idx_old, $client_id_new, 1],
            'Grant successfully (new user_id with old client_id)' => [$user_idx_new, $client_id_old, 1],
        ];
    }

    /**
     * @dataProvider denyProvider
     */
    public function testDeny($user_idx, $client_id, $expected)
    {
        $db = $this->data->getConnection('default');
        $state_service = new OAuth2ClientGrantService($db);
        $state_service->deny($user_idx, $client_id);
        $grants = $this->data->getClientGrants($this->data->user_idx_old, $this->data->client_id_old);
        $actual = count($grants);
        $this->assertSame($expected, $actual);
    }

    public function denyProvider()
    {
        $user_idx_old = $this->data->user_idx_old;
        $user_idx_new = $this->data->user_idx_new;
        $client_id_old = $this->data->client_id_old;
        $client_id_new = $this->data->client_id_new;

        return [
            'Deny successfully' => [$user_idx_old, $client_id_old, 0],
            'Not denied (wrong user_idx and client_id)' => [$user_idx_new, $client_id_new, 1],
            'Not denied (wront client_id only)' => [$user_idx_old, $client_id_new, 1],
            'Not denied (wront user_idx only)' => [$user_idx_new, $client_id_old, 1],
        ];
    }
}
