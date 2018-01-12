<?php
declare(strict_types=1);

namespace Ridibooks\Tests\Auth\Services;

use Doctrine\DBAL\Types\Type;
use Ridibooks\Auth\Services\OAuth2ClientGrantService;
use Ridibooks\Tests\Auth\OAuth2ServiceTestBase;

class OAuth2ClientGrantServiceTest extends OAuth2ServiceTestBase
{
    protected function setUp()
    {
        self::createClientGrant();
    }

    protected function tearDown()
    {
        self::cleanClientGrant();
    }

    /**
     * @dataProvider isExistProvider
     */
    public function testIsExists($user_idx, $client_id, $expected)
    {
        $db = self::getConnection('default');
        $state_service = new OAuth2ClientGrantService($db);
        $actual = $state_service->isGrantedClient($user_idx, $client_id);
        $this->assertSame($expected, $actual);
    }

    public function isExistProvider()
    {
        return [
            'normal' => [self::USER_IDX_OLD, self::CLIENT_ID_OLD, true],
            'wrong user id' => [self::USER_IDX_NEW, self::CLIENT_ID_OLD, false],
            'wrong client id' => [self::USER_IDX_OLD, self::CLIENT_ID_NEW, false],
            'wrong user id and client id' => [self::USER_IDX_NEW, self::CLIENT_ID_NEW, false],
        ];
    }

    /**
     * @dataProvider grantProvider
     */
    public function testGrant($user_idx, $client_id, $expected)
    {
        $db = self::getConnection('default');
        $grant_service = new OAuth2ClientGrantService($db);

        $grant_service->grant($user_idx, $client_id);
        $grants = $this->getClientGrants($user_idx, $client_id);
        $actual = count($grants);
        $this->assertSame($expected, $actual);
    }

    public function grantProvider()
    {
        return [
            'Grant successfully' => [self::USER_IDX_NEW, self::CLIENT_ID_NEW, 1],
            'Not changed (old user_id, old client_id pair)' => [self::USER_IDX_OLD, self::CLIENT_ID_OLD, 1],
            'Grant successfully (new client_id with old user_id)' => [self::USER_IDX_OLD, self::CLIENT_ID_NEW, 1],
            'Grant successfully (new user_id with old client_id)' => [self::USER_IDX_NEW, self::CLIENT_ID_OLD, 1],
        ];
    }

    /**
     * @dataProvider denyProvider
     */
    public function testDeny($user_idx, $client_id, $expected)
    {
        $db = self::getConnection('default');
        $state_service = new OAuth2ClientGrantService($db);
        $state_service->deny($user_idx, $client_id);
        $grants = $this->getClientGrants(self::USER_IDX_OLD, self::CLIENT_ID_OLD);
        $actual = count($grants);
        $this->assertSame($expected, $actual);
    }

    public function denyProvider()
    {
        return [
            'Deny successfully' => [self::USER_IDX_OLD, self::CLIENT_ID_OLD, 0],
            'Not denied (wrong user_idx and client_id)' => [self::USER_IDX_NEW, self::CLIENT_ID_NEW, 1],
            'Not denied (wront client_id only)' => [self::USER_IDX_OLD, self::CLIENT_ID_NEW, 1],
            'Not denied (wront user_idx only)' => [self::USER_IDX_NEW, self::CLIENT_ID_OLD, 1],
        ];
    }
}
