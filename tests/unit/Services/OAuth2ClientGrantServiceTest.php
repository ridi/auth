<?php
declare(strict_types=1);

namespace Ridibooks\Tests\Auth\Services;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Types\Type;
use PHPUnit\Framework\TestCase;
use Ridibooks\Auth\Services\OAuth2ClientGrantService;
use Ridibooks\Tests\Auth\OAuth2TestBase;

class OAuth2ClientGrantServiceTest extends OAuth2TestBase
{
    const CLIENT_ID_OLD = 'test_client_id_old';
    const CLIENT_ID_NEW = 'test_client_id_new';
    const USER_IDX_OLD = 11111111;
    const USER_IDX_NEW = 22222222;
    const TABLE_NAME = 'oauth_client_grants';

    protected function setUp()
    {
        static::createClientGrant();
    }

    protected function tearDown()
    {
        static::cleanClientGrant();
    }

    private static function createClientGrant()
    {
        self::cleanClientGrant();

        $db = self::getConnection('default');
        $db->insert(
            self::TABLE_NAME,
            [
                'user_idx' => self::USER_IDX_OLD,
                'client_id' => self::CLIENT_ID_OLD,
            ],
            [Type::INTEGER, Type::STRING]
        );
    }

    private static function cleanClientGrant()
    {
        $table = self::TABLE_NAME;
        $db = self::getConnection('default');
        $db->executeQuery(
            "DELETE FROM $table WHERE user_idx IN (?)",
            [[self::USER_IDX_OLD, self::USER_IDX_NEW]],
            [Connection::PARAM_STR_ARRAY]
        );
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
     * @dataProvider linkProvider
     */
    public function testLink($user_idx, $client_id, $expected)
    {
        $db = self::getConnection('default');
        $state_service = new OAuth2ClientGrantService($db);

        $state_service->grant($user_idx, $client_id);
        $rows = $this->getLinkedStates($user_idx, $client_id);
        $actual = count($rows);
        $this->assertSame($expected, $actual);
    }

    public function linkProvider()
    {
        return [
            'normal' => [self::USER_IDX_NEW, self::CLIENT_ID_NEW, 1],
            'user_id, client_id pair already exists' => [self::USER_IDX_OLD, self::CLIENT_ID_OLD, 1],
            'new client_id with user_id already exists' => [self::USER_IDX_OLD, self::CLIENT_ID_NEW, 1],
            'new user_id with client_id already exists' => [self::USER_IDX_NEW, self::CLIENT_ID_OLD, 1],
        ];
    }

    /**
     * @dataProvider unlinkProvider
     */
    public function testUnlink($user_idx, $client_id, $expected)
    {
        $db = self::getConnection('default');
        $state_service = new OAuth2ClientGrantService($db);
        $state_service->deny($user_idx, $client_id);
        $rows = $this->getLinkedStates(self::USER_IDX_OLD, self::CLIENT_ID_OLD);
        $actual = count($rows);
        $this->assertSame($expected, $actual);
    }

    public function unlinkProvider()
    {
        return [
            'normal' => [self::USER_IDX_OLD, self::CLIENT_ID_OLD, 0],
            'user_idx, client_id pair not exists' => [self::USER_IDX_NEW, self::CLIENT_ID_NEW, 1],
            'user_idx with new client_id not exists' => [self::USER_IDX_OLD, self::CLIENT_ID_NEW, 1],
            'client_id with new user_id not exists' => [self::USER_IDX_NEW, self::CLIENT_ID_OLD, 1],
        ];
    }

    private function getLinkedStates($user_idx, $client_id)
    {
        $table = self::TABLE_NAME;
        $db = self::getConnection('default');
        $rows = $db->fetchAll(
            "SELECT * FROM $table WHERE user_idx=? AND client_id=? AND deleted_at is null",
            [$user_idx, $client_id],
            [Type::INTEGER, Type::STRING]
        );

        return $rows;
    }
}
