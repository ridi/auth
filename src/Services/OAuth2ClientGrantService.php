<?php
declare(strict_types=1);

namespace Ridibooks\Auth\Services;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Types\Type;

/**
 * OAuth2ClientGrantService:
 * 외부 서비스가 oauth2로 사용자 리소스에 접근하기 위해서는 사용자 동의가 필요하다.
 * 외부 서비스 접근이 허용/거부된 상태를 OAuth2ClientGrantService에서 관리한다.
 * 어떤 유저가 어떤 서비스의 접근을 허용했는지 기억하고 있기 때문에, 다음번부터는 사용자 동의 요구 단계를 생략할 수 있다.
 */
class OAuth2ClientGrantService
{
    const TABLE_NAME = 'oauth_client_grants';

    /** @var Connection $db */
    private $connection;

    public function __construct($connection)
    {
        $this->connection = $connection;
    }

    public function isGrantedClient(int $user_idx, string $client_id)
    {
        $table = self::TABLE_NAME;
        $sql = "SELECT count(*) FROM $table WHERE user_idx = ? AND client_id = ? AND deleted_at is null";
        $count = (int) $this->connection->fetchColumn($sql, [$user_idx, $client_id], 0, [Type::INTEGER, Type::STRING]);
        return $count > 0;
    }

    public function grant(int $user_idx, string $client_id)
    {
        $table = self::TABLE_NAME;
        $sql = "SELECT * FROM $table WHERE user_idx = ? AND client_id = ?";
        $old_rows = $this->connection->fetchAll($sql, [$user_idx, $client_id], [Type::INTEGER, Type::STRING]);

        if (count($old_rows) > 0) {
            $this->updateGrant(true, $old_rows[0]['id']);
        } else {
            $this->insertGrant($user_idx, $client_id);
        }
    }

    public function deny(int $user_idx, string $client_id)
    {
        $now = (new \DateTime())->format('Y-m-d H:i:s');
        $this->connection->update(
            self::TABLE_NAME,
            ['deleted_at' => $now],
            [
                'user_idx' => $user_idx,
                'client_id' => $client_id,
            ]
        );
    }

    private function updateGrant(bool $is_linked, string $link_id)
    {
        $now = (new \DateTime())->format('Y-m-d H:i:s');
        $this->connection->update(
            self::TABLE_NAME,
            [
                'deleted_at' => $is_linked ? null : $now,
                'updated_at' => $now,
            ],
            ['id' => $link_id]
        );
    }

    private function insertGrant(int $user_idx, string $client_id)
    {
        $now = (new \DateTime())->format('Y-m-d H:i:s');
        $this->connection->insert(
            self::TABLE_NAME,
            [
                'user_idx' => $user_idx,
                'client_id' => $client_id,
                'updated_at' => $now,
            ]
        );
    }
}
