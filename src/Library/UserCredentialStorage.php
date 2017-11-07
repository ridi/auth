<?php
declare(strict_types=1);

namespace Ridibooks\Auth\Library;

use Doctrine\DBAL\Configuration;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Types\Type;
use OAuth2\Storage\UserCredentialsInterface;

class UserCredentialStorage implements UserCredentialsInterface
{
    /** @var Connection $db */
    private $connection;

    public function __construct(array $db, $config = [])
    {
        if (!isset($db)) {
            throw new \InvalidArgumentException('First argument must be config of DB connection.');
        }

        $config = new Configuration();
        $this->connection = DriverManager::getConnection($db, $config);
    }

    /**
     * bshaffer oauth2 라이브러리에서 요구하는 인터페이스 (\OAuth2\Storage\UserCredentialsInterface 참고)
     * access token 발급 시, user credential 방식 인증을 사용하기 위해 필요하다.
     *
     * @param $user_id
     * 유저 계정 인덱스
     * @param $password_to_check
     * 체크해야할 비밀번호
     * @return bool
     * 아이디와 비밀번호가 유효한 경우 TRUE, 그렇지 않은 경우 FALSE
     */
    public function checkUserCredentials($user_id, $password_to_check)
    {
        $sql = "SELECT passwd FROM tb_user WHERE id = ?";
        $encrypt_password = $this->connection->fetchColumn($sql, [$user_id], 0, [Type::STRING]);
        if (is_bool($encrypt_password)) {
            return false;
        }

        return password_verify($password_to_check, $encrypt_password);
    }

    /**
     * bshaffer oauth2 라이브러리의 요구하는 인터페이스 (\OAuth2\Storage\UserCredentialsInterface 참고)
     * 주어진 user_id가 유효한 계정인지, 어떤 scope를 가지는 지 체크한다.
     *
     * @param $user_id
     * 유저 로그인 아이디
     * @return bool|array
     * 해당 유저가 유효하지 않으면 FALSE 리턴.
     * 유효한 경우 "user_id", "scope" 키값을 포함한 배열을 리턴. (user_id는 required, scope는 optional)
     */
    public function getUserDetails($user_id)
    {
        $sql = "SELECT * FROM tb_user WHERE id = ?";
        $rows = $this->connection->fetchAll($sql, [$user_id], [Type::STRING]);
        if (count($rows) <= 0) {
            return false;
        }

        return array_merge($rows[0], [
            'user_id' => $rows[0]['idx'],
        ]);
    }
}
