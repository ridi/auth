<?php
declare(strict_types=1);

use Phinx\Seed\AbstractSeed;

class JwtKey extends AbstractSeed
{
    public function run()
    {
        $data = [
            [
                'client_id' => 'test_client_rs256_jwt',
                'public_key' => file_get_contents(__DIR__ . '/../../tests/id_rsa.pub'),
                'private_key' => file_get_contents(__DIR__ . '/../../tests/id_rsa'),
                'encryption_algorithm' => 'RS256',
            ],
            [
                'client_id' => 'test_client_hs256_jwt',
                'public_key' => 'secret',
                'private_key' => 'secret',
                'encryption_algorithm' => 'HS256',
            ],
        ];

        $posts = $this->table('oauth_public_keys');
        $posts->insert($data)->save();
    }
}
