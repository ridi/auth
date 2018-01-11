<?php
declare(strict_types=1);

use Phinx\Seed\AbstractSeed;

class Client extends AbstractSeed
{
    public function run()
    {
        $data = [
            [
                'client_id' => 'test_client',
                'client_secret' => 'test_client_pass',
                'redirect_uri' => 'http://fake.com/receive',
            ],
            [
                'client_id' => 'test_client_rs256_jwt',
                'client_secret' => 'test_client_pass_rs256_jwt',
                'redirect_uri' => 'http://fake.com/receive',
            ],
            [
                'client_id' => 'test_client_hs256_jwt',
                'client_secret' => 'test_client_pass_hs256_jwt',
                'redirect_uri' => 'http://fake.com/receive',
            ],
        ];

        $posts = $this->table('oauth_clients');
        $posts->insert($data)->save();
    }
}
