<?php
declare(strict_types=1);

use Phinx\Seed\AbstractSeed;

class Client extends AbstractSeed
{
    public function run()
    {
        $data = [
            [
                'client_id' => 'democlient',
                'client_secret' => 'democlient_pass',
                'redirect_uri' => 'http://fake.com/receive',
            ],
        ];

        $posts = $this->table('oauth_clients');
        $posts->insert($data)->save();
    }
}
