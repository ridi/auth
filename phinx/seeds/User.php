<?php
declare(strict_types=1);

use Phinx\Seed\AbstractSeed;

class User extends AbstractSeed
{
    public function run()
    {
        $data = [
            [
                'id' => 'testuser',
                'passwd' => '$2y$10$aQ62oOsga1VOPCjHeJWgh.NSvL/jnmNuMD7kch72bm773iDHXfHnO',
            ],
        ];

        $posts = $this->table('tb_user');
        $posts->insert($data)->save();
    }
}
