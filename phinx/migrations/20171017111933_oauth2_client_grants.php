<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

class Oauth2ClientGrants extends AbstractMigration
{
    public function change()
    {
        $this->table('oauth_client_grants')
        ->addColumn('user_idx', 'integer', ['signed' => false, 'null' => false])
        ->addColumn('client_id', 'string', ['length' => 80, 'null' => true])
        ->addTimestamps()
        ->addColumn('deleted_at', 'timestamp', ['default' => null, 'null' => true])
        ->create();
    }
}
