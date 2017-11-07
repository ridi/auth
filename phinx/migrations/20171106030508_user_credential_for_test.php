<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

class UserCredentialForTest extends AbstractMigration
{
    public function change()
    {
        $this->table('tb_user', ['id' => false, 'primary_key' => ['idx']])
            ->addColumn('idx', 'integer', ['identity' => true, 'signed' => false, 'null' => false])
            ->addColumn('id', 'string', ['length' => 32, 'null' => false])
            ->addColumn('passwd', 'string', ['length' => 255, 'null' => false])
            ->create();
    }
}
