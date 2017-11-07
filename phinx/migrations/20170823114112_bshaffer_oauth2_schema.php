<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

class BshafferOauth2Schema extends AbstractMigration
{
    public function change()
    {
        $this->table('oauth_clients', ['id' => false, 'primary_key' => ['client_id']])
            ->addColumn('client_id', 'string', ['length' => 80, 'null' => false])
            ->addColumn('client_secret', 'string', ['length' => 80, 'null' => true])
            ->addColumn('name', 'string', ['length' => 200, 'null' => true])
            ->addColumn('redirect_uri', 'string', ['length' => 2000, 'null' => true])
            ->addColumn('grant_types', 'string', ['length' => 80, 'null' => true])
            ->addColumn('scope', 'string', ['length' => 4000, 'null' => true])
            ->create();

        $this->table('oauth_access_tokens', ['id' => false, 'primary_key' => ['access_token']])
            ->addColumn('access_token', 'string', ['length' => 40, 'null' => false])
            ->addColumn('client_id', 'string', ['length' => 80, 'null' => true])
            ->addColumn('user_id', 'integer', ['signed' => false, 'null' => false])
            ->addColumn('expires', 'timestamp', ['null' => false])
            ->addColumn('scope', 'string', ['length' => 4000, 'null' => true])
            ->create();

        $this->table('oauth_authorization_codes', ['id' => false, 'primary_key' => ['authorization_code']])
            ->addColumn('authorization_code', 'string', ['length' => 40, 'null' => false])
            ->addColumn('client_id', 'string', ['length' => 80, 'null' => true])
            ->addColumn('user_id', 'integer', ['signed' => false, 'null' => false])
            ->addColumn('redirect_uri', 'string', ['length' => 2000, 'null' => true])
            ->addColumn('expires', 'timestamp', ['null' => false])
            ->addColumn('scope', 'string', ['length' => 4000, 'null' => true])
            ->addColumn('id_token', 'string', ['length' => 1000, 'null' => true])
            ->create();

        $this->table('oauth_refresh_tokens', ['id' => false, 'primary_key' => ['refresh_token']])
            ->addColumn('refresh_token', 'string', ['length' => 40, 'null' => false])
            ->addColumn('client_id', 'string', ['length' => 80, 'null' => true])
            ->addColumn('user_id', 'integer', ['signed' => false, 'null' => false])
            ->addColumn('expires', 'timestamp', ['null' => false, 'default' => 'CURRENT_TIMESTAMP'])
            ->addColumn('scope', 'string', ['length' => 4000, 'null' => true])
            ->create();

        $this->table('oauth_scopes', ['id' => false, 'primary_key' => ['scope']])
            ->addColumn('scope', 'string', ['length' => 80, 'null' => false])
            ->addColumn('is_default', 'boolean', ['null' => true])
            ->create();

        $this->table('oauth_public_keys')
            ->addColumn('client_id', 'string', ['length' => 80, 'null' => true])
            ->addColumn('public_key', 'string', ['length' => 2000, 'null' => true])
            ->addColumn('private_key', 'string', ['length' => 2000, 'null' => true])
            ->addColumn('encryption_algorithm', 'string', ['length' => 100, 'null' => true, 'default' => 'RS256'])
            ->create();

        $this->table('oauth_jwi')
            ->addColumn('issuer', 'string', ['length' => 80, 'null' => false])
            ->addColumn('subject', 'string', ['length' => 80, 'null' => true])
            ->addColumn('audience', 'string', ['length' => 80, 'null' => true])
            ->addColumn('expires', 'timestamp', ['null' => false])
            ->addColumn('jti', 'string', ['length' => 2000, 'null' => false])
            ->create();

        $this->table('oauth_jwt')
            ->addColumn('client_id', 'string', ['length' => 80, 'null' => false])
            ->addColumn('subject', 'string', ['length' => 80, 'null' => true])
            ->addColumn('public_key', 'string', ['length' => 2000, 'null' => false])
            ->create();
    }
}
