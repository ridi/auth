# Ridibooks Auth [![Build Status](https://travis-ci.org/ridi/image-optimizer.svg?branch=master)](https://travis-ci.org/ridibooks/auth)
> The auth service of Ridibooks.

OAuth2 is providing. It is implemented based on [bshaffer/oauth2-server-php](https://github.com/bshaffer/oauth2-server-php)

## Requirements
- [Composer](https://getcomposer.org)
- [newman](https://github.com/postmanlabs/newman) (for test)
- mysql

## Getting started
1. Write `.env` for configuration:
```bash
cp .env.sample .env
vim .env

---
DEBUG=1
DOMAIN={Cookie Domain}

# OAuth DB connect
OAUTH_DB_HOST=127.0.0.1
OAUTH_DB_DBNAME=oauth2_db
OAUTH_DB_USER=root
OAUTH_DB_PASSWORD=root

OAUTH_CODE_LIFETIME={TTL of authrization code}
OAUTH_ACCESS_LIFETIME={TTL of access token}
OAUTH_REFRESH_TOKEN_LIFETIME={TTL of refresh token}

# User DB connect
USER_DB_HOST=127.0.0.1
USER_DB_DBNAME=oauth2_db
USER_DB_USER=root
USER_DB_PASSWORD=root

```

2. Run server with `composer run`

3. Test with `bin/test.sh`
