# Ridibooks Auth
[![](https://images.microbadger.com/badges/version/ridibooks/auth.svg)](http://microbadger.com/images/ridibooks/auth "Get your own version badge on microbadger.com")
[![](https://images.microbadger.com/badges/image/ridibooks/auth.svg)](http://microbadger.com/images/ridibooks/auth "Get your own version badge on microbadger.com")
[![Build Status](https://travis-ci.org/ridi/image-optimizer.svg?branch=master)](https://travis-ci.org/ridibooks/auth)
> The auth service of Ridibooks.

OAuth2 is providing. It is implemented based on [bshaffer/oauth2-server-php](https://github.com/bshaffer/oauth2-server-php)

## Requirements
- [Composer](https://getcomposer.org)
- MySQL
- [newman](https://github.com/postmanlabs/newman) (for test)

## Getting started
1. Write `.env` for configuration:
```bash
cp .env.sample .env
vim .env

------

DEBUG=1
OAUTH_DOMAIN={Cookie Domain}

# OAuth DB connect
OAUTH_DBHOST=127.0.0.1
OAUTH_DBPORT=3306
OAUTH_DBNAME=oauth2_db
OAUTH_DBUSER=root
OAUTH_DBPASS=root

OAUTH_CODE_LIFETIME={TTL of authrization code}
OAUTH_ACCESS_LIFETIME={TTL of access token}
OAUTH_REFRESH_TOKEN_LIFETIME={TTL of refresh token}

# User DB connect
USER_DBHOST=127.0.0.1
USER_DBPORT=3306
USER_DBNAME=oauth2_db
USER_DBUSER=root
USER_DBPASS=root
```

2. Run server with `composer run`

3. Test with `bin/test.sh`
