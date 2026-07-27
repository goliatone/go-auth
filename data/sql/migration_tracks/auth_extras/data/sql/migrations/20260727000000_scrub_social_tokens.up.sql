UPDATE social_accounts
SET access_token = '', refresh_token = ''
WHERE access_token <> '' OR refresh_token <> '';
