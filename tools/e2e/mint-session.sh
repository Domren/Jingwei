#!/bin/sh
# Mint a Jingwei session token for scripted end-to-end checks, because the real
# login needs the slider captcha plus the admin password. The token is written
# to /tmp/jw.token (600) and never printed.
#
# The signing root lives in the database (platform_secret, #188), not in
# /app/jwt.key, so both the token version and the key are read from Postgres.
set -e
PSQL='psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc'
VER=$(docker exec jingwei-postgres-1 sh -c \
  "$PSQL \"select value from settings where key='auth.token_version'\"" | tr -d ' \n')
KEY=$(docker exec jingwei-postgres-1 sh -c \
  "$PSQL \"select jwt_key from platform_secret where id=1\"" | tr -d ' \n')
if [ "$(printf %s "$KEY" | wc -c)" -ne 32 ]; then
  echo "platform signing key not found in the database" >&2
  exit 1
fi
EXP=$(($(date +%s) + 3600))
docker exec -i -e JW_KEY="$KEY" -e JW_VER="$VER" -e JW_EXP="$EXP" jingwei-jingwei-1 python3 - <<'PY'
import base64, hashlib, hmac, json, os

def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=")

key = os.environ["JW_KEY"].encode()
now = int(os.environ["JW_EXP"]) - 3600
seg = b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
body = b64(json.dumps({"ver": os.environ["JW_VER"], "sub": "Jingwei",
                       "exp": int(os.environ["JW_EXP"]), "iat": now},
                      separators=(",", ":")).encode())
sig = b64(hmac.new(key, seg + b"." + body, hashlib.sha256).digest())
open("/tmp/jw.session", "wb").write(seg + b"." + body + b"." + sig)
PY
KEY=
docker cp jingwei-jingwei-1:/tmp/jw.session /tmp/jw.token >/dev/null
docker exec jingwei-jingwei-1 rm -f /tmp/jw.session
chmod 600 /tmp/jw.token
echo "minted: $(wc -c </tmp/jw.token) bytes, expires in 1h"
