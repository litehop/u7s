#!/usr/bin/env bash
# Mints a litehop-reviewer GitHub App installation access token and prints
# it, alone, on stdout. Uses curl rather than `gh api` for the two calls
# below: `gh` always sends `Authorization: token <...>`, but minting an App
# token requires an App JWT sent as `Authorization: Bearer <jwt>`, which `gh`
# has no flag to produce.
#
# No caching: one mint per caller. A cache file is state to invalidate for no
# measurable gain.
set -euo pipefail

APP_ID="${U7S_REVIEWER_APP_ID:?U7S_REVIEWER_APP_ID must be set to the litehop-reviewer App ID}"
APP_KEY="${U7S_REVIEWER_APP_KEY:?U7S_REVIEWER_APP_KEY must be set to the litehop-reviewer private key path}"

# The operator's own settings.local.json stores this path with a literal
# leading `~`, which bash does not expand once it has come through a
# variable rather than a bare word.
APP_KEY="${APP_KEY/#\~/$HOME}"

if [ ! -r "$APP_KEY" ]; then
  echo "gh-app-token: cannot read private key at $APP_KEY" >&2
  exit 1
fi

b64url() {
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}

IAT=$(( $(date +%s) - 60 ))
EXP=$(( IAT + 540 ))

HEADER=$(jq -cn '{alg:"RS256",typ:"JWT"}' | b64url)
PAYLOAD=$(jq -cn --arg iss "$APP_ID" --argjson iat "$IAT" --argjson exp "$EXP" \
  '{iat:$iat,exp:$exp,iss:$iss}' | b64url)
SIGNING_INPUT="$HEADER.$PAYLOAD"
SIGNATURE=$(printf '%s' "$SIGNING_INPUT" | openssl dgst -sha256 -binary -sign "$APP_KEY" | b64url)
JWT="$SIGNING_INPUT.$SIGNATURE"

INSTALLATION_ID=$(curl -sSf \
  -H "Authorization: Bearer $JWT" \
  -H "Accept: application/vnd.github+json" \
  https://api.github.com/repos/litehop/u7s/installation | jq -r '.id')

if [ -z "$INSTALLATION_ID" ] || [ "$INSTALLATION_ID" = "null" ]; then
  echo "gh-app-token: could not resolve an installation id for litehop/u7s" >&2
  exit 1
fi

TOKEN=$(curl -sSf -X POST \
  -H "Authorization: Bearer $JWT" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/app/installations/$INSTALLATION_ID/access_tokens" | jq -r '.token')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
  echo "gh-app-token: access-token response did not contain a token" >&2
  exit 1
fi

printf '%s\n' "$TOKEN"
