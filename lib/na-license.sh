#!/usr/bin/env bash
# NorthAfrica shared license helper (GitHub private repo)

GH_OWNER="asloma1984"
GH_REPO="NorthAfrica"
GH_REF="main"
GH_TOKEN_FILE="/etc/kyt/.gh_token"

_fetch_register() {
  local token=""
  if [[ -f "$GH_TOKEN_FILE" ]]; then
    token="$(tr -d '\n' < "$GH_TOKEN_FILE")"
  elif [[ -n "$GH_TOKEN" ]]; then
    token="$GH_TOKEN"
  fi
  if [[ -z "$token" ]]; then
    echo "Missing GitHub token. Put it in $GH_TOKEN_FILE or export GH_TOKEN." >&2
    return 1
  fi
  curl -fsSL \
    -H "Authorization: token $token" \
    -H "Accept: application/vnd.github.raw" \
    "https://api.github.com/repos/$GH_OWNER/$GH_REPO/contents/register?ref=$GH_REF"
}

check_license_or_exit() {
  local ip today exp gdate
  ip="$(curl -sS ipv4.icanhazip.com)"
  gdate="$(curl -sv --insecure https://google.com/ 2>&1 | grep -i '^< Date:' | sed -e 's/^< Date: //')"
  today="$(date -d "$gdate" +'%Y-%m-%d' 2>/dev/null)"; [[ -z "$today" ]] && today="$(date +'%Y-%m-%d')"
  exp="$(_fetch_register | grep -w "$ip" | awk '{print $3}')"
  if [[ -z "$exp" ]]; then
    echo "PERMISSION DENIED: IP $ip is not registered." >&2; exit 1
  fi
  if [[ "$today" < "$exp" ]]; then
    return 0
  else
    echo "PERMISSION EXPIRED: $ip (today=$today, exp=$exp)." >&2; exit 1
  fi
}
