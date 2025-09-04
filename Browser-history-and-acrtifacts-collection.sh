#!/bin/sh
set -eu

ScriptName="Collect-Browser-Artifacts"
LogPath="/tmp/${ScriptName}-script.log"
ARLog="/var/ossec/logs/active-responses.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
runStart=$(date +%s)
VERBOSE=1

LOOKBACK_HOURS="${Arg1:-${ARG1:-${1:-168}}}"

WriteLog() {
  Message="$1"; Level="${2:-INFO}"
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  line="[$ts][$Level] $Message"
  case "$Level" in
    ERROR) printf '\033[31m%s\033[0m\n' "$line" >&2 ;;
    WARN)  printf '\033[33m%s\033[0m\n' "$line" >&2 ;;
    DEBUG) [ "${VERBOSE:-0}" -eq 1 ] && printf '\033[36m%s\033[0m\n' "$line" >&2 ;;
    *)     printf '%s\n' "$line" >&2 ;;
  esac
  printf '%s\n' "$line" >> "$LogPath" 2>/dev/null || true
}

RotateLog() {
  [ -f "$LogPath" ] || return 0
  size_kb=$(du -k "$LogPath" | awk '{print $1}')
  [ "$size_kb" -le "$LogMaxKB" ] && return 0
  i=$((LogKeep-1))
  while [ $i -ge 0 ]; do
    [ -f "$LogPath.$i" ] && mv -f "$LogPath.$i" "$LogPath.$((i+1))"
    i=$((i-1))
  done
  mv -f "$LogPath" "$LogPath.1"
}

escape_json() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
iso_now() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

RotateLog
WriteLog "=== SCRIPT START : $ScriptName (host=$HostName) ==="

case "$LOOKBACK_HOURS" in ''|*[!0-9]*) 
  ts="$(iso_now)"; msg="Invalid LOOKBACK_HOURS: $LOOKBACK_HOURS"
  WriteLog "$msg" ERROR
  tmp="$(mktemp)"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"status":"error","error":"%s"}\n' \
    "$ts" "$HostName" "$ScriptName" "$(escape_json "$msg")" > "$tmp"
  mv -f "$tmp" "$ARLog" 2>/dev/null || mv -f "$tmp" "$ARLog.new"
  exit 1
;; esac

cutoff_unix=$(( $(date +%s) - LOOKBACK_HOURS*3600 ))
cutoff_win=$(( (cutoff_unix + 11644473600) * 1000000 ))
cutoff_unix_us=$(( cutoff_unix * 1000000 ))
WriteLog "Lookback: ${LOOKBACK_HOURS}h (cutoff_unix=$cutoff_unix)" INFO

install_sqlite3() {
  if command -v sqlite3 >/dev/null 2>&1; then return 0; fi
  WriteLog "sqlite3 not found, attempting install" WARN
  if command -v apt-get >/dev/null 2>&1; then apt-get update && apt-get install -y sqlite3
  elif command -v dnf >/dev/null 2>&1; then dnf install -y sqlite
  elif command -v yum >/dev/null 2>&1; then yum install -y sqlite
  else WriteLog "No supported package manager for sqlite3" ERROR; return 1; fi
}

TMP_AR="$(mktemp)"
emit_line() {
  ts="$(iso_now)"; browser="$1"; profile="$2"; user="$3"; item="$4"; kv="$5"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"lookback_hours":%s,"browser":"%s","profile":"%s","user":"%s","item":"%s"%s}\n' \
    "$ts" "$HostName" "$ScriptName" "$LOOKBACK_HOURS" \
    "$(escape_json "$browser")" "$(escape_json "$profile")" "$(escape_json "$user")" "$(escape_json "$item")" "$kv" >> "$TMP_AR"
}


query_rows() {
  db="$1"; sql="$2"
  [ -s "$db" ] || { WriteLog "DB missing/empty: $db" DEBUG; return 0; }
  tmpdb="/tmp/$(basename "$db").$$"
  cp "$db" "$tmpdb" 2>/dev/null || { WriteLog "Copy failed, skipping: $db" DEBUG; return 0; }
  timeout 15 sqlite3 -readonly -separator '|' "$tmpdb" "$sql" 2>/dev/null || true
  rm -f "$tmpdb"
}

collect_chromium_like() {
  for home in /home/* /root; do
    [ -d "$home" ] || continue
    user="$(basename "$home")"
    for base in \
      "$home/.config/google-chrome" \
      "$home/.config/chromium" \
      "$home/.config/BraveSoftware/Brave-Browser" \
      "$home/.config/vivaldi" \
      "$home/.config/opera" \
      "$home/snap/chromium/current/.config/chromium" \
      "$home/snap/chromium/common/.config/chromium" \
      "$home/snap/brave/current/.config/BraveSoftware/Brave-Browser"
    do
      [ -d "$base" ] || continue
      browser="$(basename "$base")"
      for prof in "$base"/Default "$base"/Profile*; do
        [ -d "$prof" ] || continue
        profile="$(basename "$prof")"

        query_rows "$prof/History" "
          SELECT url, IFNULL(title,''), strftime('%Y-%m-%dT%H:%M:%S','unixepoch', (last_visit_time/1000000-11644473600))
          FROM urls
          WHERE last_visit_time > $cutoff_win
          ORDER BY last_visit_time DESC LIMIT 1000;
        " | while IFS='|' read -r url title last_visit; do
          [ -n "${url:-}" ] || continue
          kv=$(printf ',%s' "\"url\":\"$(escape_json "$url")\",\"title\":\"$(escape_json "$title")\",\"last_visit\":\"$(escape_json "$last_visit")\"")
          emit_line "$browser" "$profile" "$user" "history" "$kv"
        done

        query_rows "$prof/History" "
          SELECT IFNULL(target_path,''), IFNULL(tab_url,''), strftime('%Y-%m-%dT%H:%M:%S','unixepoch', (start_time/1000000-11644473600))
          FROM downloads
          WHERE start_time > $cutoff_win
          ORDER BY start_time DESC LIMIT 1000;
        " | while IFS='|' read -r target_path tab_url start_time; do
          [ -n "${target_path:-}${tab_url:-}${start_time:-}" ] || continue
          kv=$(printf ',%s' "\"target_path\":\"$(escape_json "$target_path")\",\"tab_url\":\"$(escape_json "$tab_url")\",\"start_time\":\"$(escape_json "$start_time")\"")
          emit_line "$browser" "$profile" "$user" "download" "$kv"
        done
        query_rows "$prof/Network/Cookies" "
          SELECT IFNULL(host_key,''), IFNULL(name,''), IFNULL(value,''), 
                 strftime('%Y-%m-%dT%H:%M:%S','unixepoch',(expires_utc/1000000-11644473600)),
                 strftime('%Y-%m-%dT%H:%M:%S','unixepoch',(last_access_utc/1000000-11644473600))
          FROM cookies
          WHERE (last_access_utc > $cutoff_win) OR (creation_utc > $cutoff_win)
          LIMIT 1000;
        " | while IFS='|' read -r host name value expires last_access; do
          [ -n "${host:-}${name:-}" ] || continue
          kv=$(printf ',%s' "\"host\":\"$(escape_json "$host")\",\"name\":\"$(escape_json "$name")\",\"value\":\"$(escape_json "$value")\",\"expires\":\"$(escape_json "$expires")\",\"last_access\":\"$(escape_json "$last_access")\"")
          emit_line "$browser" "$profile" "$user" "cookie" "$kv"
        done
        if [ -f "$prof/Bookmarks" ]; then
          bookmarks="$(tr -d '\n\r\000' < "$prof/Bookmarks" | sed 's/"/\\"/g')"
          [ -n "$bookmarks" ] && emit_line "$browser" "$profile" "$user" "bookmarks_json" ",\"bookmarks\":\"$bookmarks\""
        fi

      done
    done
  done
}

collect_edge() {
  for home in /home/* /root; do
    [ -d "$home" ] || continue
    user="$(basename "$home")"
    base="$home/.config/microsoft-edge"
    [ -d "$base" ] || continue
    browser="microsoft-edge"
    for prof in "$base"/Default "$base"/Profile*; do
      [ -d "$prof" ] || continue
      profile="$(basename "$prof")"

      query_rows "$prof/History" "
        SELECT url, IFNULL(title,''), strftime('%Y-%m-%dT%H:%M:%S','unixepoch',(last_visit_time/1000000-11644473600))
        FROM urls
        WHERE last_visit_time > $cutoff_win
        ORDER BY last_visit_time DESC LIMIT 1000;
      " | while IFS='|' read -r url title last_visit; do
        [ -n "${url:-}" ] || continue
        kv=$(printf ',%s' "\"url\":\"$(escape_json "$url")\",\"title\":\"$(escape_json "$title")\",\"last_visit\":\"$(escape_json "$last_visit")\"")
        emit_line "$browser" "$profile" "$user" "history" "$kv"
      done

      query_rows "$prof/History" "
        SELECT IFNULL(target_path,''), IFNULL(tab_url,''), strftime('%Y-%m-%dT%H:%M:%S','unixepoch',(start_time/1000000-11644473600))
        FROM downloads
        WHERE start_time > $cutoff_win
        ORDER BY start_time DESC LIMIT 1000;
      " | while IFS='|' read -r target_path tab_url start_time; do
        [ -n "${target_path:-}${tab_url:-}${start_time:-}" ] || continue
        kv=$(printf ',%s' "\"target_path\":\"$(escape_json "$target_path")\",\"tab_url\":\"$(escape_json "$tab_url")\",\"start_time\":\"$(escape_json "$start_time")\"")
        emit_line "$browser" "$profile" "$user" "download" "$kv"
      done

      query_rows "$prof/Network/Cookies" "
        SELECT IFNULL(host_key,''), IFNULL(name,''), IFNULL(value,''),
               strftime('%Y-%m-%dT%H:%M:%S','unixepoch',(expires_utc/1000000-11644473600)),
               strftime('%Y-%m-%dT%H:%M:%S','unixepoch',(last_access_utc/1000000-11644473600))
        FROM cookies
        WHERE (last_access_utc > $cutoff_win) OR (creation_utc > $cutoff_win)
        LIMIT 1000;
      " | while IFS='|' read -r host name value expires last_access; do
        [ -n "${host:-}${name:-}" ] || continue
        kv=$(printf ',%s' "\"host\":\"$(escape_json "$host")\",\"name\":\"$(escape_json "$name")\",\"value\":\"$(escape_json "$value")\",\"expires\":\"$(escape_json "$expires")\",\"last_access\":\"$(escape_json "$last_access")\"")
        emit_line "$browser" "$profile" "$user" "cookie" "$kv"
      done

      if [ -f "$prof/Bookmarks" ]; then
        bookmarks="$(tr -d '\n\r\000' < "$prof/Bookmarks" | sed 's/"/\\"/g')"
        [ -n "$bookmarks" ] && emit_line "$browser" "$profile" "$user" "bookmarks_json" ",\"bookmarks\":\"$bookmarks\""
      fi

    done
  done
}

collect_firefox() {
  for home in /home/* /root; do
    [ -d "$home" ] || continue
    user="$(basename "$home")"
    for base in \
      "$home/.mozilla/firefox" \
      "$home/.var/app/org.mozilla.firefox/.mozilla/firefox" \
      "$home/snap/firefox/common/.mozilla/firefox"
    do
      [ -d "$base" ] || continue
      browser="firefox"
      for prof in "$base"/*.default*; do
        [ -d "$prof" ] || continue
        profile="$(basename "$prof")"

        query_rows "$prof/places.sqlite" "
          SELECT url, IFNULL(title,''), strftime('%Y-%m-%dT%H:%M:%S','unixepoch', last_visit_date/1000000)
          FROM moz_places
          WHERE last_visit_date > $cutoff_unix_us
          ORDER BY last_visit_date DESC LIMIT 1000;
        " | while IFS='|' read -r url title last_visit; do
          [ -n "${url:-}" ] || continue
          kv=$(printf ',%s' "\"url\":\"$(escape_json "$url")\",\"title\":\"$(escape_json "$title")\",\"last_visit\":\"$(escape_json "$last_visit")\"")
          emit_line "$browser" "$profile" "$user" "history" "$kv"
        done

        query_rows "$prof/cookies.sqlite" "
          SELECT IFNULL(host,''), IFNULL(name,''), IFNULL(value,''),
                 strftime('%Y-%m-%dT%H:%M:%S','unixepoch', expiry),
                 strftime('%Y-%m-%dT%H:%M:%S','unixepoch', lastAccessed/1000000)
          FROM moz_cookies
          WHERE (lastAccessed > $cutoff_unix_us) OR (creationTime > $cutoff_unix_us)
          LIMIT 1000;
        " | while IFS='|' read -r host name value expires last_access; do
          [ -n "${host:-}${name:-}" ] || continue
          kv=$(printf ',%s' "\"host\":\"$(escape_json "$host")\",\"name\":\"$(escape_json "$name")\",\"value\":\"$(escape_json "$value")\",\"expires\":\"$(escape_json "$expires")\",\"last_access\":\"$(escape_json "$last_access")\"")
          emit_line "$browser" "$profile" "$user" "cookie" "$kv"
        done

        if [ -f "$prof/downloads.sqlite" ]; then
          query_rows "$prof/downloads.sqlite" "
            SELECT IFNULL(name,''), IFNULL(source,''), strftime('%Y-%m-%dT%H:%M:%S','unixepoch', endTime/1000000)
            FROM moz_downloads
            WHERE endTime > $cutoff_unix_us
            LIMIT 1000;
          " | while IFS='|' read -r name source end_time; do
            [ -n "${name:-}${source:-}${end_time:-}" ] || continue
            kv=$(printf ',%s' "\"name\":\"$(escape_json "$name")\",\"source\":\"$(escape_json "$source")\",\"end_time\":\"$(escape_json "$end_time")\"")
            emit_line "$browser" "$profile" "$user" "download" "$kv"
          done
        fi

      done
    done
  done
}

if ! install_sqlite3; then
  ts="$(iso_now)"; msg="sqlite3 missing and could not be installed"
  tmp="$(mktemp)"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"status":"error","error":"%s"}\n' \
    "$ts" "$HostName" "$ScriptName" "$(escape_json "$msg")" > "$tmp"
  mv -f "$tmp" "$ARLog" 2>/dev/null || mv -f "$tmp" "$ARLog.new"
  WriteLog "$msg" ERROR
  exit 1
fi

WriteLog "Starting Chromium-like collection" INFO
collect_chromium_like
WriteLog "Starting Edge collection" INFO
collect_edge
WriteLog "Starting Firefox collection" INFO
collect_firefox
if [ ! -s "$TMP_AR" ]; then
  emit_line "none" "none" "none" "no_results" ",\"message\":\"no artifacts within lookback window\""
fi
AR_DIR="$(dirname "$ARLog")"
[ -d "$AR_DIR" ] || WriteLog "Directory missing: $AR_DIR (will attempt write anyway)" WARN
if mv -f "$TMP_AR" "$ARLog"; then
  WriteLog "Wrote NDJSON to $ARLog" INFO
else
  WriteLog "Primary write FAILED to $ARLog" WARN
  if mv -f "$TMP_AR" "$ARLog.new"; then
    WriteLog "Wrote NDJSON to $ARLog.new (fallback)" WARN
  else
    keep="/tmp/active-responses.$$.ndjson"
    cp -f "$TMP_AR" "$keep" 2>/dev/null || true
    WriteLog "Failed both writes; saved $keep" ERROR
    rm -f "$TMP_AR" 2>/dev/null || true
    exit 1
  fi
fi

for p in "$ARLog" "$ARLog.new"; do
  if [ -f "$p" ]; then
    sz=$(wc -c < "$p" 2>/dev/null || echo 0)
    ino=$(ls -li "$p" 2>/dev/null | awk '{print $1}')
    head1=$(head -n1 "$p" 2>/dev/null || true)
    WriteLog "VERIFY: path=$p inode=$ino size=${sz}B first_line=${head1:-<empty>}" INFO
  fi
done

dur=$(( $(date +%s) - runStart ))
WriteLog "=== SCRIPT END : ${dur}s ==="
