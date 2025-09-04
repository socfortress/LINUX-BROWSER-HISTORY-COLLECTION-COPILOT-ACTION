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

# Single lookback control, in HOURS (ARG1 preferred, then $1). Default: 168h (7 days)
LOOKBACK_HOURS="${ARG1:-${1:-168}}"

WriteLog() {
  Message="$1"; Level="${2:-INFO}"
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  line="[$ts][$Level] $Message"
  case "$Level" in
    ERROR) printf '\033[31m%s\033[0m\n' "$line" >&2 ;;
    WARN)  printf '\033[33m%s\033[0m\n' "$line" >&2 ;;
    DEBUG) [ "$VERBOSE" -eq 1 ] && printf '\033[36m%s\033[0m\n' "$line" >&2 ;;
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

escape_json() {
  # Escape a single string argument safely for JSON
  s=$1
  printf '%s' "$s" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

RotateLog
WriteLog "=== SCRIPT START : $ScriptName ==="

# Validate LOOKBACK_HOURS is numeric
case "$LOOKBACK_HOURS" in
  ''|*[!0-9]*) 
    WriteLog "LOOKBACK_HOURS must be a positive integer (hours): '$LOOKBACK_HOURS'" ERROR
    ts=$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')
    final_json="{\"timestamp\":\"$ts\",\"host\":\"$HostName\",\"action\":\"$ScriptName\",\"status\":\"error\",\"error\":\"Invalid LOOKBACK_HOURS: $(escape_json "$LOOKBACK_HOURS")\",\"copilot_action\":true}"
    tmpfile=$(mktemp); printf '%s\n' "$final_json" > "$tmpfile"
    if ! mv -f "$tmpfile" "$ARLog" 2>/dev/null; then mv -f "$tmpfile" "$ARLog.new"; fi
    exit 1
    ;;
esac

# Compute cutoffs
cutoff_unix=$(( $(date +%s) - LOOKBACK_HOURS*3600 ))                       # seconds since 1970
cutoff_win=$(( (cutoff_unix + 11644473600) * 1000000 ))                    # microseconds since 1601 (Chromium timestamps)
cutoff_unix_us=$(( cutoff_unix * 1000000 ))                                # microseconds since 1970 (Firefox timestamps)
WriteLog "Collecting artifacts from the last ${LOOKBACK_HOURS} hours (cutoff_unix=$cutoff_unix)" INFO

install_sqlite3() {
  if ! command -v sqlite3 >/dev/null 2>&1; then
    WriteLog "sqlite3 not found. Attempting install..." WARN
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update && apt-get install -y sqlite3
    elif command -v yum >/dev/null 2>&1; then
      yum install -y sqlite
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y sqlite
    else
      WriteLog "No supported package manager for sqlite3 install." ERROR
      return 1
    fi
  fi
}

query_sqlite() {
  db="$1"
  sql="$2"
  [ -s "$db" ] || { WriteLog "DB missing/empty: $db" DEBUG; return 0; }
  tmpdb="/tmp/$(basename "$db").$$"
  cp "$db" "$tmpdb" 2>/dev/null || { WriteLog "Copy failed, skipping: $db" DEBUG; return 0; }
  result=$(timeout 10 sqlite3 -readonly -json "$tmpdb" "$sql" 2>/dev/null | sed '/^null$/d' || true)
  rm -f "$tmpdb"
  echo "$result"
}

collect_chrome_artifacts_all() {
  results=""
  for home in /home/* /root; do
    [ -d "$home" ] || continue
    user=$(basename "$home")

    # Common base dirs for Chromium-like browsers (native + Snap/Brave/etc.)
    for base in \
      "$home/.config/google-chrome" \
      "$home/.config/chromium" \
      "$home/.config/BraveSoftware/Brave-Browser" \
      "$home/snap/chromium/current/.config/chromium" \
      "$home/snap/chromium/common/.config/chromium" \
      "$home/snap/brave/current/.config/BraveSoftware/Brave-Browser" \
      "$home/.config/vivaldi" \
      "$home/.config/opera" ; do

      [ -d "$base" ] || continue

      # All profiles, not just Default
      for profile in "$base"/Default "$base"/Profile*; do
        [ -d "$profile" ] || continue
        browser=$(basename "$base")
        profname=$(basename "$profile")
        WriteLog "Collecting from $user - $browser - $profname" DEBUG

        out=""

        # HISTORY (urls.last_visit_time, microseconds since 1601)
        history=$(query_sqlite "$profile/History" "
          SELECT url,title,datetime(last_visit_time/1000000-11644473600,'unixepoch') AS last_visit
          FROM urls
          WHERE last_visit_time > $cutoff_win
          ORDER BY last_visit_time DESC LIMIT 1000;")
        [ -n "$history" ] && out="$out\"history\":$history,"

        # BOOKMARKS (JSON file; include always)
        if [ -f "$profile/Bookmarks" ]; then
          bookmarks=$(tr -d '\n\r\000' < "$profile/Bookmarks")
          bookmarks=$(escape_json "$bookmarks")
          [ -n "$bookmarks" ] && out="$out\"bookmarks\":\"$bookmarks\","
        fi

        # DOWNLOADS (History.downloads.start_time, microseconds since 1601)
        downloads=$(query_sqlite "$profile/History" "
          SELECT target_path,tab_url,datetime(start_time/1000000-11644473600,'unixepoch') AS start_time
          FROM downloads
          WHERE start_time > $cutoff_win
          ORDER BY start_time DESC LIMIT 1000;")
        [ -n "$downloads" ] && out="$out\"downloads\":$downloads,"

        # COOKIES (Network/Cookies: prefer last_access_utc; fallback to creation_utc)
        cookies=$(query_sqlite "$profile/Network/Cookies" "
          SELECT host_key,name,value,
                 datetime(expires_utc/1000000-11644473600,'unixepoch') AS expires,
                 datetime(last_access_utc/1000000-11644473600,'unixepoch') AS last_access
          FROM cookies
          WHERE (last_access_utc > $cutoff_win) OR (creation_utc > $cutoff_win)
          LIMIT 1000;")
        [ -n "$cookies" ] && out="$out\"cookies\":$cookies,"

        out="${out%,}"
        [ -n "$out" ] && results="$results,\"$user-$browser-$profname\":{$out}"
      done
    done
  done
  [ -n "$results" ] && printf '"chrome_like":{%s}' "${results#,}"
}

collect_edge_artifacts_all() {
  results=""
  for home in /home/* /root; do
    [ -d "$home" ] || continue
    user=$(basename "$home")
    base="$home/.config/microsoft-edge"
    [ -d "$base" ] || continue

    for profile in "$base"/Default "$base"/Profile*; do
      [ -d "$profile" ] || continue
      profname=$(basename "$profile")
      WriteLog "Collecting from $user - edge - $profname" DEBUG

      out=""

      history=$(query_sqlite "$profile/History" "
        SELECT url,title,datetime(last_visit_time/1000000-11644473600,'unixepoch') AS last_visit
        FROM urls
        WHERE last_visit_time > $cutoff_win
        ORDER BY last_visit_time DESC LIMIT 1000;")
      [ -n "$history" ] && out="$out\"history\":$history,"

      if [ -f "$profile/Bookmarks" ]; then
        bookmarks=$(tr -d '\n\r\000' < "$profile/Bookmarks")
        bookmarks=$(escape_json "$bookmarks")
        [ -n "$bookmarks" ] && out="$out\"bookmarks\":\"$bookmarks\","
      fi

      downloads=$(query_sqlite "$profile/History" "
        SELECT target_path,tab_url,datetime(start_time/1000000-11644473600,'unixepoch') as start_time
        FROM downloads
        WHERE start_time > $cutoff_win
        ORDER BY start_time DESC LIMIT 1000;")
      [ -n "$downloads" ] && out="$out\"downloads\":$downloads,"

      cookies=$(query_sqlite "$profile/Network/Cookies" "
        SELECT host_key,name,value,
               datetime(expires_utc/1000000-11644473600,'unixepoch') as expires,
               datetime(last_access_utc/1000000-11644473600,'unixepoch') AS last_access
        FROM cookies
        WHERE (last_access_utc > $cutoff_win) OR (creation_utc > $cutoff_win)
        LIMIT 1000;")
      [ -n "$cookies" ] && out="$out\"cookies\":$cookies,"

      out="${out%,}"
      [ -n "$out" ] && results="$results,\"$user-edge-$profname\":{$out}"
    done
  done
  [ -n "$results" ] && printf '"edge":{%s}' "${results#,}"
}

collect_firefox_artifacts_all() {
  results=""
  for home in /home/* /root; do
    [ -d "$home" ] || continue
    user=$(basename "$home")
    for base in \
      "$home/.mozilla/firefox" \
      "$home/.var/app/org.mozilla.firefox/.mozilla/firefox" \
      "$home/snap/firefox/common/.mozilla/firefox"; do

      [ -d "$base" ] || continue
      for prof in "$base"/*.default*; do
        [ -d "$prof" ] || continue
        profname=$(basename "$prof")
        WriteLog "Collecting from $user - firefox profile $profname [$base]" DEBUG

        out=""

        # HISTORY (moz_places.last_visit_date, microseconds since 1970)
        history=$(query_sqlite "$prof/places.sqlite" "
          SELECT url,title,datetime(last_visit_date/1000000,'unixepoch') as last_visit
          FROM moz_places
          WHERE last_visit_date > $cutoff_unix_us
          ORDER BY last_visit_date DESC LIMIT 1000;")
        [ -n "$history" ] && out="$out\"history\":$history,"

        # COOKIES (moz_cookies.lastAccessed/creationTime in microseconds since 1970; expiry is seconds)
        cookies=$(query_sqlite "$prof/cookies.sqlite" "
          SELECT host,name,value,
                 datetime(expiry,'unixepoch') as expires,
                 datetime(lastAccessed/1000000,'unixepoch') as last_access
          FROM moz_cookies
          WHERE (lastAccessed > $cutoff_unix_us) OR (creationTime > $cutoff_unix_us)
          LIMIT 1000;")
        [ -n "$cookies" ] && out="$out\"cookies\":$cookies,"

        # DOWNLOADS (legacy) if present (endTime microseconds since 1970)
        if [ -f "$prof/downloads.sqlite" ]; then
          downloads=$(query_sqlite "$prof/downloads.sqlite" "
            SELECT name,source,datetime(endTime/1000000,'unixepoch') as end_time
            FROM moz_downloads
            WHERE endTime > $cutoff_unix_us
            LIMIT 1000;")
          [ -n "$downloads" ] && out="$out\"downloads\":$downloads,"
        fi

        out="${out%,}"
        [ -n "$out" ] && results="$results,\"$user-firefox-$profname\":{$out}"
      done
    done
  done
  [ -n "$results" ] && printf '"firefox":{%s}' "${results#,}"
}

install_sqlite3 || {
  ts=$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')
  errorMsg="sqlite3 missing and could not be installed."
  WriteLog "$errorMsg" ERROR
  final_json="{\"timestamp\":\"$ts\",\"host\":\"$HostName\",\"action\":\"$ScriptName\",\"status\":\"error\",\"error\":\"$errorMsg\",\"copilot_action\":true}"
  tmpfile=$(mktemp); printf '%s\n' "$final_json" > "$tmpfile"
  if ! mv -f "$tmpfile" "$ARLog" 2>/dev/null; then mv -f "$tmpfile" "$ARLog.new"; fi
  exit 1
}

payload=""
for func in collect_chrome_artifacts_all collect_edge_artifacts_all collect_firefox_artifacts_all; do
  WriteLog "Starting collection: $func" INFO
  val=$($func 2>/dev/null || true)
  [ -n "$val" ] && payload="$payload,$val"
done
payload="{${payload#,}}"

ts=$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')
final_json="{\"timestamp\":\"$ts\",\"host\":\"$HostName\",\"action\":\"$ScriptName\",\"lookback_hours\":$LOOKBACK_HOURS,\"data\":$payload,\"copilot_action\":true}"

# NDJSON overwrite: atomic move with .new fallback (no pre-clearing)
tmpfile=$(mktemp)
printf '%s\n' "$final_json" > "$tmpfile"
if ! mv -f "$tmpfile" "$ARLog" 2>/dev/null; then
  mv -f "$tmpfile" "$ARLog.new"
fi

WriteLog "JSON result written to $ARLog" INFO
dur=$(( $(date +%s) - runStart ))
WriteLog "=== SCRIPT END : duration ${dur}s ==="
