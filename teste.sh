root@3bd039747087:/home/ubuntu# cat bounty/recon.sh
#!/usr/bin/env bash
# =============================================================================
# Recon5 — lean, high-signal bug bounty recon pipeline
# Usage: ./Recon5.sh <targets_file_or_dir> <company_name>
#
# v2 changelog (see TOOLS_EVALUATION.md for the full rationale):
#   - JS is now scored and tiered BEFORE download (js-priority), not after.
#     Only tiers HIGH/MEDIUM/LOW are fetched; SKIP is logged to
#     js/third_party.txt and never touched again. This is the fix for the
#     "downloads every vendor/analytics/CDN bundle" problem.
#   - Crawl-discovered JS (current) and gau/archive-discovered JS (historical)
#     are tagged separately and scored differently — historical JS is kept
#     (old endpoints can still be live) but deprioritized.
#   - js-extract gained a variable+concatenation heuristic (BASE + "/x",
#     `${BASE}/x`) so common patterns aren't missed by pure literal regex.
#   - New optional pass: jsluice (AST-based, handles concatenation natively)
#     runs alongside LinkFinder when available — see js/sources.jsonl "tool"
#     provenance via source file naming, both feed the same resolve pipeline.
#   - HTTP validation is now targeted: only api/endpoints.txt + api/graphql.txt
#     get probed (not the full URL corpus), per requirement #29.
# =============================================================================
set -uo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
RECON5_BASE="${RECON5_BASE:-/home/ubuntu}"
MAX_PROCS="${MAX_PROCS:-15}"
TOOL_TIMEOUT="${TOOL_TIMEOUT:-180}"
KATANA_DEPTH="${KATANA_DEPTH:-3}"
JS_DOWNLOAD_TIER="${JS_DOWNLOAD_TIER:-LOW}"   # download everything at or above this tier (HIGH > MEDIUM > LOW > SKIP)
LOW_TIER_SIZE_CAP_BYTES="${LOW_TIER_SIZE_CAP_BYTES:-5242880}"  # 5MB: LOW-tier files above this skip the slower LinkFinder pass
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPERS="$SCRIPT_DIR/recon5_helpers.py"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

MISSING_TOOLS=()

log()  { echo -e "${CYAN}[*]${RESET} $*"; }
ok()   { echo -e "${GREEN}[+]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
err()  { echo -e "${RED}[-]${RESET} $*" >&2; }

has_tool() { command -v "$1" >/dev/null 2>&1; }
need_tool() {
    if ! has_tool "$1"; then
        MISSING_TOOLS+=("$1")
        return 1
    fi
    return 0
}

# Run a tool, timeboxed, all noisy output goes to recon.log only.
run_tool() {
    timeout -k 10s "${TOOL_TIMEOUT}s" "$@" >>"$LOG" 2>&1
}

safe_count() {
    [[ -f "${1:-}" ]] && wc -l < "$1" 2>/dev/null | tr -d ' ' || echo 0
}

# tier rank for comparisons (higher = keep). Used to decide the download cutoff.
tier_rank() {
    case "$1" in
        HIGH) echo 3 ;;
        MEDIUM) echo 2 ;;
        LOW) echo 1 ;;
        *) echo 0 ;;  # SKIP
    esac
}
DOWNLOAD_CUTOFF="$(tier_rank "$JS_DOWNLOAD_TIER")"

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------
if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <targets_file_or_dir> <company_name>"
    echo "Example: $0 /home/ubuntu/Alvos Acme"
    exit 1
fi

TARGETS_INPUT="$1"
COMPANY="$2"
WS="$RECON5_BASE/$COMPANY"

if [[ ! -e "$TARGETS_INPUT" ]]; then
    err "Targets path not found: $TARGETS_INPUT"
    exit 1
fi

# ---------------------------------------------------------------------------
# Workspace
# ---------------------------------------------------------------------------
mkdir -p "$WS"/{http,urls,api,js/downloaded,technologies}
LOG="$WS/recon.log"
: > "$LOG"

if [[ -d "$TARGETS_INPUT" ]]; then
    find "$TARGETS_INPUT" -maxdepth 1 -type f -exec cat {} + > "$WS/targets.txt"
else
    cp "$TARGETS_INPUT" "$WS/targets.txt"
fi
# normalize: lowercase, strip blank lines/comments
sed -i 's/\r$//' "$WS/targets.txt"
grep -viE '^\s*(#|$)' "$WS/targets.txt" | tr '[:upper:]' '[:lower:]' | sort -u -o "$WS/targets.txt"

ok "Workspace: $WS"
ok "Targets:   $(safe_count "$WS/targets.txt") root domain(s)"

# ---------------------------------------------------------------------------
# 0. Scope
# ---------------------------------------------------------------------------
SCOPE="$WS/scope.txt"
python3 "$HELPERS" scope-domains "$WS/targets.txt" > "$SCOPE"

filter_scope() { python3 "$HELPERS" filter-scope --scope "$SCOPE"; }
noise_filter() { python3 "$HELPERS" noise-filter; }

# ---------------------------------------------------------------------------
# 1. Subdomain discovery
# ---------------------------------------------------------------------------
log "Subdomain discovery..."
TMP_SUBS="$(mktemp -d)"
trap 'rm -rf "$TMP_SUBS" "${TMP_URLS:-}"' EXIT

if need_tool subfinder; then
    run_tool subfinder -silent -all -dL "$WS/targets.txt" -o "$TMP_SUBS/subfinder.txt" &
    PID_SUBFINDER=$!
fi
if need_tool assetfinder; then
    (
        while read -r d; do
            timeout -k 5s 60s assetfinder --subs-only "$d" 2>>"$LOG"
        done < "$WS/targets.txt"
    ) > "$TMP_SUBS/assetfinder.txt" &
    PID_ASSETFINDER=$!
fi

# crt.sh — free, high-coverage, no binary dependency
(
    while read -r d; do
        curl -sk --connect-timeout 10 --max-time 30 \
            "https://crt.sh/?q=%25.$d&output=json" 2>>"$LOG" \
            | jq -r '.[].name_value' 2>/dev/null \
            | tr ',' '\n' | grep -v '^\*\.'
    done < "$WS/targets.txt"
) > "$TMP_SUBS/crtsh.txt" &
PID_CRTSH=$!

[[ -n "${PID_SUBFINDER:-}" ]] && wait "$PID_SUBFINDER" 2>/dev/null
[[ -n "${PID_ASSETFINDER:-}" ]] && wait "$PID_ASSETFINDER" 2>/dev/null
wait "$PID_CRTSH" 2>/dev/null

cat "$TMP_SUBS"/*.txt 2>/dev/null \
    | tr '[:upper:]' '[:lower:]' \
    | sed -E 's~^https?://~~; s~/.*~~; s~:.*$~~' \
    | grep -viE '^\*|^\s*$' \
    | sort -u \
    | filter_scope \
    > "$WS/subdomains.txt"

ok "Subdomains: $(safe_count "$WS/subdomains.txt")"

# ---------------------------------------------------------------------------
# 2. DNS resolution
# ---------------------------------------------------------------------------
log "DNS resolution..."
if need_tool dnsx; then
    run_tool dnsx -l "$WS/subdomains.txt" -silent -threads 200 -retry 2 -o "$WS/resolved.txt"
else
    warn "dnsx not found — using unresolved subdomain list"
    cp "$WS/subdomains.txt" "$WS/resolved.txt"
fi
ok "Resolved: $(safe_count "$WS/resolved.txt")"

# ---------------------------------------------------------------------------
# 3. HTTP probing + technologies (httpx)
# ---------------------------------------------------------------------------
log "HTTP probing..."
if need_tool httpx; then
    run_tool httpx -l "$WS/resolved.txt" -silent -timeout 10 \
        -json -sc -td -title -server -location -cl -tls-probe \
        -o "$WS/http/httpx.jsonl"

    jq -r '
        [.url,
         ("[" + (.status_code|tostring) + "]"),
         (if .title then ("[" + .title + "]") else "" end),
         (if .webserver then ("[" + .webserver + "]") else "" end)
        ] | join(" ")
    ' "$WS/http/httpx.jsonl" 2>/dev/null > "$WS/http/httpx.txt"

    jq -r 'select(.status_code|tostring|test("^(2|3)[0-9][0-9]$|^401$|^403$")) | .url' \
        "$WS/http/httpx.jsonl" 2>/dev/null | sort -u > "$WS/alive.txt"

    jq -r 'select(.tech) | .tech[]?' "$WS/http/httpx.jsonl" 2>/dev/null \
        | sort -u > "$WS/http/technologies.txt"
else
    err "httpx not found — cannot probe HTTP, remaining stages will have no input"
    : > "$WS/alive.txt"
    : > "$WS/http/technologies.txt"
fi
ok "Alive hosts: $(safe_count "$WS/alive.txt")"

# ---------------------------------------------------------------------------
# 4. WhatWeb fingerprinting (alive hosts only, capped concurrency)
# ---------------------------------------------------------------------------
if need_tool whatweb && [[ -s "$WS/alive.txt" ]]; then
    log "WhatWeb fingerprinting..."
    xargs -a "$WS/alive.txt" -P 8 -I{} \
        timeout -k 5s 20s whatweb -q --color=never '{}' >> "$WS/technologies/whatweb.txt" 2>>"$LOG"
    sort -u -o "$WS/technologies/whatweb.txt" "$WS/technologies/whatweb.txt" 2>/dev/null
fi
ok "Technologies: $(safe_count "$WS/http/technologies.txt") (httpx) + $(safe_count "$WS/technologies/whatweb.txt") (whatweb)"

# ---------------------------------------------------------------------------
# 4b. Technology-aware target hints (requirement #30)
# Detected stacks unlock a small, curated set of extra paths worth probing.
# This is discovery-oriented, not a vuln scanner.
# ---------------------------------------------------------------------------
: > "$WS/urls/tech_suggested.txt"
TECH_BLOB="$(cat "$WS/http/technologies.txt" "$WS/technologies/whatweb.txt" 2>/dev/null | tr '[:upper:]' '[:lower:]')"
if [[ -s "$WS/alive.txt" ]]; then
    while read -r base; do
        [[ -z "$base" ]] && continue
        if grep -q 'next.js' <<<"$TECH_BLOB"; then
            printf '%s/_next/static/chunks/webpack.js\n%s/api\n' "$base" "$base"
        fi
        if grep -qE 'laravel' <<<"$TECH_BLOB"; then
            printf '%s/api\n%s/sanctum/csrf-cookie\n%s/storage\n' "$base" "$base" "$base"
        fi
        if grep -qE 'spring' <<<"$TECH_BLOB"; then
            printf '%s/actuator\n%s/actuator/health\n%s/api\n' "$base" "$base" "$base"
        fi
        if grep -qE 'graphql' <<<"$TECH_BLOB"; then
            printf '%s/graphql\n%s/graphiql\n' "$base" "$base"
        fi
    done < "$WS/alive.txt" | sort -u > "$WS/urls/tech_suggested.txt"
fi
ok "Technology-suggested paths: $(safe_count "$WS/urls/tech_suggested.txt")"

# ---------------------------------------------------------------------------
# 5. Crawling + passive URL discovery (current vs. historical, kept separate)
# ---------------------------------------------------------------------------
log "Crawling..."
TMP_URLS="$(mktemp -d)"

if [[ -s "$WS/alive.txt" ]]; then
    if need_tool katana; then
        run_tool katana -list "$WS/alive.txt" -d "$KATANA_DEPTH" -jc -silent \
            -c "$MAX_PROCS" -fs fqdn -o "$TMP_URLS/katana.txt"
    fi
    if need_tool gau; then
        (cat "$WS/subdomains.txt"; cat "$WS/targets.txt") | sort -u \
            | run_tool gau --threads "$MAX_PROCS" 2>>"$LOG" > "$TMP_URLS/gau.txt" &
        PID_GAU=$!
        wait "$PID_GAU" 2>/dev/null
    fi
fi

strip_ansi() { sed 's/\x1B\[[0-9;]*[a-zA-Z]//g'; }

cat "$TMP_URLS/katana.txt" "$TMP_URLS/gau.txt" "$WS/urls/tech_suggested.txt" 2>/dev/null \
    | strip_ansi \
    | sort -u \
    | filter_scope \
    | noise_filter \
    > "$WS/urls/all.txt"

ok "URLs discovered: $(safe_count "$WS/urls/all.txt")"

# Priority classification (requirement #27): HIGH/MEDIUM/LOW/NOISE
python3 "$HELPERS" url-priority < "$WS/urls/all.txt" > "$WS/urls/priority.tsv"
awk -F'\t' '$2=="HIGH" || $2=="MEDIUM" {print $1}' "$WS/urls/priority.tsv" \
    | sort -u > "$WS/urls/interesting.txt"

# Classify: api / graphql (orthogonal axis — resource kind, not priority)
: > "$WS/api/endpoints.txt"; : > "$WS/api/graphql.txt"
python3 "$HELPERS" classify-urls \
    --api-out "$WS/api/endpoints.txt" \
    --graphql-out "$WS/api/graphql.txt" \
    --interesting-out /dev/null \
    < "$WS/urls/all.txt"
sort -u -o "$WS/api/endpoints.txt" "$WS/api/endpoints.txt"
sort -u -o "$WS/api/graphql.txt" "$WS/api/graphql.txt"

# JS file list — tagged by discovery source (current crawl vs. historical archive)
: > "$WS/js/candidates.tsv"
grep -iE '\.js([?#].*)?$' "$TMP_URLS/katana.txt" 2>/dev/null | strip_ansi | filter_scope \
    | awk '{print $0"\tcrawl"}' >> "$WS/js/candidates.tsv"
grep -iE '\.js([?#].*)?$' "$TMP_URLS/gau.txt" 2>/dev/null | strip_ansi | filter_scope \
    | awk '{print $0"\thistorical"}' >> "$WS/js/candidates.tsv"
# dedup, preferring the "crawl" tag when a URL appears in both
sort -t$'\t' -k1,1 -k2,2r "$WS/js/candidates.tsv" | awk -F'\t' '!seen[$1]++' \
    > "$WS/js/candidates.tsv.tmp" && mv "$WS/js/candidates.tsv.tmp" "$WS/js/candidates.tsv"

rm -rf "$TMP_URLS"; TMP_URLS=""

# Parameters from crawl URLs
python3 "$HELPERS" classify-params \
    --urls-file "$WS/urls/all.txt" \
    --all-out "$WS/urls/parameters.txt" \
    --interesting-out "$WS/api/parameters.txt.tmp"

ok "Interesting URLs: $(safe_count "$WS/urls/interesting.txt")"
ok "JS candidates (pre-priority): $(safe_count "$WS/js/candidates.tsv")"

# ---------------------------------------------------------------------------
# 6. JavaScript intelligence — the core module
#    Phase A: priority scoring (pre-download selection)
#    Phase B: selective download
#    Phase C: content extraction (regex + variable-concat + LinkFinder/jsluice)
#    Phase D: aggregation + secrets
# ---------------------------------------------------------------------------
log "JS priority scoring..."
python3 "$HELPERS" js-priority --scope "$SCOPE" < "$WS/js/candidates.tsv" \
    > "$WS/js/priority.tsv"

# SKIP tier: never downloaded, kept visible for manual review (requirement #36)
awk -F'\t' '$3=="SKIP"' "$WS/js/priority.tsv" > "$WS/js/third_party.txt"

# Download queue: everything at/above the configured cutoff tier
awk -F'\t' -v cutoff="$DOWNLOAD_CUTOFF" '
    { rank = ($3=="HIGH") ? 3 : ($3=="MEDIUM") ? 2 : ($3=="LOW") ? 1 : 0
      if (rank >= cutoff) print }
' "$WS/js/priority.tsv" > "$WS/js/to_download.tsv"

ok "JS candidates: $(safe_count "$WS/js/priority.tsv")  |  queued for download: $(safe_count "$WS/js/to_download.tsv")  |  skipped (third-party/CDN/analytics): $(safe_count "$WS/js/third_party.txt")"

cut -f1 "$WS/js/to_download.tsv" > "$WS/js/urls.txt"

JS_SOURCES="$WS/js/sources.jsonl"
: > "$JS_SOURCES"

LINKFINDER_BIN=""
if has_tool linkfinder; then LINKFINDER_BIN="linkfinder"; fi
if [[ -z "$LINKFINDER_BIN" ]]; then
    # Common install locations. $HOME is unreliable here (this script is
    # often run as root via sudo/docker, where $HOME=/root even though the
    # tool was cloned under a regular user's home) — so we check explicit,
    # real candidate paths in addition to $HOME, and honor an optional
    # LINKFINDER_PATH override for anything nonstandard.
    LF_CANDIDATES=(
        "${LINKFINDER_PATH:-}"
        "$HOME/Download/LinkFinder/linkfinder.py"
        "/home/ubuntu/Download/LinkFinder/linkfinder.py"
        "/root/Download/LinkFinder/linkfinder.py"
        "/opt/LinkFinder/linkfinder.py"
        "/usr/local/LinkFinder/linkfinder.py"
    )
    for cand in "${LF_CANDIDATES[@]}"; do
        [[ -n "$cand" && -f "$cand" ]] && { LF_PY="$cand"; break; }
    done
    # Fall back to a real filesystem search across every user's home dir,
    # not just $HOME, capped in depth so it stays fast.
    if [[ -z "${LF_PY:-}" ]]; then
        LF_PY=$(find /home /root /opt /usr/local -maxdepth 5 -iname "linkfinder.py" 2>/dev/null | head -1)
    fi
    [[ -n "${LF_PY:-}" ]] && LINKFINDER_BIN="python3 $LF_PY"
fi
[[ -z "$LINKFINDER_BIN" ]] && MISSING_TOOLS+=("linkfinder")

JSLUICE_BIN=""
has_tool jsluice && JSLUICE_BIN="jsluice"
# jsluice is optional (AST-based, understands string-concat endpoints natively —
# see TOOLS_EVALUATION.md). We don't add it to MISSING_TOOLS since LinkFinder +
# our own variable-concat heuristic already cover most of the same ground.

process_one_js() {
    local url="$1"
    local hash
    hash=$(echo -n "$url" | md5sum | cut -d' ' -f1)
    local out_file="$WS/js/downloaded/${hash}.js"

    curl -sk --connect-timeout 8 --max-time 15 --max-filesize 26214400 \
        -o "$out_file" "$url" 2>>"$LOG"
    [[ -s "$out_file" ]] || { rm -f "$out_file"; return; }

    local tier
    tier=$(awk -F'\t' -v u="$url" '$1==u{print $3; exit}' "$WS/js/to_download.tsv")
    local fsize
    fsize=$(stat -c%s "$out_file" 2>/dev/null || echo 0)

    # Primary: our own regex+urljoin+variable-concat extractor (fast, always runs)
    python3 "$HELPERS" js-extract --jsfile "$out_file" --source "$url" --scope "$SCOPE" \
        >> "$JS_SOURCES.tmp.$hash" 2>>"$LOG"

    # Auxiliary parsers are skipped on large, low-priority files to avoid
    # burning the timeout budget on a single minified vendor bundle
    # (requirement #24: size matters, but only combined with low priority).
    if [[ "$tier" == "LOW" && "$fsize" -gt "$LOW_TIER_SIZE_CAP_BYTES" ]]; then
        return
    fi

    if [[ -n "$LINKFINDER_BIN" ]]; then
        timeout -k 5s 30s $LINKFINDER_BIN -i "$out_file" -o cli 2>>"$LOG" \
            | grep -Eo '"[^"]+"' | tr -d '"' \
            | python3 "$HELPERS" resolve-list --source "$url" --scope "$SCOPE" \
            >> "$JS_SOURCES.tmp.$hash" 2>>"$LOG"
    fi

    if [[ -n "$JSLUICE_BIN" ]]; then
        timeout -k 5s 30s jsluice urls "$out_file" 2>>"$LOG" \
            | jq -r '.url // empty' 2>/dev/null \
            | python3 "$HELPERS" resolve-list --source "$url" --scope "$SCOPE" \
            >> "$JS_SOURCES.tmp.$hash" 2>>"$LOG"
    fi
}
export -f process_one_js
export WS SCOPE HELPERS LOG LINKFINDER_BIN JSLUICE_BIN LOW_TIER_SIZE_CAP_BYTES JS_SOURCES

if [[ -s "$WS/js/urls.txt" ]]; then
    JS_COUNT=$(safe_count "$WS/js/urls.txt")
    log "Downloading + analyzing $JS_COUNT prioritized JS file(s)..."
    xargs -a "$WS/js/urls.txt" -P "$MAX_PROCS" -I{} bash -c 'process_one_js "$@"' _ {}
    cat "$WS/js/sources.jsonl.tmp."* 2>/dev/null > "$JS_SOURCES"
    rm -f "$WS/js/sources.jsonl.tmp."*
fi

# Aggregate JS JSONL -> endpoints / endpoints_full / domains / api / graphql / params
: > "$WS/js/endpoints.txt"; : > "$WS/js/endpoints_full.txt"; : > "$WS/js/domains.txt"
if [[ -s "$JS_SOURCES" ]]; then
    python3 "$HELPERS" aggregate-js \
        --jsonl "$JS_SOURCES" \
        --endpoints-out "$WS/js/endpoints.txt" \
        --endpoints-full-out "$WS/js/endpoints_full.txt" \
        --domains-out "$WS/js/domains.txt" \
        --api-out "$WS/api/endpoints.txt" \
        --graphql-out "$WS/api/graphql.txt" \
        --params-out "$WS/js/js_parameters.txt" 2>>"$LOG"
fi
sort -u -o "$WS/api/endpoints.txt" "$WS/api/endpoints.txt"
sort -u -o "$WS/api/graphql.txt" "$WS/api/graphql.txt"

# api/endpoints_full.txt: endpoints.txt with their source context (crawl or JS)
: > "$WS/api/endpoints_full.txt"
while IFS= read -r ep; do
    src=$(grep -F -- "$ep" "$WS/js/endpoints_full.txt" 2>/dev/null | grep -A1 -- "^$ep$" | grep 'source=' | head -1)
    echo "$ep" >> "$WS/api/endpoints_full.txt"
    if [[ -n "$src" ]]; then
        echo "    $src" | sed 's/^ *//' | sed 's/^/    /' >> "$WS/api/endpoints_full.txt"
    else
        echo "    source=crawl" >> "$WS/api/endpoints_full.txt"
    fi
done < "$WS/api/endpoints.txt"

# api/parameters.txt: merge crawl-interesting + JS params
cat "$WS/api/parameters.txt.tmp" "$WS/js/js_parameters.txt" 2>/dev/null \
    | sort -u > "$WS/api/parameters.txt"
rm -f "$WS/api/parameters.txt.tmp"

# Secrets
if [[ -d "$WS/js/downloaded" ]] && [[ -n "$(ls -A "$WS/js/downloaded" 2>/dev/null)" ]]; then
    python3 "$HELPERS" secrets-scan --dir "$WS/js/downloaded" > "$WS/js/secrets.txt" 2>>"$LOG"
fi

ok "JS endpoints: $(safe_count "$WS/js/endpoints.txt")"
ok "In-scope JS domains: $(safe_count "$WS/js/domains.txt")"
ok "API endpoints: $(safe_count "$WS/api/endpoints.txt")"
ok "GraphQL endpoints: $(safe_count "$WS/api/graphql.txt")"
ok "Potential secrets: $(safe_count "$WS/js/secrets.txt")"

# ---------------------------------------------------------------------------
# 7. Targeted HTTP validation (requirement #29) — only high-value endpoints,
#    never the full URL corpus.
# ---------------------------------------------------------------------------
: > "$WS/api/endpoints_probed.txt"
if need_tool httpx; then
    cat "$WS/api/endpoints.txt" "$WS/api/graphql.txt" 2>/dev/null | sort -u > "$WS/api/.probe_targets.tmp"
    if [[ -s "$WS/api/.probe_targets.tmp" ]]; then
        log "Probing $(safe_count "$WS/api/.probe_targets.tmp") API/GraphQL endpoint(s)..."
        run_tool httpx -l "$WS/api/.probe_targets.tmp" -silent -timeout 8 -sc -cl -mc 200,201,204,301,302,401,403,405 \
            -o "$WS/api/endpoints_probed.txt"
    fi
    rm -f "$WS/api/.probe_targets.tmp"
fi
ok "API endpoints probed (responsive): $(safe_count "$WS/api/endpoints_probed.txt")"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}========================================${RESET}"
echo -e "${BOLD}             RECON5 SUMMARY${RESET}"
echo -e "${BOLD}========================================${RESET}"
printf "%-26s %s\n" "Targets:"              "$(safe_count "$WS/targets.txt")"
printf "%-26s %s\n" "Subdomains:"           "$(safe_count "$WS/subdomains.txt")"
printf "%-26s %s\n" "Resolved:"             "$(safe_count "$WS/resolved.txt")"
printf "%-26s %s\n" "Alive:"                "$(safe_count "$WS/alive.txt")"
echo ""
printf "%-26s %s\n" "URLs discovered:"      "$(safe_count "$WS/urls/all.txt")"
printf "%-26s %s\n" "Interesting URLs:"     "$(safe_count "$WS/urls/interesting.txt")"
echo ""
printf "%-26s %s\n" "JS candidates found:"  "$(safe_count "$WS/js/priority.tsv")"
printf "%-26s %s\n" "JS queued for download:" "$(safe_count "$WS/js/urls.txt")"
printf "%-26s %s\n" "JS actually downloaded:" "$(find "$WS/js/downloaded" -type f -name '*.js' 2>/dev/null | wc -l | tr -d ' ')"
printf "%-26s %s\n" "JS skipped (3rd-party):" "$(safe_count "$WS/js/third_party.txt")"
echo ""
printf "%-26s %s\n" "API endpoints:"        "$(safe_count "$WS/api/endpoints.txt")"
printf "%-26s %s\n" "  ...responsive:"      "$(safe_count "$WS/api/endpoints_probed.txt")"
printf "%-26s %s\n" "GraphQL endpoints:"    "$(safe_count "$WS/api/graphql.txt")"
printf "%-26s %s\n" "Parameters:"           "$(safe_count "$WS/api/parameters.txt")"
echo ""
printf "%-26s %s\n" "JS endpoints:"         "$(safe_count "$WS/js/endpoints.txt")"
printf "%-26s %s\n" "In-scope JS domains:"  "$(safe_count "$WS/js/domains.txt")"
printf "%-26s %s\n" "Potential secrets:"    "$(safe_count "$WS/js/secrets.txt")"
echo ""
printf "%-26s %s\n" "Technologies:"         "$(( $(safe_count "$WS/http/technologies.txt") + $(safe_count "$WS/technologies/whatweb.txt") ))"
echo ""
echo -e "Workspace: ${CYAN}$WS${RESET}"
echo -e "${BOLD}========================================${RESET}"

if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
    warn "Missing tools (steps skipped or degraded):"
    printf '  - %s\n' "${MISSING_TOOLS[@]}"
fi
root@3bd039747087:/home/ubuntu#