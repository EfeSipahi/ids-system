#!/bin/bash
# The lab of the proxy plan (T9, verification item 5): Caddy with ids_copy in
# front of a test application, ids-live behind the socket, and the 396 CSIC
# validation and test requests replayed over HTTPS.
#
#   lab/lab.sh build                 # the programs, Caddy and the CSIC files
#   lab/lab.sh equality              # 5.1: live gives the records offline gives
#   lab/lab.sh timing                # 5.2: the time ids_copy adds
#   lab/lab.sh overload              # 5.3: drops under a burst, all counted
#   lab/lab.sh stopstart             # 5.4: ids-live stopped during a replay
#   lab/lab.sh tls                   # 5.5: TLS, client IP, HTTP/2, HTTP/3
#   lab/lab.sh responses             # 5.6: response copies, max_wait, upgrade
#
# LIVE_CPUS and OTHER_CPUS, when set, pin ids-live and the other programs
# to those CPUs (taskset), to tell CPU sharing from waiting.
#
# Everything goes to $LAB (default /tmp/ids-lab), never to the repository,
# and Caddy's data too ($XDG_DATA_HOME). The CSIC files are made from the
# ids-model repository next to this one (tools/csic_to_examples.py).
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
LAB=${LAB:-/tmp/ids-lab}
BIN=$LAB/bin
export LAB_DATA=$LAB XDG_DATA_HOME=$LAB/xdg
CA=$LAB/caddy/pki/authorities/local/root.crt
CSIC=$LAB/csic396
mkdir -p "$LAB" "$XDG_DATA_HOME"
# A socket path can't be longer than 107 bytes: the socket gets a short
# folder of its own.
SOCKDIR=$(cat "$LAB/sockdir" 2>/dev/null || true)
if [ -z "$SOCKDIR" ] || [ ! -d "$SOCKDIR" ]; then
	SOCKDIR=$(mktemp -d /tmp/idslab.XXXX)
	echo "$SOCKDIR" > "$LAB/sockdir"
fi
export IDS_SOCKET=$SOCKDIR/copy.sock

say() { echo "== $*"; }
# pin CPUS: the command prefix that runs a program on those CPUs, or none.
# taskset replaces itself with the program, so a started program's $! is
# its own process ID, which stop() needs.
pin() { if [ -n "$1" ]; then echo "taskset -c $1"; fi; }
fail() { echo "FAILED: $*"; exit 1; }

build() {
	mkdir -p "$BIN"
	(cd "$REPO" && go build -o "$BIN/" ./cmd/ids-live ./cmd/ids-offline ./lab/testapp ./lab/replay ./lab/compare) || fail "go build"
	if [ ! -x "$BIN/caddy" ]; then
		local xcaddy
		xcaddy=$(command -v xcaddy || echo "$(go env GOPATH)/bin/xcaddy")
		(cd "$REPO" && "$xcaddy" build v2.11.9 --with github.com/EfeSipahi/ids-system/caddy-module=./caddy-module \
			--replace github.com/EfeSipahi/ids-system=. --output "$BIN/caddy") || fail "xcaddy build"
	fi
	if [ ! -d "$CSIC" ]; then
		python3 "$REPO/tools/csic_to_examples.py" --splits --out "$LAB/csic" || fail "CSIC conversion"
		mkdir -p "$CSIC"
		for f in validation-normal validation-anomalous test-normal test-anomalous; do
			cp "$LAB/csic/csic-$f.json" "$CSIC/"
		done
	fi
	# The CSIC configuration with absolute paths, so that a copy with other
	# live settings can sit in the lab folder.
	python3 - "$REPO" "$LAB" <<'PY'
import json, sys, os
repo, lab = sys.argv[1], sys.argv[2]
cfg = json.load(open(os.path.join(repo, "configs/csic-shop.json")))
fix = lambda p: os.path.normpath(os.path.join(repo, "configs", p))
cfg["files"] = [fix(f) for f in cfg["files"]]
for a in cfg.get("applications", []):
    a["profile"] = fix(a["profile"])
cfg.pop("records", None)
json.dump(cfg, open(os.path.join(lab, "csic-live.json"), "w"), indent=2)
cfg["live"] = {"socket": "unused", "workers": 1, "queue_copies": 5}
json.dump(cfg, open(os.path.join(lab, "csic-overload.json"), "w"), indent=2)
PY
	say "built: $(ls "$BIN" | tr '\n' ' ')"
}

FILES() { echo "$CSIC"/csic-validation-normal.json "$CSIC"/csic-validation-anomalous.json "$CSIC"/csic-test-normal.json "$CSIC"/csic-test-anomalous.json; }

APP_PID=""; CADDY_PID=""; LIVE_PID=""
start_app() {
	$(pin "${OTHER_CPUS:-}") "$BIN/testapp" -listen 127.0.0.1:9000 > "$LAB/testapp.log" 2>&1 & APP_PID=$!
	for i in $(seq 50); do curl -s -o /dev/null http://127.0.0.1:9000/ && return; sleep 0.1; done
	fail "testapp did not start"
}
start_caddy() {
	$(pin "${OTHER_CPUS:-}") "$BIN/caddy" run --config "$REPO/lab/Caddyfile" > "$LAB/caddy.log" 2>&1 & CADDY_PID=$!
	for i in $(seq 100); do [ -f "$CA" ] && curl -s -o /dev/null --cacert "$CA" https://localhost:8443/ && return; sleep 0.1; done
	fail "Caddy did not start; see $LAB/caddy.log"
}
start_live() { # start_live RECORDS-DIR [CONFIG]
	# Ready when this run prints its "Listening on" line, not when a socket
	# exists: one may be left by an earlier run.
	local before
	before=$(grep -c "^Listening on" "$LAB/ids-live.log" 2>/dev/null || true)
	$(pin "${LIVE_CPUS:-}") "$BIN/ids-live" -config "${2:-$LAB/csic-live.json}" -socket "$IDS_SOCKET" -records "$1" >> "$LAB/ids-live.log" 2>&1 & LIVE_PID=$!
	for i in $(seq 150); do
		[ "$(grep -c "^Listening on" "$LAB/ids-live.log")" -gt "${before:-0}" ] && return
		kill -0 "$LIVE_PID" 2>/dev/null || fail "ids-live stopped; see $LAB/ids-live.log"
		sleep 0.1
	done
	fail "ids-live did not start; see $LAB/ids-live.log"
}
stop() { # stop PID...: SIGTERM, then wait
	for p in "$@"; do [ -n "$p" ] && kill -TERM "$p" 2>/dev/null; done
	for p in "$@"; do [ -n "$p" ] && wait "$p" 2>/dev/null; done
}
stop_all() { stop "$LIVE_PID" "$CADDY_PID" "$APP_PID"; LIVE_PID=""; CADDY_PID=""; APP_PID=""; }
trap stop_all EXIT
# wait_copier: until Caddy's copier is connected to ids-live.
wait_copier() {
	for i in $(seq 50); do
		grep -q "copier connected" "$LAB/ids-live.log" 2>/dev/null && [ "$(grep -c 'copier connected' "$LAB/ids-live.log")" -gt "$(grep -c 'copier disconnected' "$LAB/ids-live.log")" ] && return
		sleep 0.1
	done
	fail "the copier did not connect"
}
replay() { $(pin "${OTHER_CPUS:-}") "$BIN/replay" -ca "$CA" "$@"; }

# summary DIR: what the records of a folder say.
summary() {
	python3 - "$1" <<'PY'
import json, sys, glob, os, collections
d = sys.argv[1]
analysed = recorded = 0; gaps = collections.Counter(); copiers = []
for f in sorted(glob.glob(os.path.join(d, "records-*.jsonl"))) + [os.path.join(d, "records.jsonl")]:
    if not os.path.exists(f): continue
    for l in open(f):
        r = json.loads(l)
        if r["type"] == "counts":
            analysed += r["analysed"]; recorded += r["recorded"]
        elif r["type"] == "gap":
            gaps[f'{r["source"]}: {r["reason"]}'] += r["missed"]
print(f"analysed {analysed}, recorded {recorded}, not analysed {sum(gaps.values())} {dict(gaps)}")
PY
}

memory() { # memory PID NAME: the most memory the process used
	echo "$2: $(grep -E 'VmHWM' /proc/"$1"/status | tr -s ' ')"
}

equality() {
	say "5.1 equality: the 396 CSIC requests, offline and through Caddy"
	local off=$LAB/eq/offline live=$LAB/eq/live
	rm -rf "$LAB/eq"; mkdir -p "$LAB/eq"
	"$BIN/ids-offline" -config "$LAB/csic-live.json" -requests "$CSIC" -summary -records "$off" | tail -n 4
	start_app; start_caddy; start_live "$live"; wait_copier
	replay -addr localhost:8080 $(FILES) || fail "replay"
	sleep 1
	stop "$LIVE_PID"; LIVE_PID=""
	tail -n 1 "$LAB/ids-live.log"
	"$BIN/compare" "$off" "$live"
	local same=$?
	stop_all
	return $same
}

timing() {
	say "5.2 added time: 396 requests × 10, kept connections, sequential and 8 at a time"
	rm -rf "$LAB/timing"; mkdir -p "$LAB/timing"
	start_app; start_caddy; start_live "$LAB/timing/records"; wait_copier
	for par in 1 8; do
		echo "-- $par at a time"
		printf "without ids_copy (8443):       "; replay -addr localhost:8443 -keepalive -repeat 10 -parallel $par $(FILES)
		printf "with ids_copy, ids-live runs:  "; replay -addr localhost:8080 -keepalive -repeat 10 -parallel $par $(FILES)
		kill -STOP "$LIVE_PID"
		printf "with ids_copy, ids-live hangs: "; replay -addr localhost:8080 -keepalive -repeat 10 -parallel $par $(FILES)
		kill -CONT "$LIVE_PID"
		stop "$LIVE_PID"; LIVE_PID=""
		printf "with ids_copy, ids-live off:   "; replay -addr localhost:8080 -keepalive -repeat 10 -parallel $par $(FILES)
		start_live "$LAB/timing/records"; wait_copier
	done
	memory "$CADDY_PID" caddy
	stop_all
	summary "$LAB/timing/records"
}

overload() {
	say "5.3 overload: ids-live with 1 worker and a queue of 5, the copier's queue 20, a burst of 16 at a time, ids-live paused for 2 s"
	rm -rf "$LAB/overload"; mkdir -p "$LAB/overload"
	export COPIER_QUEUE=20
	start_app; start_caddy; start_live "$LAB/overload/records" "$LAB/csic-overload.json"; wait_copier
	( sleep 1; kill -STOP "$LIVE_PID"; sleep 2; kill -CONT "$LIVE_PID" ) &
	local pauser=$!
	local out
	out=$(replay -addr localhost:8080 -keepalive -repeat 20 -parallel 16 -json $(FILES)) || fail "replay: $out"
	wait $pauser
	echo "$out"
	sleep 2
	memory "$LIVE_PID" ids-live; memory "$CADDY_PID" caddy
	stop "$LIVE_PID"; LIVE_PID=""
	tail -n 1 "$LAB/ids-live.log"
	stop_all
	unset COPIER_QUEUE
	local sent
	sent=$(echo "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sent"])')
	echo "sent $sent; records: $(summary "$LAB/overload/records")"
}

stopstart() {
	say "5.4 stop and start: 132 requests, ids-live stopped, 132 requests, ids-live started, 132 requests"
	rm -rf "$LAB/stopstart"; mkdir -p "$LAB/stopstart"
	start_app; start_caddy; start_live "$LAB/stopstart/records"; wait_copier
	replay -addr localhost:8080 -limit 132 $(FILES) || fail "replay 1"
	stop "$LIVE_PID"; LIVE_PID=""
	replay -addr localhost:8080 -skip 132 -limit 132 $(FILES) || fail "replay 2"
	start_live "$LAB/stopstart/records"; wait_copier
	sleep 1.5
	replay -addr localhost:8080 -skip 264 $(FILES) || fail "replay 3"
	sleep 1
	stop_all
	echo "sent 396; records: $(summary "$LAB/stopstart/records")"
}

# fields DIR: the live fields of the request records, one line each.
fields() {
	python3 - "$1" <<'PY'
import json, sys, os
for l in open(os.path.join(sys.argv[1], "records.jsonl")):
    r = json.loads(l)
    if r["type"] != "request": continue
    t, resp = r.get("tls") or {}, r.get("response") or {}
    print(f'{r["request"]["method"]} {r["request"]["path"][:32]:32} {r["request"].get("version",""):9} client {r["client"].get("ip","-"):14} conn {r.get("connection",{}).get("ip","-"):10} '
          f'tls {t.get("version","-")} {t.get("cipher","")} sni {t.get("server_name","-")} alpn {t.get("alpn","-")} | resp {resp.get("status","-")} {resp.get("content_type","")} '
          f'{resp.get("encoding","")} length {resp.get("body_length","-")} copied {resp.get("body_copied","-")} {resp.get("note","")}')
PY
}

tls_ip() {
	say "5.5 TLS and client IP: X-Forwarded-For untrusted, then trusted; HTTP/2; HTTP/3"
	rm -rf "$LAB/tls"; mkdir -p "$LAB/tls"
	start_app; start_caddy; start_live "$LAB/tls/records"; wait_copier
	replay -addr localhost:8080 -limit 2 -xff 198.51.100.7 "$CSIC/csic-test-anomalous.json"
	stop "$CADDY_PID"; CADDY_PID=""
	LAB_TRUSTED="127.0.0.1/32 ::1/128" start_caddy; wait_copier
	replay -addr localhost:8080 -skip 2 -limit 2 -xff 198.51.100.7 "$CSIC/csic-test-anomalous.json"
	replay -addr localhost:8080 -skip 4 -limit 2 -h2 "$CSIC/csic-test-anomalous.json"
	echo "HTTP/3: $(curl -s -o /dev/null -w '%{http_version} %{http_code}' --http3-only --cacert "$CA" "https://localhost:8080/tienda1/publico/caracteristicas.jsp?id=2+union+select+1")"
	sleep 1
	stop_all
	fields "$LAB/tls/records"
}

responses() {
	say "5.6 responses: types, sizes, max_wait, an upgrade"
	rm -rf "$LAB/resp"; mkdir -p "$LAB/resp"
	start_app; start_caddy; start_live "$LAB/resp/records"; wait_copier
	# The query makes each request an attack, so that it gets a record.
	local q="q=1+union+select+2"
	for p in "lab/text" "lab/html" "lab/image.png" "lab/big?kb=600&"; do
		case $p in *\&) url="https://localhost:8080/${p}$q" ;; *) url="https://localhost:8080/$p?$q" ;; esac
		curl -s -o /dev/null -w "$p %{http_code} %{size_download} bytes\n" --cacert "$CA" "$url"
	done
	# A client that takes gzip gets it as the application sent it. Without
	# Accept-Encoding, Caddy's proxy asks the application for gzip itself
	# and unzips the answer (Go's transport), so no gzip reaches the copier.
	curl -s -o /dev/null -w "lab/gzip (Accept-Encoding: gzip) %{http_code} %{size_download} bytes\n" -H "Accept-Encoding: gzip" --cacert "$CA" "https://localhost:8080/lab/gzip?$q"
	curl -s -o /dev/null -w "lab/gzip (no Accept-Encoding) %{http_code} %{size_download} bytes\n" --cacert "$CA" "https://localhost:8080/lab/gzip?$q&plain=1"
	local t0=$(date +%s.%N)
	curl -s -o /dev/null -w "lab/slow %{http_code} after %{time_total} s\n" --cacert "$CA" "https://localhost:8080/lab/slow?ms=12000&$q" &
	local slow=$!
	curl -s -o /dev/null -w "lab/ws %{http_code}\n" --max-time 3 --http1.1 --cacert "$CA" -H "Connection: Upgrade" -H "Upgrade: websocket" \
		-H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" "https://localhost:8080/lab/ws?$q"
	sleep 10.5
	echo "after 10.5 s, the slow request is still running: $(kill -0 $slow 2>/dev/null && echo yes || echo no); its record: $(grep -c 'not finished' "$LAB/resp/records/records.jsonl") with 'not finished'"
	wait $slow
	sleep 1
	stop_all
	fields "$LAB/resp/records"
}

[ $# -gt 0 ] || { sed -n '2,16p' "$0"; exit 2; }
for s in "$@"; do
	case $s in
	build) build ;;
	equality) equality ;;
	timing) timing ;;
	overload) overload ;;
	stopstart) stopstart ;;
	tls) tls_ip ;;
	responses) responses ;;
	*) echo "unknown: $s"; exit 2 ;;
	esac
done
