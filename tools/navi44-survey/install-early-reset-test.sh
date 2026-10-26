#!/bin/sh
# Installs a one-shot, next-boot capture job for the controlled early-reset test.
# This installer never executes the GPU client.  The reset request is made only
# by the already-installed kernel extension during the explicitly armed boot.
set -eu

usage() {
    cat <<'EOF'
Usage: install-early-reset-test.sh --install-and-reboot

Installs the verified capture agent for the next boot, arms the USB config,
then requests one normal reboot. Run from the supplied TAHOE payload on macOS.
EOF
}

if [ "${1-}" = --help ]; then usage; exit 0; fi
[ "${1-}" = --install-and-reboot ] && [ "$#" -eq 1 ] || { usage >&2; exit 2; }
[ "$(uname -s)" = Darwin ] || { echo "This installer requires macOS." >&2; exit 2; }
[ "$(/usr/bin/id -u)" = 0 ] || { echo "Run as root (sudo)." >&2; exit 2; }

PAYLOAD_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd -P)
PLAN=$PAYLOAD_DIR/plan.plist
ROOT='/Library/Application Support/CobaltEarlyResetTest'
DAEMON='/Library/LaunchDaemons/com.cobalt.early-reset-capture.plist'
PREFLIGHT='/Library/LaunchDaemons/com.cobalt.early-reset-preflight.plist'
APP='/Applications/CobaltEarlyCapture.app'
LAUNCHER=$APP/Contents/MacOS/CobaltEarlyCapture
TAHOE='/Volumes/TAHOE'
EFI_CONFIG=$TAHOE/EFI/OC/config.plist
SESSION=''
BOOTSTRAP_HASH=''
ARMED_HASH=''
BASELINE_HASH=''
ROOT_CREATED=0
DAEMON_CREATED=0
ARM_TMP_CREATED=0
INSTALL_STARTED=0
COMMITTED=0
PREFLIGHT_CREATED=0
PREFLIGHT_LOADED=0
PROBE_DIR=''
PROBE_REQUEST_CREATED=0

fail() { echo "early reset setup: $*" >&2; exit 1; }
regular_file() { [ -f "$1" ] && [ ! -L "$1" ]; }
get_plan() { /usr/bin/plutil -extract "$1" raw -o - "$PLAN" 2>/dev/null; }
sha_file() {
    _sha=$(/usr/bin/shasum -a 256 "$1") || { echo "cannot hash file: $1" >&2; return 1; }
    printf '%s\n' "${_sha%% *}"
}
valid_hash() { case "$1" in *[!0-9a-f]*|'') return 1;; esac; [ "${#1}" -eq 64 ]; }
check_hash() {
    _file=$1 _want=$2
    regular_file "$_file" || fail "missing, non-regular, or symlink payload file: $_file"
    valid_hash "$_want" || fail "invalid plan hash"
    _actual=$(sha_file "$_file") || fail "cannot hash payload file: $(basename "$_file")"
    [ "$_actual" = "$_want" ] || fail "payload hash mismatch: $(basename "$_file")"
}
plist_value() { /usr/bin/plutil -extract "$2" raw -o - "$1" 2>/dev/null; }
restore_baseline_if_known() {
    [ "$INSTALL_STARTED" = 1 ] || return 0
    verify_usb_identity || return 0
    [ -f "$PAYLOAD_DIR/config-baseline.plist" ] && [ ! -L "$PAYLOAD_DIR/config-baseline.plist" ] || return 0
    [ -f "$EFI_CONFIG" ] && [ ! -L "$EFI_CONFIG" ] || return 0
    _hash=$(sha_file "$EFI_CONFIG" 2>/dev/null || true)
    if [ "$_hash" = "$BOOTSTRAP_HASH" ] || [ "$_hash" = "$ARMED_HASH" ]; then
        _tmp=$EFI_CONFIG.early-reset-restore.tmp
        [ ! -e "$_tmp" ] && [ ! -L "$_tmp" ] || return 0
        cp "$PAYLOAD_DIR/config-baseline.plist" "$_tmp" || return 0
        [ "$(sha_file "$_tmp" 2>/dev/null || true)" = "$BASELINE_HASH" ] || { rm -f "$_tmp"; return 0; }
        chmod 644 "$_tmp" || { rm -f "$_tmp"; return 0; }
        mv "$_tmp" "$EFI_CONFIG" || { rm -f "$_tmp"; return 0; }
    fi
}
verify_usb_identity() {
    [ -d "$TAHOE" ] && [ ! -L "$TAHOE" ] || return 1
    _info=$(/usr/sbin/diskutil info -plist "$TAHOE" 2>/dev/null) || return 1
    _uuid=$(printf '%s' "$_info" | /usr/bin/plutil -extract DiskUUID raw -o - - 2>/dev/null) || return 1
    [ "$(printf '%s' "$_uuid" | /usr/bin/tr 'A-F' 'a-f')" = "$PARTITION" ] || return 1
    _parent=$(printf '%s' "$_info" | /usr/bin/plutil -extract ParentWholeDisk raw -o - - 2>/dev/null) || return 1
    _bus=$(/usr/sbin/diskutil info -plist "$_parent" 2>/dev/null | /usr/bin/plutil -extract BusProtocol raw -o - - 2>/dev/null) || return 1
    [ "$_bus" = USB ]
}
cleanup_failed_setup() {
    cleanup_probe
    [ "$COMMITTED" = 1 ] && return
    restore_baseline_if_known
    [ "$ARM_TMP_CREATED" = 1 ] && [ -f "$EFI_CONFIG.early-reset.tmp" ] && [ ! -L "$EFI_CONFIG.early-reset.tmp" ] && rm -f "$EFI_CONFIG.early-reset.tmp"
    if [ "$DAEMON_CREATED" = 1 ] && [ -f "$DAEMON" ] && [ ! -L "$DAEMON" ]; then rm -f "$DAEMON"; fi
    if [ "$ROOT_CREATED" = 1 ] && [ -d "$ROOT" ] && [ ! -L "$ROOT" ]; then
        for _name in plan.plist config-baseline.plist collect-gpu-survey.sh mode1-reset capture-early-reset.sh pending-session; do
            [ ! -L "$ROOT/$_name" ] && [ -f "$ROOT/$_name" ] && rm -f "$ROOT/$_name"
        done
        rmdir "$ROOT" 2>/dev/null || true
    fi
}
cleanup_probe() {
    if [ "$PREFLIGHT_LOADED" = 1 ]; then
        /bin/launchctl bootout system/com.cobalt.early-reset-preflight 2>/dev/null || true
        PREFLIGHT_LOADED=0
    fi
    if [ "$PREFLIGHT_CREATED" = 1 ] && regular_file "$PREFLIGHT"; then rm -f "$PREFLIGHT"; fi
    if [ "$PROBE_REQUEST_CREATED" = 1 ] && regular_file "$ROOT/probe-request"; then rm -f "$ROOT/probe-request"; fi
    if [ -n "$PROBE_DIR" ] && [ -d "$PROBE_DIR" ] && [ ! -L "$PROBE_DIR" ]; then
        for _probe_file in expected result result.tmp source copied renamed; do
            regular_file "$PROBE_DIR/$_probe_file" && rm -f "$PROBE_DIR/$_probe_file"
        done
        rmdir "$PROBE_DIR" 2>/dev/null || true
    fi
}
trap cleanup_failed_setup EXIT
trap 'exit 1' HUP INT TERM
require_flag() {
    _key=$1 _count=0
    set -f
    for _arg in $BOOTARGS; do
        case "$_arg" in
            "$_key"=*) _count=$((_count + 1)); [ "$_arg" = "$_key=1" ] || return 1;;
        esac
    done
    [ "$_count" -eq 1 ]
}
require_off() {
    _key=$1 _count=0
    set -f
    for _arg in $BOOTARGS; do
        case "$_arg" in
            "$_key"=*)
                _count=$((_count + 1))
                [ "$_arg" = "$_key=0" ] || return 1
                ;;
        esac
    done
    [ "$_count" -le 1 ]
}

regular_file "$PLAN" || fail 'plan.plist missing or unsafe'
[ "$(get_plan PlanVersion)" = 1 ] || fail 'unsupported plan version'
SESSION=$(get_plan SessionID) || fail 'missing SessionID'
case "$SESSION" in *[!0-9a-f]*|'') fail 'invalid SessionID';; esac
[ "${#SESSION}" -eq 32 ] || fail 'invalid SessionID'
PARTITION=$(get_plan PartitionGUID) || fail 'missing PartitionGUID'
case "$PARTITION" in ????????-????-????-????-????????????) :;; *) fail 'invalid PartitionGUID';; esac
case "$PARTITION" in *[!0-9a-f-]*) fail 'invalid PartitionGUID';; esac
SYSTEM_UUID=$(get_plan ExpectedSystemUUID) || fail 'missing ExpectedSystemUUID'
case "$SYSTEM_UUID" in ????????-????-????-????-????????????) :;; *) fail 'invalid ExpectedSystemUUID';; esac
case "$SYSTEM_UUID" in *[!0-9A-Fa-f-]*) fail 'invalid ExpectedSystemUUID';; esac
REVISION=$(get_plan BuildRevision) || fail 'missing BuildRevision'
case "$REVISION" in *[!0-9a-f]*) fail 'invalid BuildRevision';; esac
[ "${#REVISION}" -eq 40 ] || fail 'invalid BuildRevision'
[ "$(get_plan BundleVersion)" = 0.12.0 ] || fail 'unexpected client version'

check_hash "$PAYLOAD_DIR/config-baseline.plist" "$(get_plan BaselineConfigSHA256)"
check_hash "$PAYLOAD_DIR/config-bootstrap.plist" "$(get_plan BootstrapConfigSHA256)"
check_hash "$PAYLOAD_DIR/config-armed.plist" "$(get_plan ArmedConfigSHA256)"
check_hash "$PAYLOAD_DIR/collect-gpu-survey.sh" "$(get_plan CollectorSHA256)"
check_hash "$PAYLOAD_DIR/mode1-reset" "$(get_plan ClientSHA256)"
check_hash "$PAYLOAD_DIR/capture-early-reset.sh" "$(get_plan CaptureAgentSHA256)"
check_hash "$PAYLOAD_DIR/install-early-reset-test.sh" "$(get_plan InstallerSHA256)"
check_hash "$PAYLOAD_DIR/CobaltEarlyCapture.app/Contents/MacOS/CobaltEarlyCapture" "$(get_plan LauncherSHA256)"
check_hash "$PAYLOAD_DIR/CobaltEarlyCapture.app/Contents/Info.plist" "$(get_plan AppInfoSHA256)"
check_hash "$PAYLOAD_DIR/CobaltEarlyCapture.app/Contents/_CodeSignature/CodeResources" "$(get_plan AppResourcesSHA256)"
PLAN_HASH=$(sha_file "$PLAN") || fail 'cannot hash private plan'

# Match the actual mounted volume, its GPT partition UUID, and USB bus. Volume
# name alone is never treated as identity.
[ -d "$TAHOE" ] && [ ! -L "$TAHOE" ] || fail 'expected TAHOE payload volume is not mounted'
TAHOE_REAL=$(CDPATH= cd -P "$TAHOE" && pwd -P) || fail 'cannot resolve TAHOE mount path'
[ "$PAYLOAD_DIR" = "$TAHOE_REAL/gpu-early-test" ] || fail 'installer must run from /Volumes/TAHOE/gpu-early-test'
INFO=$(/usr/sbin/diskutil info -plist "$TAHOE") || fail 'cannot inspect TAHOE volume'
VOL_UUID=$(printf '%s' "$INFO" | /usr/bin/plutil -extract DiskUUID raw -o - - 2>/dev/null) || fail 'diskutil did not report DiskUUID'
[ "$(printf '%s' "$VOL_UUID" | /usr/bin/tr 'A-F' 'a-f')" = "$PARTITION" ] || fail 'TAHOE partition UUID does not match plan'
VOL_NAME=$(printf '%s' "$INFO" | /usr/bin/plutil -extract VolumeName raw -o - - 2>/dev/null) || fail 'diskutil did not report volume name'
[ "$VOL_NAME" = TAHOE ] || fail 'mounted volume is not TAHOE'
PARENT=$(printf '%s' "$INFO" | /usr/bin/plutil -extract ParentWholeDisk raw -o - - 2>/dev/null) || fail 'missing TAHOE parent disk'
BUS=$(/usr/sbin/diskutil info -plist "$PARENT" | /usr/bin/plutil -extract BusProtocol raw -o - - 2>/dev/null) || fail 'cannot inspect TAHOE transport'
[ "$BUS" = USB ] || fail 'TAHOE is not on USB transport'
regular_file "$EFI_CONFIG" || fail 'EFI config.plist missing or unsafe'
BOOTSTRAP_HASH=$(get_plan BootstrapConfigSHA256)
ARMED_HASH=$(get_plan ArmedConfigSHA256)
BASELINE_HASH=$(get_plan BaselineConfigSHA256)
LIVE_HASH=$(sha_file "$EFI_CONFIG") || fail 'cannot hash live EFI config (permission/access failure)'
[ "$LIVE_HASH" = "$BOOTSTRAP_HASH" ] || fail 'live EFI config is not the expected passive bootstrap config'

# Confirm this is the passive bootstrap boot and the expected machine.
LIVE_UUID=$(/usr/sbin/ioreg -rd1 -c IOPlatformExpertDevice -a | /usr/bin/plutil -extract 0.IOPlatformUUID raw -o - - 2>/dev/null) || fail 'cannot read platform UUID'
[ "$(printf '%s' "$LIVE_UUID" | /usr/bin/tr 'A-F' 'a-f')" = "$(printf '%s' "$SYSTEM_UUID" | /usr/bin/tr 'A-F' 'a-f')" ] || fail 'this is not the planned Mac'
BOOTARGS=$(/usr/sbin/sysctl -n kern.bootargs 2>/dev/null) || fail 'cannot inspect kernel boot arguments'
for _flag in cobalt-survey=1 cobalt-survey-indexed=1 cobalt-survey-state=1; do
    require_flag "${_flag%=*}" || fail "required passive flag missing, duplicated, or invalid: $_flag"
done
for _flag in cobalt-survey-mode1 cobalt-survey-mode1boot cobalt-survey-aperture cobalt-survey-staging cobalt-survey-kdb cobalt-survey-spl cobalt-survey-presos cobalt-survey-sos; do
    require_off "$_flag" || fail "test/write flag is active, duplicated, or invalid: $_flag"
done
DRIVERS=$(/usr/sbin/ioreg -r -c CobaltNavi44Survey -l 2>/dev/null) || fail 'cannot inspect survey service'
case "$DRIVERS" in *'CobaltNavi44Survey'*) :;; *) fail 'Cobalt survey service is not loaded';; esac
case "$DRIVERS" in *'CobaltSurvey,BuildVersion" = "0.12.0"'*) :;; *) fail 'loaded survey service is not build 0.12.0';; esac
SERVICE_COUNT=$(printf '%s\n' "$DRIVERS" | /usr/bin/grep -c 'CobaltNavi44Survey  <class CobaltNavi44Survey' || true)
[ "$SERVICE_COUNT" = 1 ] || fail 'expected exactly one Cobalt survey service'

[ ! -e "$ROOT" ] && [ ! -L "$ROOT" ] || fail 'resident directory already exists; refusing to overwrite'
[ ! -e "$DAEMON" ] && [ ! -L "$DAEMON" ] || fail 'LaunchDaemon already exists; refusing to overwrite'
[ ! -e "$PREFLIGHT" ] && [ ! -L "$PREFLIGHT" ] || fail 'preflight LaunchDaemon already exists; refusing to overwrite'
SESSION_DIR=$TAHOE/EARLY-RESET-$SESSION
[ ! -e "$SESSION_DIR" ] && [ ! -L "$SESSION_DIR" ] || fail 'session capture directory already exists'

# Keep the verified app installed after a denied probe so it can be selected in
# Full Disk Access. Never overwrite an unknown or older app at this identity.
verify_app() {
    for _dir in "$APP" "$APP/Contents" "$APP/Contents/MacOS" "$APP/Contents/_CodeSignature"; do
        [ -d "$_dir" ] && [ ! -L "$_dir" ] || fail 'unsafe capture app directory'
        [ "$(/usr/bin/stat -f '%u:%g' "$_dir")" = 0:0 ] || fail 'capture app directory is not root:wheel owned'
        [ "$(/usr/bin/stat -f '%Lp' "$_dir")" = 755 ] || fail 'capture app directory permissions are unsafe'
    done
    for _entry in 'MacOS/CobaltEarlyCapture LauncherSHA256' 'Info.plist AppInfoSHA256' '_CodeSignature/CodeResources AppResourcesSHA256'; do
        set -- $_entry
        check_hash "$APP/Contents/$1" "$(get_plan "$2")"
        [ "$(/usr/bin/stat -f '%u:%g' "$APP/Contents/$1")" = 0:0 ] || fail 'capture app file is not root:wheel owned'
        case "$1" in MacOS/CobaltEarlyCapture) _mode=755;; *) _mode=644;; esac
        [ "$(/usr/bin/stat -f '%Lp' "$APP/Contents/$1")" = "$_mode" ] || fail 'capture app file permissions are unsafe'
    done
    [ "$(/usr/bin/find "$APP" -type f | /usr/bin/wc -l | /usr/bin/tr -d ' ')" = 3 ] || fail 'capture app has unexpected files'
    [ -z "$(/usr/bin/find "$APP" -type l -print)" ] || fail 'capture app has symlinks'
    /usr/bin/codesign --verify --strict "$APP" || fail 'capture app signature verification failed'
}
if [ -e "$APP" ] || [ -L "$APP" ]; then
    verify_app
else
    mkdir -m 755 "$APP" "$APP/Contents" "$APP/Contents/MacOS" "$APP/Contents/_CodeSignature"
    cp "$PAYLOAD_DIR/CobaltEarlyCapture.app/Contents/MacOS/CobaltEarlyCapture" "$LAUNCHER"
    cp "$PAYLOAD_DIR/CobaltEarlyCapture.app/Contents/Info.plist" "$APP/Contents/Info.plist"
    cp "$PAYLOAD_DIR/CobaltEarlyCapture.app/Contents/_CodeSignature/CodeResources" "$APP/Contents/_CodeSignature/CodeResources"
    chmod 755 "$APP" "$APP/Contents" "$APP/Contents/MacOS" "$APP/Contents/_CodeSignature" "$LAUNCHER"
    chmod 644 "$APP/Contents/Info.plist" "$APP/Contents/_CodeSignature/CodeResources"
    chown root:wheel "$APP" "$APP/Contents" "$APP/Contents/MacOS" "$APP/Contents/_CodeSignature" "$LAUNCHER" "$APP/Contents/Info.plist" "$APP/Contents/_CodeSignature/CodeResources"
    verify_app
fi

mkdir -m 700 "$ROOT" || fail 'cannot create resident directory'
ROOT_CREATED=1
cp "$PLAN" "$ROOT/plan.plist"
cp "$PAYLOAD_DIR/config-baseline.plist" "$ROOT/config-baseline.plist"
cp "$PAYLOAD_DIR/collect-gpu-survey.sh" "$ROOT/collect-gpu-survey.sh"
cp "$PAYLOAD_DIR/mode1-reset" "$ROOT/mode1-reset"
cp "$PAYLOAD_DIR/capture-early-reset.sh" "$ROOT/capture-early-reset.sh"
check_hash "$ROOT/collect-gpu-survey.sh" "$(get_plan CollectorSHA256)"
check_hash "$ROOT/mode1-reset" "$(get_plan ClientSHA256)"
check_hash "$ROOT/capture-early-reset.sh" "$(get_plan CaptureAgentSHA256)"
check_hash "$ROOT/config-baseline.plist" "$(get_plan BaselineConfigSHA256)"
check_hash "$ROOT/plan.plist" "$(sha_file "$PLAN")"
printf '%s\n' "$SESSION" > "$ROOT/pending-session"
chmod 700 "$ROOT" "$ROOT/capture-early-reset.sh" "$ROOT/collect-gpu-survey.sh" "$ROOT/mode1-reset"
chmod 600 "$ROOT/plan.plist" "$ROOT/config-baseline.plist" "$ROOT/pending-session"
chown root:wheel "$ROOT"
chown root:wheel "$ROOT/plan.plist" "$ROOT/config-baseline.plist" "$ROOT/collect-gpu-survey.sh" "$ROOT/mode1-reset" "$ROOT/capture-early-reset.sh" "$ROOT/pending-session"

# Exercise the real launchd -> signed app -> shell attribution before arming.
# A Terminal sudo check cannot establish permission in this background context.
NONCE=$(/usr/bin/uuidgen | /usr/bin/tr 'A-F' 'a-f' | /usr/bin/tr -d '-')
case "$NONCE" in *[!0-9a-f]*|'') fail 'cannot generate probe nonce';; esac
[ "${#NONCE}" = 32 ] || fail 'cannot generate probe nonce'
PROBE_DIR=$ROOT/probe-$NONCE
mkdir -m 700 "$PROBE_DIR" || fail 'cannot create owned probe directory'
(set -C; printf '%s\n%s\n%s\n' "$SESSION" "$PLAN_HASH" "$NONCE" > "$ROOT/probe-request") || fail 'cannot create probe request'
PROBE_REQUEST_CREATED=1
printf 'Session=%s\nPlanSHA256=%s\nNonce=%s\nprobe_complete=1\n' "$SESSION" "$PLAN_HASH" "$NONCE" > "$PROBE_DIR/expected"
: > "$PREFLIGHT"
PREFLIGHT_CREATED=1
cat > "$PREFLIGHT" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.cobalt.early-reset-preflight</string>
<key>ProgramArguments</key><array><string>$LAUNCHER</string><string>--probe-agent</string></array>
<key>RunAtLoad</key><false/>
<key>StandardOutPath</key><string>/var/log/cobalt-early-reset-capture.log</string>
<key>StandardErrorPath</key><string>/var/log/cobalt-early-reset-capture.log</string>
</dict></plist>
EOF
chmod 644 "$PREFLIGHT"
chown root:wheel "$PREFLIGHT"
/usr/bin/plutil -lint "$PREFLIGHT" >/dev/null || fail 'invalid preflight LaunchDaemon'
/bin/launchctl bootstrap system "$PREFLIGHT" || fail 'cannot bootstrap permission preflight'
PREFLIGHT_LOADED=1
/bin/launchctl kickstart system/com.cobalt.early-reset-preflight || fail 'cannot start permission preflight'
POLL=0
while [ "$POLL" -lt 30 ] && [ ! -f "$PROBE_DIR/result" ]; do /bin/sleep 1; POLL=$((POLL + 1)); done
if ! regular_file "$PROBE_DIR/result" || ! /usr/bin/cmp -s "$PROBE_DIR/expected" "$PROBE_DIR/result"; then
    fail 'USB permission preflight failed; grant /Applications/CobaltEarlyCapture.app Full Disk Access in System Settings, then rerun this installer. Config was not armed; no reboot requested. See /var/log/cobalt-early-reset-capture.log.'
fi
cleanup_probe
PROBE_DIR=''
PROBE_REQUEST_CREATED=0
PREFLIGHT_CREATED=0

mkdir -m 700 "$SESSION_DIR" || fail 'cannot create session capture directory'
# Required pre-arm baseline capture, after the background permission proof.
if ! /bin/sh "$PAYLOAD_DIR/collect-gpu-survey.sh" "$SESSION_DIR/baseline"; then
    fail 'baseline survey capture failed; refusing to arm'
fi
INSTALL_STARTED=1

 [ ! -e "$DAEMON" ] && [ ! -L "$DAEMON" ] || fail 'LaunchDaemon appeared before creation'
: > "$DAEMON"
DAEMON_CREATED=1
cat > "$DAEMON" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.cobalt.early-reset-capture</string>
  <key>ProgramArguments</key><array><string>$LAUNCHER</string><string>--run-agent</string></array>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>/var/log/cobalt-early-reset-capture.log</string>
  <key>StandardErrorPath</key><string>/var/log/cobalt-early-reset-capture.log</string>
</dict></plist>
EOF
chmod 644 "$DAEMON"
chown root:wheel "$DAEMON"
/usr/bin/plutil -lint "$DAEMON" >/dev/null || fail 'generated LaunchDaemon plist is invalid'

# The armed replacement is written last, verified, then atomically renamed.
TMP=$EFI_CONFIG.early-reset.tmp
[ ! -e "$TMP" ] && [ ! -L "$TMP" ] || fail 'refusing existing temporary config path'
verify_usb_identity || fail 'USB identity changed before arming'
[ "$(sha_file "$EFI_CONFIG")" = "$BOOTSTRAP_HASH" ] || fail 'live EFI config changed before arming'
ARM_TMP_CREATED=1
cp "$PAYLOAD_DIR/config-armed.plist" "$TMP"
[ "$(sha_file "$TMP")" = "$(get_plan ArmedConfigSHA256)" ] || fail 'armed config copy hash mismatch'
chmod 644 "$TMP"
mv "$TMP" "$EFI_CONFIG" || fail 'cannot atomically arm USB config'
[ "$(sha_file "$EFI_CONFIG")" = "$(get_plan ArmedConfigSHA256)" ] || fail 'armed EFI config verification failed'
ARM_TMP_CREATED=0
sync
echo "One-shot early reset capture installed for session $SESSION; rebooting normally."
COMMITTED=1
if ! /sbin/shutdown -r now; then
    COMMITTED=0
    cleanup_failed_setup
    fail 'normal reboot command failed; setup has been rolled back where safe'
fi
