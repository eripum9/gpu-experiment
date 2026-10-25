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

fail() { echo "early reset setup: $*" >&2; exit 1; }
regular_file() { [ -f "$1" ] && [ ! -L "$1" ]; }
get_plan() { /usr/bin/plutil -extract "$1" raw -o - "$PLAN" 2>/dev/null; }
sha_file() { /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'; }
valid_hash() { case "$1" in *[!0-9a-f]*|'') return 1;; esac; [ "${#1}" -eq 64 ]; }
check_hash() {
    _file=$1 _want=$2
    regular_file "$_file" || fail "missing, non-regular, or symlink payload file: $_file"
    valid_hash "$_want" || fail "invalid plan hash"
    [ "$(sha_file "$_file")" = "$_want" ] || fail "payload hash mismatch: $(basename "$_file")"
}
plist_value() { /usr/bin/plutil -extract "$2" raw -o - "$1" 2>/dev/null; }
restore_baseline_if_known() {
    { [ "$ROOT_CREATED" = 1 ] || [ "$DAEMON_CREATED" = 1 ] || [ "$ARM_TMP_CREATED" = 1 ] || [ "$INSTALL_STARTED" = 1 ]; } || return 0
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
[ "$(sha_file "$EFI_CONFIG")" = "$BOOTSTRAP_HASH" ] || fail 'live EFI config is not the expected passive bootstrap config'

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
SESSION_DIR=$TAHOE/EARLY-RESET-$SESSION
[ ! -e "$SESSION_DIR" ] && [ ! -L "$SESSION_DIR" ] || fail 'session capture directory already exists'
mkdir -m 700 "$SESSION_DIR" || fail 'cannot create session capture directory'

# Required pre-arm baseline capture. It must succeed before any config is armed.
if ! /bin/sh "$PAYLOAD_DIR/collect-gpu-survey.sh" "$SESSION_DIR/baseline"; then
    fail 'baseline survey capture failed; refusing to arm'
fi
INSTALL_STARTED=1

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

 [ ! -e "$DAEMON" ] && [ ! -L "$DAEMON" ] || fail 'LaunchDaemon appeared before creation'
: > "$DAEMON"
DAEMON_CREATED=1
cat > "$DAEMON" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.cobalt.early-reset-capture</string>
  <key>ProgramArguments</key><array><string>/bin/sh</string><string>$ROOT/capture-early-reset.sh</string><string>--capture-once</string></array>
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
