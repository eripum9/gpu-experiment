#!/bin/sh
# One-shot next-boot evidence collection. Never activates the GPU client.
set -u

ROOT='/Library/Application Support/CobaltEarlyResetTest'
DAEMON='/Library/LaunchDaemons/com.cobalt.early-reset-capture.plist'
TAHOE='/Volumes/TAHOE'
EFI_CONFIG=$TAHOE/EFI/OC/config.plist
LOG='/var/log/cobalt-early-reset-capture.log'

if [ "${1-}" = --help ]; then
    echo 'Usage: capture-early-reset.sh --capture-once'
    exit 0
fi

say() { echo "$(date '+%Y-%m-%dT%H:%M:%S%z') $*" >> "$LOG" 2>&1; }
regular_file() { [ -f "$1" ] && [ ! -L "$1" ]; }
get_plan() { /usr/bin/plutil -extract "$1" raw -o - "$ROOT/plan.plist" 2>/dev/null; }
sha_file() { /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'; }
valid_hash() { case "$1" in *[!0-9a-f]*|'') return 1;; esac; [ "${#1}" -eq 64 ]; }
check_hash() {
    regular_file "$1" || { say "missing/unsafe resident file: $1"; return 1; }
    valid_hash "$2" || { say "invalid expected hash for $(basename "$1")"; return 1; }
    _actual=$(sha_file "$1") || return 1
    [ "$_actual" = "$2" ] || { say "hash mismatch for $(basename "$1"): expected $2 got $_actual"; return 1; }
}
extract() { printf '%s' "$1" | /usr/bin/plutil -extract "$2" raw -o - - 2>/dev/null; }
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
            "$_key"=*) _count=$((_count + 1)); [ "$_arg" = "$_key=0" ] || return 1;;
        esac
    done
    [ "$_count" -le 1 ]
}

[ "$(uname -s 2>/dev/null)" = Darwin ] || exit 0
[ "$(/usr/bin/id -u 2>/dev/null)" = 0 ] || exit 0
[ "${1-}" = --capture-once ] && [ "$#" -eq 1 ] || exit 2
[ -d "$ROOT" ] && [ ! -L "$ROOT" ] || exit 0
[ -f "$ROOT/pending-session" ] && [ ! -L "$ROOT/pending-session" ] || exit 0
regular_file "$ROOT/plan.plist" || { say 'unsafe/missing plan'; exit 1; }
SESSION=$(get_plan SessionID) || exit 1
case "$SESSION" in *[!0-9a-f]*|'') exit 1;; esac
[ "${#SESSION}" -eq 32 ] || exit 1
[ "$(cat "$ROOT/pending-session" 2>/dev/null)" = "$SESSION" ] || exit 1
PARTITION=$(get_plan PartitionGUID) || exit 1
SYSTEM_UUID=$(get_plan ExpectedSystemUUID) || exit 1
REVISION=$(get_plan BuildRevision) || exit 1
[ "$(get_plan PlanVersion)" = 1 ] || exit 1
[ "$(get_plan BundleVersion)" = 0.12.0 ] || exit 1
case "$PARTITION" in ????????-????-????-????-????????????) :;; *) exit 1;; esac
case "$PARTITION" in *[!0-9a-f-]*) exit 1;; esac
case "$SYSTEM_UUID" in ????????-????-????-????-????????????) :;; *) exit 1;; esac
case "$SYSTEM_UUID" in *[!0-9A-Fa-f-]*) exit 1;; esac
case "$REVISION" in *[!0-9a-f]*) exit 1;; esac
[ "${#REVISION}" -eq 40 ] || exit 1
BASE_HASH=$(get_plan BaselineConfigSHA256) || exit 1
ARMED_HASH=$(get_plan ArmedConfigSHA256) || exit 1
COLLECTOR_HASH=$(get_plan CollectorSHA256) || exit 1
CLIENT_HASH=$(get_plan ClientSHA256) || exit 1
AGENT_HASH=$(get_plan CaptureAgentSHA256) || exit 1
check_hash "$ROOT/capture-early-reset.sh" "$AGENT_HASH" || { say 'resident agent hash mismatch'; exit 1; }
check_hash "$ROOT/collect-gpu-survey.sh" "$COLLECTOR_HASH" || { say 'resident collector hash mismatch'; exit 1; }
check_hash "$ROOT/mode1-reset" "$CLIENT_HASH" || { say 'resident client hash mismatch'; exit 1; }
check_hash "$ROOT/config-baseline.plist" "$BASE_HASH" || { say 'resident baseline config hash mismatch'; exit 1; }

# Avoid consuming the one-shot on setup, recovery, or any unintended boot.
BOOTARGS=$(/usr/sbin/sysctl -n kern.bootargs 2>/dev/null) || exit 0
for _flag in cobalt-survey=1 cobalt-survey-indexed=1 cobalt-survey-state=1 cobalt-survey-mode1boot=1; do
    require_flag "${_flag%=*}" || exit 0
done
for _flag in cobalt-survey-mode1 cobalt-survey-aperture cobalt-survey-staging cobalt-survey-kdb cobalt-survey-spl cobalt-survey-presos cobalt-survey-sos; do
    require_off "$_flag" || exit 0
done

# Check the planned Mac's hardware UUID before waiting for removable media.
PLATFORM=$(/usr/sbin/ioreg -rd1 -c IOPlatformExpertDevice -a 2>/dev/null) || exit 0
LIVE_UUID=$(extract "$PLATFORM" 0.IOPlatformUUID) || exit 0
[ "$(printf '%s' "$LIVE_UUID" | /usr/bin/tr 'A-F' 'a-f')" = "$(printf '%s' "$SYSTEM_UUID" | /usr/bin/tr 'A-F' 'a-f')" ] || { say 'system UUID mismatch; leaving pending setup untouched'; exit 0; }

# A hard hang before userland starts cannot run this agent; the one-shot
# guarantee applies only after this code can run.
attempt=0
while [ "$attempt" -lt 180 ]; do
    if [ -d "$TAHOE" ] && [ ! -L "$TAHOE" ]; then
        INFO=$(/usr/sbin/diskutil info -plist "$TAHOE" 2>/dev/null) || INFO=''
        VOL_UUID=$(extract "$INFO" DiskUUID 2>/dev/null) || VOL_UUID=''
        PARENT=$(extract "$INFO" ParentWholeDisk 2>/dev/null) || PARENT=''
        BUS=''
        [ -n "$PARENT" ] && BUS=$(/usr/sbin/diskutil info -plist "$PARENT" 2>/dev/null | /usr/bin/plutil -extract BusProtocol raw -o - - 2>/dev/null || true)
        if [ "$(printf '%s' "$VOL_UUID" | /usr/bin/tr 'A-F' 'a-f')" = "$PARTITION" ] && [ "$BUS" = USB ]; then
            break
        fi
    fi
    /bin/sleep 1
    attempt=$((attempt + 1))
done
[ "$attempt" -lt 180 ] || { say 'expected USB partition did not appear within 180 seconds'; exit 0; }

SESSION_DIR=$TAHOE/EARLY-RESET-$SESSION
[ -d "$SESSION_DIR" ] && [ ! -L "$SESSION_DIR" ] || { say 'session capture directory missing/unsafe'; exit 1; }
[ -f "$EFI_CONFIG" ] && [ ! -L "$EFI_CONFIG" ] || { say 'EFI config missing/unsafe'; exit 1; }
CURRENT_HASH=$(sha_file "$EFI_CONFIG") || { say 'cannot hash EFI config'; exit 1; }
if [ "$CURRENT_HASH" = "$ARMED_HASH" ]; then
    cp "$EFI_CONFIG" "$SESSION_DIR/config-armed-observed.plist" || { say 'cannot preserve armed config'; exit 1; }
    [ "$(sha_file "$SESSION_DIR/config-armed-observed.plist")" = "$ARMED_HASH" ] || { say 'armed config snapshot mismatch'; exit 1; }
    TMP=$EFI_CONFIG.early-reset-restore.tmp
    [ ! -e "$TMP" ] && [ ! -L "$TMP" ] || { say 'restore temp path already exists'; exit 1; }
    cp "$ROOT/config-baseline.plist" "$TMP" || { say 'cannot prepare baseline restore'; exit 1; }
    [ "$(sha_file "$TMP")" = "$BASE_HASH" ] || { say 'baseline restore copy mismatch'; exit 1; }
    chmod 644 "$TMP"
    mv "$TMP" "$EFI_CONFIG" || { say 'cannot atomically restore baseline config'; exit 1; }
    [ "$(sha_file "$EFI_CONFIG")" = "$BASE_HASH" ] || { say 'baseline restore verification failed'; exit 1; }
elif [ "$CURRENT_HASH" = "$BASE_HASH" ]; then
    : # A prior partial run already disarmed the USB; continue the capture.
else
    say 'USB config is neither planned armed nor baseline config; leaving job pending'
    exit 1
fi

# Claim the pending marker only after intended-boot and USB checks and restore.
LOCK=$ROOT/active-$SESSION
mkdir "$LOCK" 2>/dev/null || exit 0
if ! mv "$ROOT/pending-session" "$ROOT/consumed-session-$SESSION"; then
    rmdir "$LOCK" 2>/dev/null || true
    exit 0
fi
RECEIPT=$ROOT/completion-$SESSION.txt
printf 'Session: %s\nSystem UUID: %s\nDiskUUID: %s\nBoot arguments: %s\n' \
    "$SESSION" "$LIVE_UUID" "$VOL_UUID" "$BOOTARGS" > "$RECEIPT"
chmod 600 "$RECEIPT"

# Wait briefly for the early driver properties, but collect partial logs even
# if the driver is absent, failed, or does not expose the expected metadata.
say "waiting up to 30 seconds for early-boot driver evidence for $SESSION"
POLL=0
DRIVER_STATUS=127
PEER_STATUS=127
PEER_OUTPUT=''
PLATFORM_DRIVER=''
BUILD_VERSION=not-observed
EARLY_REQUESTED=not-observed
TRIGGER=not-observed
while [ "$POLL" -lt 30 ]; do
    POLL=$((POLL + 1))
    PEER_OUTPUT=$("$ROOT/mode1-reset" --inspect-peers 2>&1)
    PEER_STATUS=$?
    PLATFORM_DRIVER=$(/usr/sbin/ioreg -r -c CobaltNavi44Survey -l 2>&1)
    DRIVER_STATUS=$?
    case "$PLATFORM_DRIVER" in *'CobaltSurvey,BuildVersion" = "0.12.0"'*) BUILD_VERSION=0.12.0;; esac
    case "$PLATFORM_DRIVER" in *'CobaltSurvey,Mode1ResetEarlyRequested" = Yes'*) EARLY_REQUESTED=yes;;
        *'CobaltSurvey,Mode1ResetEarlyRequested" = No'*) EARLY_REQUESTED=no;; esac
    case "$PLATFORM_DRIVER" in *'CobaltSurvey,Mode1ResetTrigger" = "early-boot"'*) TRIGGER=early-boot;;
        *'CobaltSurvey,Mode1ResetTrigger" = "manual"'*) TRIGGER=manual;; esac
    [ "$PEER_STATUS" -eq 0 ] && [ "$BUILD_VERSION" = 0.12.0 ] && \
        [ "$EARLY_REQUESTED" = yes ] && [ "$TRIGGER" = early-boot ] && break
    /bin/sleep 1
done
printf '%s\n' "$PLATFORM_DRIVER" > "$SESSION_DIR/early-driver-ioreg.txt"
printf '%s\n' "$PEER_OUTPUT" > "$SESSION_DIR/peer-inventory.txt"
printf 'driver_poll_attempts=%s\npeer_inspect_exit=%s\ndriver_ioreg_exit=%s\nbuild_version=%s\nearly_requested=%s\ntrigger=%s\n' \
    "$POLL" "$PEER_STATUS" "$DRIVER_STATUS" "$BUILD_VERSION" "$EARLY_REQUESTED" "$TRIGGER" >> "$RECEIPT"

COLLECT_STATUS=0
/bin/sh "$ROOT/collect-gpu-survey.sh" "$SESSION_DIR/after-early-test" > "$SESSION_DIR/collector.stdout.txt" 2> "$SESSION_DIR/collector.stderr.txt" || COLLECT_STATUS=$?
printf 'collector_exit=%s\n' "$COLLECT_STATUS" >> "$RECEIPT"
printf 'collector_exit=%s\n' "$COLLECT_STATUS" > "$SESSION_DIR/collector-exit-status.txt"

# Remove only this known plist. RunAtLoad without KeepAlive disables later boots;
# bootout of this currently running agent can kill us before evidence is durable.
if [ -f "$DAEMON" ] && [ ! -L "$DAEMON" ]; then
    /bin/rm "$DAEMON" 2>/dev/null || printf 'daemon_plist_cleanup=failed\n' >> "$RECEIPT"
fi
printf 'capture_complete=1\n' >> "$RECEIPT"
rmdir "$LOCK" 2>/dev/null || true
say "capture complete for $SESSION; preparing normal reboot (collector exit $COLLECT_STATUS)"
cp "$RECEIPT" "$SESSION_DIR/completion-$SESSION.txt" || { say 'USB receipt copy failed; refusing automatic reboot'; exit 1; }
cp "$LOG" "$SESSION_DIR/capture-agent.log" || { say 'USB agent log copy failed; refusing automatic reboot'; exit 1; }
/bin/sync || { say 'sync failed; refusing automatic reboot'; exit 1; }
SHUTDOWN_STATUS=0
/sbin/shutdown -r now || SHUTDOWN_STATUS=$?
printf 'shutdown_command_returned=%s\n' "$SHUTDOWN_STATUS" >> "$RECEIPT"
cp "$RECEIPT" "$SESSION_DIR/completion-$SESSION.txt" || exit 1
cp "$LOG" "$SESSION_DIR/capture-agent.log" || exit 1
/bin/sync || exit 1
if [ "$SHUTDOWN_STATUS" -ne 0 ]; then exit "$SHUTDOWN_STATUS"; fi
exit 0
