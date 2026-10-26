#!/bin/sh
# One-shot next-boot evidence collection. Never activates the GPU client.
set -u
umask 077

ROOT='/Library/Application Support/CobaltEarlyResetTest'
DAEMON='/Library/LaunchDaemons/com.cobalt.early-reset-capture.plist'
TAHOE='/Volumes/TAHOE'
EFI_CONFIG=$TAHOE/EFI/OC/config.plist
LOG='/var/log/cobalt-early-reset-capture.log'

if [ "${1-}" = --help ]; then
    echo 'Usage: capture-early-reset.sh --capture-once | --probe-usb'
    exit 0
fi

say() { echo "$(date '+%Y-%m-%dT%H:%M:%S%z') $*" >> "$LOG" 2>&1; }
regular_file() { [ -f "$1" ] && [ ! -L "$1" ]; }
get_plan() { /usr/bin/plutil -extract "$1" raw -o - "$ROOT/plan.plist" 2>/dev/null; }
sha_file() {
    _sha=$(/usr/bin/shasum -a 256 "$1") || { say "cannot hash file (permission/access failure): $1"; return 1; }
    printf '%s\n' "${_sha%% *}"
}
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
[ "$#" -eq 1 ] || exit 2
case "$1" in --capture-once|--probe-usb) MODE=$1;; *) exit 2;; esac
say "capture agent startup: $MODE"
[ -d "$ROOT" ] && [ ! -L "$ROOT" ] || { say 'capture directory absent or unsafe; no session consumed'; exit 0; }
[ -f "$ROOT/pending-session" ] && [ ! -L "$ROOT/pending-session" ] || { say 'no pending session; leaving boot unchanged'; exit 0; }
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

probe_usb() {
    say 'starting USB permission preflight in native launcher child context'
    regular_file "$ROOT/probe-request" || return 1
    {
        IFS= read -r REQUEST_SESSION && IFS= read -r REQUEST_HASH && IFS= read -r NONCE
    } < "$ROOT/probe-request" || return 1
    [ "$REQUEST_SESSION" = "$SESSION" ] || return 1
    PLAN_HASH=$(sha_file "$ROOT/plan.plist") || return 1
    [ "$REQUEST_HASH" = "$PLAN_HASH" ] || return 1
    case "$NONCE" in *[!0-9a-f]*|'') return 1;; esac
    [ "${#NONCE}" = 32 ] || return 1
    PROBE_DIR=$ROOT/probe-$NONCE
    [ -d "$PROBE_DIR" ] && [ ! -L "$PROBE_DIR" ] || return 1
    [ "$(/usr/bin/stat -f '%u:%g' "$PROBE_DIR")" = 0:0 ] || return 1
    BOOTARGS=$(/usr/sbin/sysctl -n kern.bootargs 2>/dev/null) || return 1
    for _flag in cobalt-survey cobalt-survey-indexed cobalt-survey-state; do require_flag "$_flag" || return 1; done
    for _flag in cobalt-survey-mode1 cobalt-survey-mode1boot cobalt-survey-aperture cobalt-survey-staging cobalt-survey-kdb cobalt-survey-spl cobalt-survey-presos cobalt-survey-sos; do require_off "$_flag" || return 1; done
    PLATFORM=$(/usr/sbin/ioreg -rd1 -c IOPlatformExpertDevice -a 2>/dev/null) || return 1
    LIVE_UUID=$(extract "$PLATFORM" 0.IOPlatformUUID) || return 1
    [ "$(printf '%s' "$LIVE_UUID" | /usr/bin/tr 'A-F' 'a-f')" = "$(printf '%s' "$SYSTEM_UUID" | /usr/bin/tr 'A-F' 'a-f')" ] || return 1
    [ -d "$TAHOE" ] && [ ! -L "$TAHOE" ] || return 1
    INFO=$(/usr/sbin/diskutil info -plist "$TAHOE" 2>/dev/null) || return 1
    VOL_UUID=$(extract "$INFO" DiskUUID) || return 1
    PARENT=$(extract "$INFO" ParentWholeDisk) || return 1
    BUS=$(/usr/sbin/diskutil info -plist "$PARENT" 2>/dev/null) || return 1
    BUS=$(extract "$BUS" BusProtocol) || return 1
    [ "$(printf '%s' "$VOL_UUID" | /usr/bin/tr 'A-F' 'a-f')" = "$PARTITION" ] && [ "$BUS" = USB ] || return 1
    regular_file "$EFI_CONFIG" || { say 'preflight EFI config missing/unsafe/inaccessible'; return 1; }
    BOOTSTRAP_HASH=$(get_plan BootstrapConfigSHA256) || return 1
    check_hash "$EFI_CONFIG" "$BOOTSTRAP_HASH" || return 1
    USB_SOURCE=$TAHOE/EFI/OC/.cobalt-early-probe-$SESSION-$NONCE.tmp
    USB_COPY=$USB_SOURCE.copy
    USB_RENAMED=$USB_SOURCE.verified
    USB_OUTPUT_DIR=$TAHOE/.cobalt-early-output-probe-$SESSION-$NONCE
    USB_SOURCE_CREATED=0 USB_COPY_CREATED=0 USB_RENAMED_CREATED=0 USB_OUTPUT_CREATED=0
    trap 'cleanup_probe_files' EXIT
    trap 'exit 1' HUP INT TERM
    for _file in "$USB_SOURCE" "$USB_COPY" "$USB_RENAMED" "$USB_OUTPUT_DIR" "$PROBE_DIR/source" "$PROBE_DIR/copied" "$PROBE_DIR/renamed" "$PROBE_DIR/result" "$PROBE_DIR/result.tmp"; do
        [ ! -e "$_file" ] && [ ! -L "$_file" ] || return 1
    done
    printf 'Session=%s\nPlanSHA256=%s\nNonce=%s\nprobe_complete=1\n' "$SESSION" "$PLAN_HASH" "$NONCE" > "$PROBE_DIR/source" || return 1
    SOURCE_HASH=$(sha_file "$PROBE_DIR/source") || return 1
    cp "$PROBE_DIR/source" "$PROBE_DIR/copied" && check_hash "$PROBE_DIR/copied" "$SOURCE_HASH" || return 1
    mv "$PROBE_DIR/copied" "$PROBE_DIR/renamed" && check_hash "$PROBE_DIR/renamed" "$SOURCE_HASH" || return 1
    (set -C; : > "$USB_SOURCE") || return 1
    USB_SOURCE_CREATED=1
    cp "$PROBE_DIR/source" "$USB_SOURCE" && check_hash "$USB_SOURCE" "$SOURCE_HASH" || return 1
    (set -C; : > "$USB_COPY") || return 1
    USB_COPY_CREATED=1
    cp "$USB_SOURCE" "$USB_COPY" && check_hash "$USB_COPY" "$SOURCE_HASH" || return 1
    mv "$USB_COPY" "$USB_RENAMED" || return 1
    USB_COPY_CREATED=0 USB_RENAMED_CREATED=1
    check_hash "$USB_RENAMED" "$SOURCE_HASH" || return 1
    rm "$USB_SOURCE" "$USB_RENAMED" || return 1
    USB_SOURCE_CREATED=0 USB_RENAMED_CREATED=0
    # Also prove the capture-output parent permits creation and rename, rather
    # than relying on access to an EFI file alone.
    mkdir -m 700 "$USB_OUTPUT_DIR" || return 1
    USB_OUTPUT_CREATED=1
    cp "$PROBE_DIR/source" "$USB_OUTPUT_DIR/source" && check_hash "$USB_OUTPUT_DIR/source" "$SOURCE_HASH" || return 1
    mv "$USB_OUTPUT_DIR/source" "$USB_OUTPUT_DIR/verified" && check_hash "$USB_OUTPUT_DIR/verified" "$SOURCE_HASH" || return 1
    rm "$USB_OUTPUT_DIR/verified" && rmdir "$USB_OUTPUT_DIR" || return 1
    USB_OUTPUT_CREATED=0
    # Prove that the real passive config was never replaced by the probe.
    check_hash "$EFI_CONFIG" "$BOOTSTRAP_HASH" || return 1
    check_hash "$ROOT/config-baseline.plist" "$BASE_HASH" || return 1
    cp "$PROBE_DIR/renamed" "$PROBE_DIR/result.tmp" && check_hash "$PROBE_DIR/result.tmp" "$SOURCE_HASH" || return 1
    mv "$PROBE_DIR/result.tmp" "$PROBE_DIR/result" || return 1
    cleanup_probe_files
    say 'USB permission preflight passed; passive config unchanged'
}
cleanup_probe_files() {
    [ "${USB_SOURCE_CREATED-0}" = 1 ] && regular_file "$USB_SOURCE" && rm -f "$USB_SOURCE"
    [ "${USB_COPY_CREATED-0}" = 1 ] && regular_file "$USB_COPY" && rm -f "$USB_COPY"
    [ "${USB_RENAMED_CREATED-0}" = 1 ] && regular_file "$USB_RENAMED" && rm -f "$USB_RENAMED"
    if [ "${USB_OUTPUT_CREATED-0}" = 1 ] && [ -d "$USB_OUTPUT_DIR" ] && [ ! -L "$USB_OUTPUT_DIR" ]; then
        for _output_file in source verified; do
            regular_file "$USB_OUTPUT_DIR/$_output_file" && rm -f "$USB_OUTPUT_DIR/$_output_file"
        done
        rmdir "$USB_OUTPUT_DIR" 2>/dev/null || true
    fi
    return 0
}
if [ "$MODE" = --probe-usb ]; then
    if probe_usb; then exit 0; fi
    say 'USB permission preflight refused; grant /Applications/CobaltEarlyCapture.app Full Disk Access and rerun installer; no config armed'
    exit 1
fi

# Avoid consuming the one-shot on setup, recovery, or any unintended boot.
BOOTARGS=$(/usr/sbin/sysctl -n kern.bootargs 2>/dev/null) || { say 'cannot read boot arguments; session retained'; exit 0; }
for _flag in cobalt-survey=1 cobalt-survey-indexed=1 cobalt-survey-state=1 cobalt-survey-mode1boot=1; do
    require_flag "${_flag%=*}" || { say "not the intended early boot: missing/invalid $_flag; session retained"; exit 0; }
done
for _flag in cobalt-survey-mode1 cobalt-survey-aperture cobalt-survey-staging cobalt-survey-kdb cobalt-survey-spl cobalt-survey-presos cobalt-survey-sos; do
    require_off "$_flag" || { say "conflicting boot flag $_flag; session retained"; exit 0; }
done

# Check the planned Mac's hardware UUID before waiting for removable media.
PLATFORM=$(/usr/sbin/ioreg -rd1 -c IOPlatformExpertDevice -a 2>/dev/null) || exit 0
LIVE_UUID=$(extract "$PLATFORM" 0.IOPlatformUUID) || exit 0
[ "$(printf '%s' "$LIVE_UUID" | /usr/bin/tr 'A-F' 'a-f')" = "$(printf '%s' "$SYSTEM_UUID" | /usr/bin/tr 'A-F' 'a-f')" ] || { say 'system UUID mismatch; leaving pending setup untouched'; exit 0; }

collect_evidence() {
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

}
capture_failure() {
    say "$*; preserving private local evidence; pending session retained; refusing automatic reboot"
    SESSION_DIR=$(/usr/bin/mktemp -d "$ROOT/evidence-$SESSION.XXXXXXXX") || { say 'cannot create private evidence directory'; exit 1; }
    chmod 700 "$SESSION_DIR"
    RECEIPT=$SESSION_DIR/incomplete-receipt.txt
    printf 'Session: %s\nusb_restore_verified=0\ncapture_complete=0\nreason=%s\n' "$SESSION" "$*" > "$RECEIPT"
    collect_evidence
    cp "$LOG" "$SESSION_DIR/capture-agent.log" || true
    /bin/sync || true
    exit 1
}

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
[ "$attempt" -lt 180 ] || { capture_failure 'expected USB partition did not appear within 180 seconds'; }

SESSION_DIR=$TAHOE/EARLY-RESET-$SESSION
[ -d "$SESSION_DIR" ] && [ ! -L "$SESSION_DIR" ] || { capture_failure 'session capture directory missing/unsafe'; }
[ -f "$EFI_CONFIG" ] && [ ! -L "$EFI_CONFIG" ] || { capture_failure 'EFI config missing/unsafe'; }
CURRENT_HASH=$(sha_file "$EFI_CONFIG") || { capture_failure 'cannot hash EFI config'; }
if [ "$CURRENT_HASH" = "$ARMED_HASH" ]; then
    cp "$EFI_CONFIG" "$SESSION_DIR/config-armed-observed.plist" || { capture_failure 'cannot preserve armed config'; }
    [ "$(sha_file "$SESSION_DIR/config-armed-observed.plist")" = "$ARMED_HASH" ] || { capture_failure 'armed config snapshot mismatch'; }
    TMP=$EFI_CONFIG.early-reset-restore.tmp
    [ ! -e "$TMP" ] && [ ! -L "$TMP" ] || { capture_failure 'restore temp path already exists'; }
    cp "$ROOT/config-baseline.plist" "$TMP" || { capture_failure 'cannot prepare baseline restore'; }
    [ "$(sha_file "$TMP")" = "$BASE_HASH" ] || { capture_failure 'baseline restore copy mismatch'; }
    chmod 644 "$TMP"
    mv "$TMP" "$EFI_CONFIG" || { capture_failure 'cannot atomically restore baseline config'; }
    [ "$(sha_file "$EFI_CONFIG")" = "$BASE_HASH" ] || { capture_failure 'baseline restore verification failed'; }
elif [ "$CURRENT_HASH" = "$BASE_HASH" ]; then
    : # A prior partial run already disarmed the USB; continue the capture.
else
    capture_failure 'USB config is neither planned armed nor baseline config'
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

collect_evidence

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
