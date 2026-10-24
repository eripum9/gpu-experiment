#!/bin/sh
# Explicit, manually invoked Mode 1 reset test. This script never self-starts.

umask 077

usage() {
    printf 'Usage: sudo sh %s --run\n' "$0"
    printf '       sh %s --help\n' "$0"
}

if [ "$#" -eq 1 ] && [ "$1" = "--help" ]; then
    usage
    printf '\n--help is read-only. The test requires the exact --run argument.\n'
    exit 0
fi

if [ "$#" -ne 1 ] || [ "$1" != "--run" ]; then
    usage >&2
    printf 'Refusing: an exact explicit --run argument is required.\n' >&2
    exit 2
fi

printf '%s\n' 'WARNING: save all work first. The Mode 1 test may blank the display and will attempt a normal reboot after captures.' >&2
printf '%s\n' 'You must manually select Windows Boot Manager after that reboot. A hard hang may still require manual recovery.' >&2

case "$0" in
    */*) script_path=${0%/*}; [ -n "$script_path" ] || script_path=/ ;;
    *) script_path=. ;;
esac
SCRIPT_DIR=$(CDPATH= cd -P "$script_path" 2>/dev/null && pwd) || {
    printf 'Preflight failed: cannot resolve the script directory.\n' >&2
    exit 1
}
CLI=$SCRIPT_DIR/mode1-reset
COLLECTOR=$SCRIPT_DIR/collect-gpu-survey.sh

if [ "$(id -u 2>/dev/null)" != 0 ]; then
    printf 'Preflight failed: run as root, for example: sudo sh %s --run\n' "$0" >&2
    exit 1
fi
if [ "$(uname -s 2>/dev/null)" != Darwin ]; then
    printf 'Preflight failed: this helper must run from the booted macOS system.\n' >&2
    exit 1
fi
if [ ! -x "$CLI" ]; then
    printf 'Preflight failed: sibling CLI is missing or not executable: %s\n' "$CLI" >&2
    exit 1
fi
if [ ! -r "$COLLECTOR" ]; then
    printf 'Preflight failed: sibling collector is missing or unreadable: %s\n' "$COLLECTOR" >&2
    exit 1
fi
if [ ! -x /sbin/shutdown ] || ! command -v sync >/dev/null 2>&1; then
    printf 'Preflight failed: normal reboot or sync command is unavailable.\n' >&2
    exit 1
fi
for required_command in id uname date mkdir chmod sed tail cat tee sh; do
    if ! command -v "$required_command" >/dev/null 2>&1; then
        printf 'Preflight failed: required command is unavailable: %s\n' "$required_command" >&2
        exit 1
    fi
done
if [ ! -w "$SCRIPT_DIR" ]; then
    printf 'Preflight failed: script directory is not writable: %s\n' "$SCRIPT_DIR" >&2
    exit 1
fi

stamp=$(date '+%Y%m%d-%H%M%S' 2>/dev/null) || {
    printf 'Preflight failed: cannot obtain a timestamp.\n' >&2
    exit 1
}
case "$stamp" in
    *[!0-9-]*|'')
        printf 'Preflight failed: timestamp contains unexpected characters.\n' >&2
        exit 1
        ;;
esac
SESSION_DIR=$SCRIPT_DIR/SOFTWARE-RESET-$stamp
suffix=1
while [ -e "$SESSION_DIR" ]; do
    SESSION_DIR=$SCRIPT_DIR/SOFTWARE-RESET-$stamp-$suffix
    suffix=$((suffix + 1))
done
mkdir "$SESSION_DIR" 2>/dev/null || {
    printf 'Preflight failed: cannot create private session directory: %s\n' "$SESSION_DIR" >&2
    exit 1
}
# FAT32 test media do not implement POSIX permission bits.
chmod 700 "$SESSION_DIR" 2>/dev/null || :
LOG=$SESSION_DIR/orchestration.log
if ! : >"$LOG"; then
    printf 'Preflight failed: cannot create orchestration log in %s\n' "$SESSION_DIR" >&2
    exit 1
fi
chmod 600 "$LOG" 2>/dev/null || :

log() {
    printf '%s\n' "$*" | tee -a "$LOG"
}

run_collector() {
    capture_label=$1
    capture_output=$SESSION_DIR/$capture_label-collector-output.txt
    log "Running $capture_label survey capture."
    sh "$COLLECTOR" "$SESSION_DIR" >"$capture_output" 2>&1
    CAPTURE_RC=$?
    chmod 600 "$capture_output" 2>/dev/null || :
    capture_path=$(sed -n 's/^.*Report: //p' "$capture_output" | tail -n 1)
    if [ -n "$capture_path" ]; then
        CAPTURE_PATH=$capture_path
    else
        CAPTURE_PATH=not-reported
    fi
    {
        printf '\n--- %s collector output ---\n' "$capture_label"
        cat "$capture_output"
        printf '%s\n' "--- end $capture_label collector output ---"
    } >>"$LOG"
    log "$capture_label collector exit status: $CAPTURE_RC"
    log "$capture_label capture path: $CAPTURE_PATH"
}

log "Session directory: $SESSION_DIR"
log "CLI: $CLI"
log "Collector: $COLLECTOR"
log 'Preflight passed: root, booted Darwin, sibling files, writable destination, and normal reboot command.'

# Baseline capture is mandatory and happens before the one-shot reset request.
run_collector baseline
BASELINE_RC=$CAPTURE_RC
if [ "$BASELINE_RC" -ne 0 ]; then
    log "Aborting before reset: baseline collector failed with status $BASELINE_RC. No reboot will be attempted."
    sync
    exit "$BASELINE_RC"
fi
sync
log 'Baseline capture completed and synced before the reset request.'

# Deliberately invoke the fixed CLI exactly once. Even a refusal/error gets a
# post-attempt capture and a normal reboot attempt for the explicit --run flow.
CLI_OUTPUT=$SESSION_DIR/mode1-reset-output.txt
log 'Invoking mode1-reset --run-mode1-reset exactly once.'
"$CLI" --run-mode1-reset >"$CLI_OUTPUT" 2>&1
CLI_RC=$?
chmod 600 "$CLI_OUTPUT" 2>/dev/null || :
{
    printf '\n--- Mode 1 CLI output ---\n'
    cat "$CLI_OUTPUT"
    printf '%s\n' '--- end Mode 1 CLI output ---'
} >>"$LOG"
log "Mode 1 CLI exit status: $CLI_RC"

# Post capture is unconditional after the CLI invocation, including nonzero exit.
run_collector post
POST_RC=$CAPTURE_RC
log "Post-attempt capture exit status: $POST_RC"
sync
log 'All available captures and exit statuses synced to the USB session directory.'
log 'Attempting normal reboot with /sbin/shutdown -r now; select Windows Boot Manager after restart.'
sync
/sbin/shutdown -r now >>"$LOG" 2>&1
SHUTDOWN_RC=$?
log "Normal reboot command exit status: $SHUTDOWN_RC"
sync

if [ "$SHUTDOWN_RC" -ne 0 ]; then
    printf '%s\n' 'Normal reboot command failed. If macOS remains responsive, use its normal Restart action, then select Windows Boot Manager. Do not force power off unless the machine hangs.' >&2
    exit "$SHUTDOWN_RC"
fi
exit 0
