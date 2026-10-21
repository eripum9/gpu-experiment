#!/bin/sh
# Read-only, user-side capture for the CobaltNavi44Survey diagnostic service.

umask 077

usage() {
    echo "Usage: sh $0 [output-directory]" >&2
    exit 1
}

[ "$#" -le 1 ] || usage

case $0 in
    */*) script_path=${0%/*} ;;
    *) script_path=. ;;
esac
script_dir=$(CDPATH= cd -- "$script_path" 2>/dev/null && pwd) || {
    echo "Cannot resolve the script directory." >&2
    exit 1
}
base_dir=${1:-$script_dir}
stamp=$(date '+%Y%m%d-%H%M%S' 2>/dev/null) || {
    echo "Cannot get a timestamp." >&2
    exit 1
}
report_dir=$base_dir/CobaltNavi44Survey-$stamp
mkdir -p "$base_dir" 2>/dev/null || {
    echo "Cannot create output directory: $base_dir" >&2
    exit 1
}
suffix=1
while [ -e "$report_dir" ]; do
    report_dir=$base_dir/CobaltNavi44Survey-$stamp-$suffix
    suffix=$((suffix + 1))
done
mkdir "$report_dir" 2>/dev/null || {
    echo "Cannot create report directory: $report_dir" >&2
    exit 1
}
chmod 700 "$report_dir" 2>/dev/null || :

failed=0

capture() {
    label=$1
    shift
    if "$@" >"$report_dir/$label.txt" 2>"$report_dir/$label.stderr.txt"; then
        result=0
    else
        result=$?
    fi
    printf '%s: exit %s\n' "$label" "$result" >>"$report_dir/status.txt"
    chmod 600 "$report_dir/$label.txt" "$report_dir/$label.stderr.txt" 2>/dev/null || :
    return "$result"
}

printf 'CobaltNavi44Survey read-only capture\nStarted: %s\n' "$stamp" >"$report_dir/README.txt"
printf 'Files contain command output and separate stderr. No system changes are made.\n' >>"$report_dir/README.txt"
printf 'Command results:\n' >"$report_dir/status.txt"

# These identify the host and whether the targeted service was observable.
capture sw_vers sw_vers || failed=1
capture uname uname -a || failed=1
capture ioreg-service ioreg -r -c CobaltNavi44Survey -l -w0
ioreg_rc=$?
[ "$ioreg_rc" -eq 0 ] || failed=1
capture ioreg-service-xml ioreg -r -c CobaltNavi44Survey -a || failed=1

# These diagnostics are useful when available; preserve failures and continue.
capture kmutil-showloaded kmutil showloaded || :
capture boot-log log show --last 15m --style compact --predicate 'process == "kernel" AND eventMessage CONTAINS "CobaltNavi44Survey"' || :

chmod 600 "$report_dir/README.txt" "$report_dir/status.txt" 2>/dev/null || :

if [ "$failed" -ne 0 ]; then
    echo "Capture completed with required-command failures. Report: $report_dir" >&2
    exit 1
fi

if [ ! -s "$report_dir/ioreg-service.txt" ]; then
    printf 'Service status: MISSING (no CobaltNavi44Survey instance returned)\n' >>"$report_dir/README.txt"
    chmod 600 "$report_dir/README.txt" 2>/dev/null || :
    echo "CobaltNavi44Survey service was not found. Report: $report_dir" >&2
    exit 2
fi

printf 'Service status: instance output captured\n' >>"$report_dir/README.txt"
chmod 600 "$report_dir/README.txt" 2>/dev/null || :

echo "Capture completed. Report: $report_dir"
exit 0
