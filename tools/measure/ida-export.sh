#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
# SPDX-License-Identifier: Apache-2.0

# Exports IDA Free's function list for many binaries, several IDAs at once,
# with nobody at the keyboard. IDA Free has no batch mode (-A) and no command-line
# scripts (-S), so each binary is opened in the GUI on an invisible X screen
# (Xvfb) and xdotool does what a person would: Enter at the load dialog, then
# the exporter (fulg_export.idc on one line) typed into the IDC command line.
# It writes <binary>.ida.txt next to the binary and closes IDA.
#
#   tools/measure/ida-export.sh FILE_OR_DIR...
#
# Environment:
#   IDA=/opt/ida-free/ida   the IDA executable
#   JOBS=2                  IDAs running at once, each on its own screen
#   TIMEOUT=900             seconds per binary before IDA is killed
#   FORCE=1                 export again even if <binary>.ida.txt exists
#
# Needs Xvfb and xdotool. Binaries that time out or fail are listed in
# ida-export-failed.txt, with a screenshot (ida-export-<dir>-<name>.xwd) when xwd is
# installed. Run it again to retry them; finished binaries are skipped.
set -u

ida=${IDA:-/opt/ida-free/ida}
jobs=${JOBS:-2}
timeout=${TIMEOUT:-900}
failed=$PWD/ida-export-failed.txt

for tool in Xvfb xdotool "$ida"; do
    command -v "$tool" >/dev/null || { echo "error: $tool not found" >&2; exit 1; }
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# Ctrl+C stops every IDA and Xvfb this script started (they share its
# process group).
trap 'trap - INT TERM; rm -rf "$work"; echo "stopping"; kill 0' INT TERM

# fulg_export.idc on one line, for IDA's IDC command line, ending with
# qexit so IDA closes when the file is written.
command='auto f, ea; auto_wait(); f = fopen(get_input_file_path() + ".ida.txt", "w"); fprintf(f, "# ida imagebase 0x%x\n", get_imagebase()); ea = get_func_attr(0, FUNCATTR_START); if (ea != 0) ea = get_next_func(0); while (ea != BADADDR) { fprintf(f, "0x%x 0x%x %s\n", ea, get_func_attr(ea, FUNCATTR_END), get_func_name(ea)); ea = get_next_func(ea); } fclose(f); qexit(0);'

# True for the files IDA Free can open: PE, and x86 or x86-64 ELF (it has no
# ARM decoders).
supported() {
    case $(head -c 20 "$1" 2>/dev/null | od -An -tx1 | tr -d ' \n') in
        4d5a*) true ;;
        7f454c46????????????????????????????0300 | 7f454c46????????????????????????????3e00) true ;;
        *) false ;;
    esac
}

# Every input file, directories searched for the files IDA Free can open.
list=$work/list
for arg in "$@"; do
    if [ -d "$arg" ]; then
        find "$arg" -type f ! -name '*.txt' ! -name '*.i64' ! -name '*.id[0-2]' \
            ! -name '*.nam' ! -name '*.til' -print0 |
            while IFS= read -r -d '' f; do
                if supported "$f"; then realpath "$f"; fi
            done
    elif [ -f "$arg" ]; then
        if supported "$arg"; then realpath "$arg"; else echo "warning: IDA Free cannot open $arg, skipped" >&2; fi
    else
        echo "warning: $arg does not exist, skipped" >&2
    fi
done | sort -u > "$list"
total=$(wc -l < "$list")
[ "$total" -gt 0 ] || { echo "error: no x86 ELF or PE files found" >&2; exit 1; }
echo "$total binaries, $jobs at a time"

# Waits until a visible window of process $1 whose name matches $2 exists;
# prints its id.
wait_window() {
    local pid=$1 pattern=$2 deadline=$((SECONDS + $3)) w
    while [ $SECONDS -lt $deadline ]; do
        kill -0 "$pid" 2>/dev/null || return 1
        for w in $(xdotool search --onlyvisible --pid "$pid" '' 2>/dev/null); do
            if xdotool getwindowname "$w" 2>/dev/null | grep -Eiq -- "$pattern"; then
                echo "$w"
                return 0
            fi
        done
        sleep 1
    done
    return 1
}

# Presses Return in window $1 until it closes (the file dialog's completion
# popup can take the first one).
submit() {
    local w=$1 i
    for i in 1 2 3; do
        xdotool windowfocus --sync "$w" key Return 2>/dev/null
        sleep 1
        xdotool search --onlyvisible --name '' 2>/dev/null | grep -qx "$w" || return 0
    done
    return 1
}

# Exports one binary on screen $1.
export_one() {
    local display=$1 bin=$2 name pid w out start
    name=$(basename "$(dirname "$bin")")-$(basename "$bin")
    log() { echo "[$name] $*"; }
    out=$bin.ida.txt
    if [ -s "$out" ] && [ -z "${FORCE:-}" ]; then
        return 0
    fi
    rm -f "$out" "$bin".i64 "$bin".id0 "$bin".id1 "$bin".id2 "$bin".nam "$bin".til
    start=$SECONDS
    DISPLAY=$display QT_QPA_PLATFORM=xcb "$ida" "$bin" >/dev/null 2>&1 &
    pid=$!
    export DISPLAY=$display
    log "started IDA on $display"
    # The "Load a new file" dialog: accept the defaults.
    if w=$(wait_window "$pid" '^load' 120); then
        log "load dialog"
        submit "$w" || log "load dialog did not close"
    fi
    # The main window: type the exporter into the IDC command line at the
    # bottom (36 pixels above the window's bottom edge) and run it. File >
    # Script file opens a dialog that Xvfb draws black, so that is no use.
    if w=$(wait_window "$pid" '^IDA - ' 120); then
        log "main window"
        sleep 2
        eval "$(xdotool getwindowgeometry --shell "$w")"
        xdotool mousemove --window "$w" $((WIDTH / 2)) $((HEIGHT - 36)) click 1
        sleep 1
        xdotool type --delay 5 "$command"
        xdotool key Return
        log "exporting"
    else
        log "no main window"
    fi
    while kill -0 "$pid" 2>/dev/null && [ $((SECONDS - start)) -lt "$timeout" ]; do
        sleep 2
    done
    if kill -0 "$pid" 2>/dev/null || [ ! -s "$out" ]; then
        command -v xwd >/dev/null && xwd -root -silent -display "$display" > "ida-export-$name.xwd"
        kill -9 "$pid" 2>/dev/null
        echo "$bin" >> "$failed"
        echo "failed: $bin ($((SECONDS - start)) s)"
    else
        echo "done: $bin ($(($(wc -l < "$out") - 1)) functions, $((SECONDS - start)) s)"
    fi
    rm -f "$bin".i64 "$bin".id0 "$bin".id1 "$bin".id2 "$bin".nam "$bin".til
}

# One worker per screen, each taking every JOBS-th binary.
worker() {
    local n=$1 i=0 bin display
    # Xvfb picks a free display number and prints it.
    Xvfb -displayfd 1 -screen 0 1600x1000x24 -nolisten tcp > "$work/display$n" 2>/dev/null &
    local xvfb=$!
    while [ ! -s "$work/display$n" ]; do
        kill -0 "$xvfb" 2>/dev/null || { echo "error: Xvfb did not start" >&2; return 1; }
        sleep 0.2
    done
    display=:$(head -n1 "$work/display$n")
    while IFS= read -r bin; do
        if [ $((i % jobs)) -eq "$n" ]; then
            export_one "$display" "$bin"
        fi
        i=$((i + 1))
    done < "$list"
    kill "$xvfb" 2>/dev/null
}

: > "$failed"
for n in $(seq 0 $((jobs - 1))); do
    worker "$n" &
done
wait
echo "finished; $(wc -l < "$failed") failed (see $failed)"
