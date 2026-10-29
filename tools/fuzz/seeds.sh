#!/usr/bin/env bash
# Builds seed corpora for the fuzz targets in fuzz/corpus/<target>/ (not committed:
# see .gitignore). Seeds are real files up to 1 MB:
#   - ELF files from the system (MAX_SYSTEM of them),
#   - the analysis test programs (crates/fg-analysis/tests/data) built with gcc and
#     clang: PIE, shared library, fixed address, each with and without
#     --emit-relocs; 32-bit PIC libraries; AArch64 with clang and rust-lld,
#   - Windows PE files if a MinGW toolchain is installed.
# Missing compilers are skipped with a note.
#
#   tools/fuzz/seeds.sh                   # every target
#   MAX_SYSTEM=500 tools/fuzz/seeds.sh    # more system files
set -u

root=$(cd "$(dirname "$0")/../.." && pwd)
data="$root/crates/fg-analysis/tests/data"
corpus="$root/fuzz/corpus"
max_size=$((1024 * 1024))
max_system=${MAX_SYSTEM:-200}
build=$(mktemp -d)
trap 'rm -rf "$build"' EXIT
seeds="$build/seeds"
mkdir -p "$seeds"

note() { echo "note: $*" >&2; }
run() { "$@" 2>/dev/null; }

# System ELF files, smallest variety first: executables and libraries.
count=0
while IFS= read -r -d '' f; do
    [ "$count" -ge "$max_system" ] && break
    size=$(stat -c %s "$f" 2>/dev/null) || continue
    [ "$size" -gt "$max_size" ] && continue
    head -c 4 "$f" 2>/dev/null | grep -q $'^\x7fELF' || continue
    cp "$f" "$seeds/sys-$(basename "$f")-$count" && count=$((count + 1))
done < <(find /usr/bin /usr/lib /usr/lib64 /usr/libexec -maxdepth 3 -type f -print0 2>/dev/null)
echo "system ELF files: $count"

# The analysis test program, every way the tests build it.
for cc in gcc clang; do
    command -v "$cc" >/dev/null || { note "$cc not found; skipped"; continue; }
    for kind in pie so exe; do
        case $kind in
            pie) link="-pie -fPIE" ;;
            so) link="-shared -fPIC" ;;
            exe) link="-no-pie -fno-pie" ;;
        esac
        for opt in -O0 -O2 -Os; do
            # shellcheck disable=SC2086
            run "$cc" $opt -fcf-protection=full $link -o "$seeds/$cc-$kind$opt" "$data/program.c"
            # shellcheck disable=SC2086
            run "$cc" $opt -fcf-protection=full -Wl,--emit-relocs $link \
                -o "$seeds/$cc-$kind$opt-relocs" "$data/program.c"
        done
        # shellcheck disable=SC2086
        run "$cc" -O2 -s $link -o "$seeds/$cc-$kind-stripped" "$data/program.c"
    done
    run "$cc" -m32 -O2 -fPIC -ffreestanding -nostdlib -shared \
        -o "$seeds/$cc-pic32.so" "$data/pic32.c" || note "$cc cannot build 32-bit code"
done

# AArch64: clang and the linker that ships with Rust.
lld=$(find "$(rustc --print sysroot 2>/dev/null)/lib/rustlib" -name rust-lld -path '*/bin/*' 2>/dev/null | head -n 1)
if command -v clang >/dev/null && [ -n "$lld" ]; then
    a64() {
        clang --target=aarch64-linux-gnu -O2 -ffreestanding -fno-builtin -nostdlib \
            -mbranch-protection=standard -c "$@" 2>/dev/null
    }
    if a64 -fPIC -o "$build/dep.o" "$data/aarch64-dep.c" &&
        "$lld" -flavor gnu -shared -soname libdep.so -o "$seeds/a64-libdep.so" "$build/dep.o"; then
        for kind in pie exe; do
            if [ $kind = pie ]; then cflag=-fPIE lflag=-pie; else cflag=-fno-pic lflag=-no-pie; fi
            a64 $cflag -o "$build/prog-$kind.o" "$data/aarch64.c" &&
                "$lld" -flavor gnu -e _start -z now --emit-relocs $lflag \
                    -o "$seeds/a64-$kind" "$build/prog-$kind.o" "$seeds/a64-libdep.so"
        done
    else
        note "clang cannot build for AArch64; skipped"
    fi
else
    note "clang or rust-lld not found; AArch64 skipped"
fi

# Windows PE, if a MinGW toolchain is installed.
pe=0
for cc in x86_64-w64-mingw32-gcc x86_64-w64-mingw32-clang aarch64-w64-mingw32-clang i686-w64-mingw32-gcc; do
    command -v "$cc" >/dev/null || continue
    run "$cc" -O2 -o "$seeds/$cc.exe" "$data/program.c" && pe=$((pe + 1))
    run "$cc" -O2 -shared -o "$seeds/$cc.dll" "$data/program.c" && pe=$((pe + 1))
done
[ "$pe" -eq 0 ] && note "no MinGW toolchain; no PE seeds"

for target in load disasm functions xrefs; do
    mkdir -p "$corpus/$target"
    cp "$seeds"/* "$corpus/$target/"
done
echo "$(ls "$seeds" | wc -l) seeds in $corpus/{load,disasm,functions,xrefs}"
