#!/usr/bin/env bash
# Builds the function-recovery corpus for M1 step 8: open-source programs
# compiled with many compilers and flags, every binary kept three ways:
#
#   OUT/bin/<config>/<program>-<binary>         stripped: what the tools analyse
#   OUT/debug/<config>/<program>-<binary>       the same build with its symbols
#   OUT/truth/<config>/<program>-<binary>.txt   its true functions, "0xVA name"
#
# The true list comes from the unstripped build's symbol table, read by GNU
# binutils, not by Fulgurite's own loader: every defined function symbol in an
# executable section (ELF: FUNC or IFUNC; PE: COFF type 0x20 in a code
# section), aliases at one address counted once. Symbols named "*.cold" are
# left out: they are the cold parts of another function, not functions.
# Stripping moves nothing; each stripped copy's segments are checked against
# the unstripped one's.
#
#   tools/measure/corpus.sh [OUT]          OUT defaults to ./corpus
#
# Environment:
#   JOBS=$(nproc)     builds at once (each runs make -j2)
#   CONFIGS=regex     only the configs whose name matches (default: all)
#   PROGRAMS=regex    only the programs whose name matches (default: all)
#
# Sources are downloaded once into OUT/src and checked against the SHA-256
# sums below. A build that fails is listed in OUT/failed.txt with its log in
# OUT/logs; finished builds are skipped, so running again retries only those.
# tools/measure/setup-ubuntu.sh installs every compiler used here.
set -u

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)

# name | C compiler | C++ compiler | CFLAGS | LDFLAGS | --host | ar | ranlib
# "rust" and "go" in the compiler column build the Rust and Go programs.
# AArch64 is built by clang only: Ubuntu's gcc cross compilers cannot be
# installed next to gcc-multilib, which the -m32 builds need.
CONFIGS_TABLE='
gcc-O0|gcc|g++|-O0||||
gcc-O1|gcc|g++|-O1||||
gcc-O2|gcc|g++|-O2||||
gcc-O3|gcc|g++|-O3||||
gcc-Os|gcc|g++|-Os||||
clang-O0|clang|clang++|-O0||||
clang-O1|clang|clang++|-O1||||
clang-O2|clang|clang++|-O2||||
clang-O3|clang|clang++|-O3||||
clang-Os|clang|clang++|-Os||||
clang-Oz|clang|clang++|-Oz||||
gcc-O2-static|gcc|g++|-O2|-static|||
clang-O2-static|clang|clang++|-O2|-static|||
gcc-O2-lto|gcc|g++|-O2 -flto=auto|-flto=auto||gcc-ar|gcc-ranlib
clang-O2-lto|clang|clang++|-O2 -flto|-flto -fuse-ld=lld||llvm-ar|llvm-ranlib
gcc-O2-nounwind|gcc|g++|-O2 -fno-asynchronous-unwind-tables -fno-unwind-tables||||
clang-O2-nounwind|clang|clang++|-O2 -fno-asynchronous-unwind-tables -fno-unwind-tables||||
gcc-O2-nopie|gcc|g++|-O2 -fno-pie|-no-pie|||
clang-O2-nopie|clang|clang++|-O2 -fno-pie|-no-pie|||
gcc-O2-sections|gcc|g++|-O2 -ffunction-sections -fdata-sections|-Wl,--gc-sections|||
gcc-O2-nocet|gcc|g++|-O2 -fcf-protection=none||||
clang-O2-cet|clang|clang++|-O2 -fcf-protection=full||||
gcc-O2-m32|gcc -m32|g++ -m32|-O2||||
clang-O2-m32|clang -m32|clang++ -m32|-O2||||
gcc-O0-m32|gcc -m32|g++ -m32|-O0||||
aarch64-clang-O0|clang --target=aarch64-linux-gnu|clang++ --target=aarch64-linux-gnu|-O0|-fuse-ld=lld|aarch64-linux-gnu|llvm-ar|llvm-ranlib
aarch64-clang-O2|clang --target=aarch64-linux-gnu|clang++ --target=aarch64-linux-gnu|-O2|-fuse-ld=lld|aarch64-linux-gnu|llvm-ar|llvm-ranlib
mingw64-O0|x86_64-w64-mingw32-gcc|x86_64-w64-mingw32-g++|-O0||x86_64-w64-mingw32|x86_64-w64-mingw32-ar|x86_64-w64-mingw32-ranlib
mingw64-O2|x86_64-w64-mingw32-gcc|x86_64-w64-mingw32-g++|-O2||x86_64-w64-mingw32|x86_64-w64-mingw32-ar|x86_64-w64-mingw32-ranlib
mingw32-O2|i686-w64-mingw32-gcc|i686-w64-mingw32-g++|-O2||i686-w64-mingw32|i686-w64-mingw32-ar|i686-w64-mingw32-ranlib
rust-O0|rust||0||||
rust-O3|rust||3||||
rust-O3-lto|rust||3|fat|||
go-amd64|go||amd64||||
go-386|go||386||||
go-arm64|go||arm64||||
'

# name | file | SHA-256 | URL
SOURCES='
coreutils|coreutils-9.5.tar.xz|cd328edeac92f6a665de9f323c93b712af1858bc2e0d88f3f7100469470a1b8a|https://ftp.gnu.org/gnu/coreutils/coreutils-9.5.tar.xz
grep|grep-3.11.tar.xz|1db2aedde89d0dea42b16d9528f894c8d15dae4e190b59aecc78f5a951276eab|https://ftp.gnu.org/gnu/grep/grep-3.11.tar.xz
sed|sed-4.9.tar.xz|6e226b732e1cd739464ad6862bd1a1aba42d7982922da7a53519631d24975181|https://ftp.gnu.org/gnu/sed/sed-4.9.tar.xz
diffutils|diffutils-3.10.tar.xz|90e5e93cc724e4ebe12ede80df1634063c7a855692685919bfe60b556c9bd09e|https://ftp.gnu.org/gnu/diffutils/diffutils-3.10.tar.xz
findutils|findutils-4.10.0.tar.xz|1387e0b67ff247d2abde998f90dfbf70c1491391a59ddfecb8ae698789f0a4f5|https://ftp.gnu.org/gnu/findutils/findutils-4.10.0.tar.xz
gawk|gawk-5.3.1.tar.xz|694db764812a6236423d4ff40ceb7b6c4c441301b72ad502bb5c27e00cd56f78|https://ftp.gnu.org/gnu/gawk/gawk-5.3.1.tar.xz
groff|groff-1.23.0.tar.gz|6b9757f592b7518b4902eb6af7e54570bdccba37a871fddb2d30ae3863511c13|https://ftp.gnu.org/gnu/groff/groff-1.23.0.tar.gz
jq|jq-1.7.1.tar.gz|478c9ca129fd2e3443fe27314b455e211e0d8c60bc8ff7df703873deeee580c2|https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-1.7.1.tar.gz
sqlite|sqlite-amalgamation-3460100.zip|77823cb110929c2bcb0f5d48e4833b5c59a8a6e40cdea3936b99e199dbbe5784|https://www.sqlite.org/2024/sqlite-amalgamation-3460100.zip
lua|lua-5.4.7.tar.gz|9fbf5e28ef86c69858f6d3d34eccc32e911c1a28b4120ff3e84aaa70cfbf1e30|https://www.lua.org/ftp/lua-5.4.7.tar.gz
zlib|zlib-1.3.1.tar.gz|9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23|https://zlib.net/fossils/zlib-1.3.1.tar.gz
bzip2|bzip2-1.0.8.tar.gz|ab5a03176ee106d3f0fa90e381da478ddae405918153cca248e682cd0c4a2269|https://sourceware.org/pub/bzip2/bzip2-1.0.8.tar.gz
'

# The C and C++ programs, and the ones that build for Windows (the GNU tools
# need a POSIX system) or cross (groff runs what it builds).
C_PROGRAMS='coreutils grep sed diffutils findutils gawk groff jq sqlite lua lua-cxx zlib bzip2'
WINDOWS_PROGRAMS='sqlite lua lua-cxx zlib bzip2'
NO_CROSS='groff'

field() { printf '%s\n' "$1" | cut -d'|' -f"$2"; }
config_line() { printf '%s\n' "$CONFIGS_TABLE" | grep -m1 "^$1|"; }
source_line() { printf '%s\n' "$SOURCES" | grep -m1 "^$1|"; }

# Prints the programs config $1 builds.
programs_of() {
    local line cc host
    line=$(config_line "$1")
    cc=$(field "$line" 2)
    host=$(field "$line" 6)
    case $cc in
        rust) echo fulg ;;
        go) echo gocmd ;;
        *)
            case $host in
                *mingw32) echo $WINDOWS_PROGRAMS ;;
                '') echo $C_PROGRAMS ;;
                *) for p in $C_PROGRAMS; do case " $NO_CROSS " in *" $p "*) ;; *) echo "$p" ;; esac; done ;;
            esac
            ;;
    esac
}

# The source archive a program is built from.
source_of() {
    case $1 in lua-cxx) echo lua ;; *) echo "$1" ;; esac
}

# Unpacks program $1's source into the current directory.
unpack() {
    local line file
    line=$(source_line "$(source_of "$1")")
    file=$OUT/src/$(field "$line" 2)
    case $file in
        *.zip) unzip -q "$file" && mv sqlite-amalgamation-*/* . ;;
        *) tar xf "$file" --strip-components=1 ;;
    esac
}

# --- Builders. Each runs in an empty directory with CC, CXX, CFLAGS, LDFLAGS,
# HOST, AR and RANLIB set, and prints the paths of the binaries it made.

autotools() {
    local dirs=$1
    shift
    local host_arg=()
    [ -n "$HOST" ] && host_arg=(--host="$HOST")
    unpack "$PROGRAM"
    FORCE_UNSAFE_CONFIGURE=1 ./configure "${host_arg[@]}" CC="$CC" CXX="$CXX" \
        CFLAGS="$CFLAGS" CXXFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS" AR="$AR" RANLIB="$RANLIB" \
        --disable-nls "$@" >&2 || return 1
    make -j"${MAKEJOBS:-2}" >&2 || return 1
    for d in $dirs; do
        find "$d" -maxdepth 1 -type f \( -perm -u+x -o -name '*.so' \) | while IFS= read -r f; do
            if is_binary "$f"; then echo "$f"; fi
        done
    done
    return 0
}

build_coreutils() {
    autotools src --without-selinux --without-openssl --without-libgmp \
        --disable-acl --disable-xattr --disable-libcap
}
build_grep() { autotools src --disable-perl-regexp; }
build_sed() { autotools sed --without-selinux --disable-acl; }
build_diffutils() { autotools src; }
build_findutils() { autotools 'find xargs locate' --without-selinux; }
build_gawk() { autotools . --without-readline --without-mpfr --disable-extensions --disable-pma; }
build_jq() {
    autotools . --with-oniguruma=no --disable-docs --disable-shared --disable-valgrind \
        --disable-maintainer-mode
}
build_groff() { autotools . --without-x --without-uchardet --without-doc; }

# The small programs are compiled file by file, the same way on every system.
exe() { case $HOST in *mingw32) echo "$1.exe" ;; *) echo "$1" ;; esac; }

build_sqlite() {
    unpack sqlite
    local libs=(-lm)
    case $HOST in *mingw32) ;; *) libs+=(-lpthread -ldl) ;; esac
    $CC $CFLAGS -DSQLITE_OMIT_LOAD_EXTENSION -o "$(exe sqlite3)" shell.c sqlite3.c $LDFLAGS "${libs[@]}" >&2 || return 1
    exe sqlite3
}

build_lua_with() {
    local cc=$1 lang=()
    unpack lua
    cd src || return 1
    [ "$cc" = "$CXX" ] && lang=(-x c++)
    local defs=(-DLUA_COMPAT_5_3)
    case $HOST in *mingw32) ;; *) defs+=(-DLUA_USE_LINUX) ;; esac
    local core
    core=$(ls ./*.c | grep -v -e '/lua\.c$' -e '/luac\.c$')
    # shellcheck disable=SC2086
    $cc $CFLAGS "${defs[@]}" "${lang[@]}" -o "$(exe lua)" lua.c $core $LDFLAGS -lm >&2 || return 1
    # shellcheck disable=SC2086
    $cc $CFLAGS "${defs[@]}" "${lang[@]}" -o "$(exe luac)" luac.c $core $LDFLAGS -lm >&2 || return 1
    echo "src/$(exe lua)"
    echo "src/$(exe luac)"
}
build_lua() { build_lua_with "$CC"; }
# Lua compiled as C++: errors are C++ exceptions instead of longjmp.
build_lua-cxx() { build_lua_with "$CXX"; }

build_zlib() {
    unpack zlib
    local defs=()
    case $HOST in *mingw32) ;; *) defs=(-DZ_HAVE_UNISTD_H) ;; esac
    local lib='adler32.c crc32.c deflate.c infback.c inffast.c inflate.c inftrees.c trees.c zutil.c compress.c uncompr.c gzclose.c gzlib.c gzread.c gzwrite.c'
    # shellcheck disable=SC2086
    $CC $CFLAGS "${defs[@]}" -I. -o "$(exe minigzip)" test/minigzip.c $lib $LDFLAGS >&2 || return 1
    # shellcheck disable=SC2086
    $CC $CFLAGS "${defs[@]}" -I. -o "$(exe example)" test/example.c $lib $LDFLAGS >&2 || return 1
    exe minigzip
    exe example
}

build_bzip2() {
    unpack bzip2
    local lib='blocksort.c huffman.c crctable.c randtable.c compress.c decompress.c bzlib.c'
    # shellcheck disable=SC2086
    $CC $CFLAGS -D_FILE_OFFSET_BITS=64 -o "$(exe bzip2)" bzip2.c $lib $LDFLAGS >&2 || return 1
    $CC $CFLAGS -D_FILE_OFFSET_BITS=64 -o "$(exe bzip2recover)" bzip2recover.c $LDFLAGS >&2 || return 1
    exe bzip2
    exe bzip2recover
}

# Fulgurite's own command-line tool: CFLAGS is the opt-level, LDFLAGS the LTO
# setting.
build_fulg() {
    CARGO_PROFILE_RELEASE_OPT_LEVEL=$CFLAGS CARGO_PROFILE_RELEASE_LTO=${LDFLAGS:-false} \
        CARGO_PROFILE_RELEASE_DEBUG=false CARGO_PROFILE_RELEASE_STRIP=none \
        cargo build --release --locked -p fg-cli --manifest-path "$repo/Cargo.toml" \
        --target-dir "$PWD/target" >&2 || return 1
    echo target/release/fulg
}

# Tools from the Go distribution itself; CFLAGS is GOARCH.
build_gocmd() {
    local c
    for c in gofmt addr2line nm objdump; do
        CGO_ENABLED=0 GOARCH=$CFLAGS go build -trimpath -o "$c" "cmd/$c" >&2 || return 1
        echo "$c"
    done
}

# --- Ground truth.

# True if $1 is a linked ELF or PE file (not an object file or a script).
is_binary() {
    local magic
    magic=$(head -c 4 "$1" 2>/dev/null | od -An -tx1 | tr -d ' \n')
    case $magic in
        7f454c46) readelf -hW "$1" 2>/dev/null | grep -Eq 'Type: +(EXEC|DYN)' ;;
        4d5a*) true ;;
        *) false ;;
    esac
}

is_pe() { [ "$(head -c 2 "$1" | od -An -tx1 | tr -d ' \n')" = 4d5a ]; }

# Prints "0xVA name" for every true function of the unstripped binary $1.
truth() {
    if is_pe "$1"; then
        # The COFF symbols of type 0x20 are the functions; nm gives their
        # addresses with the image base, as PE tools show them.
        { x86_64-w64-mingw32-objdump -t "$1"; echo '@@nm'; x86_64-w64-mingw32-nm --defined-only "$1"; } | awk '
            /^@@nm/ { nm = 1; next }
            !nm { if ($0 ~ /\(ty +20\)/) function_name[$NF] = 1; next }
            # nm types T and t: defined in a code section.
            $2 ~ /^[Tt]$/ && ($3 in function_name) && $3 !~ /\.cold($|\.)/ {
                v = $1; sub(/^0+/, "", v); if (v == "") v = "0"
                if (!(v in seen)) { seen[v] = 1; print "0x" v, $3 }
            }'
    else
        { readelf -SW "$1"; echo '@@symbols'; readelf -sW "$1"; } | awk '
            /^@@symbols/ { symbols = 1; next }
            !symbols {
                # [Nr] Name Type Address Off Size ES Flg Lk Inf Al
                if (match($0, /^ *\[ *[0-9]+\]/)) {
                    i = substr($0, RSTART, RLENGTH); gsub(/[^0-9]/, "", i)
                    n = split(substr($0, RSTART + RLENGTH), f, " ")
                    if (n >= 10 && f[n - 3] ~ /X/) exec[i] = 1
                }
                next
            }
            # Num: Value Size Type Bind Vis Ndx Name
            ($4 == "FUNC" || $4 == "IFUNC") && ($7 in exec) {
                name = $8; sub(/@.*/, "", name)
                if (name ~ /\.cold($|\.)/) next
                # Go marks the end of its code with a function symbol.
                if (name == "runtime.etext") next
                v = $2; sub(/^0+/, "", v); if (v == "") v = "0"
                if (!(v in seen)) { seen[v] = 1; print "0x" v, name }
            }'
    fi | sort -u -k1,1
}

# The loaded layout of $1, which stripping must not change.
layout() {
    if is_pe "$1"; then
        # Debug sections are not loaded; strip removes them.
        x86_64-w64-mingw32-objdump -h "$1" | awk '/^ +[0-9]+ / && $2 !~ /^\.debug/ { print $2, $3, $4 }'
    else
        readelf -lW "$1" | awk '$1 == "LOAD" { print $3, $5, $6, $7 }'
    fi
}

# --- One build: config $1, program $2.

build_one() {
    local config=$1 PROGRAM=$2 line work log out made=0 f name
    line=$(config_line "$config")
    CC=$(field "$line" 2)
    CXX=$(field "$line" 3)
    CFLAGS=$(field "$line" 4)
    LDFLAGS=$(field "$line" 5)
    HOST=$(field "$line" 6)
    AR=$(field "$line" 7)
    RANLIB=$(field "$line" 8)
    AR=${AR:-ar}
    RANLIB=${RANLIB:-ranlib}
    export CC CXX CFLAGS LDFLAGS HOST AR RANLIB PROGRAM
    work=$OUT/build/$config/$PROGRAM
    log=$OUT/logs/$config-$PROGRAM.log
    rm -rf "$work"
    mkdir -p "$work" "$OUT/logs" "$OUT/bin/$config" "$OUT/debug/$config" "$OUT/truth/$config"
    if ! out=$(cd "$work" && "build_$PROGRAM" 2>"$log"); then
        echo "$config $PROGRAM" >> "$OUT/failed.txt"
        echo "failed: $config $PROGRAM (see $log)"
        return
    fi
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        f=$work/$f
        name=$PROGRAM-$(basename "$f")
        name=${name//\[/lbracket} # coreutils' "[" command
        cp "$f" "$OUT/debug/$config/$name"
        llvm-strip --strip-all -o "$OUT/bin/$config/$name" "$f"
        truth "$f" > "$OUT/truth/$config/$name.txt"
        if [ ! -s "$OUT/truth/$config/$name.txt" ]; then
            echo "warning: $config/$name has no function symbols; left out" >> "$log"
            rm -f "$OUT/bin/$config/$name" "$OUT/debug/$config/$name" "$OUT/truth/$config/$name.txt"
            continue
        fi
        if [ "$(layout "$f")" != "$(layout "$OUT/bin/$config/$name")" ]; then
            echo "error: stripping $config/$name moved its segments" >> "$log"
            rm -f "$OUT/bin/$config/$name" "$OUT/debug/$config/$name" "$OUT/truth/$config/$name.txt"
            continue
        fi
        made=$((made + 1))
    done <<< "$out"
    if [ "$made" -eq 0 ]; then
        echo "$config $PROGRAM" >> "$OUT/failed.txt"
        echo "failed: $config $PROGRAM made no binaries (see $log)"
        return
    fi
    mkdir -p "$OUT/done"
    touch "$OUT/done/$config-$PROGRAM"
    rm -rf "$work"
    echo "built: $config $PROGRAM ($made binaries)"
}

if [ "${1:-}" = --one ]; then
    OUT=$2
    build_one "$3" "$4"
    exit 0
fi

OUT=$(mkdir -p "${1:-corpus}" && cd "${1:-corpus}" && pwd)
export OUT
jobs=${JOBS:-$(nproc)}

# Downloads, checked.
mkdir -p "$OUT/src"
printf '%s\n' "$SOURCES" | while IFS='|' read -r name file sum url; do
    [ -n "$name" ] || continue
    [[ $name =~ ${PROGRAMS:-.} || ( $name == lua && lua-cxx =~ ${PROGRAMS:-.} ) ]] || continue
    if ! echo "$sum  $OUT/src/$file" | sha256sum -c --status 2>/dev/null; then
        echo "downloading $file"
        curl -fsSL --retry 5 --retry-all-errors -o "$OUT/src/$file" "$url" || { echo "error: cannot download $url" >&2; exit 1; }
        echo "$sum  $OUT/src/$file" | sha256sum -c --status || { echo "error: $file has the wrong SHA-256" >&2; exit 1; }
    fi
done || exit 1

# Every build not done yet.
: > "$OUT/failed.txt"
list=$OUT/todo.txt
printf '%s\n' "$CONFIGS_TABLE" | cut -d'|' -f1 | while IFS= read -r config; do
    [ -n "$config" ] && [[ $config =~ ${CONFIGS:-.} ]] || continue
    cc=$(field "$(config_line "$config")" 2)
    case $cc in rust) cc=cargo ;; esac
    if ! command -v "${cc%% *}" >/dev/null; then
        echo "skipped $config: ${cc%% *} is not installed" >&2
        continue
    fi
    for p in $(programs_of "$config"); do
        [[ $p =~ ${PROGRAMS:-.} ]] || continue
        [ -e "$OUT/done/$config-$p" ] || echo "$config $p"
    done
done > "$list"
echo "$(wc -l < "$list") builds, $jobs at a time"

# The compilers used, for the record.
{
    echo "# corpus built $(date -u +%Y-%m-%dT%H:%MZ) on $(uname -srm)"
    for c in gcc clang x86_64-w64-mingw32-gcc i686-w64-mingw32-gcc rustc go readelf; do
        command -v "$c" >/dev/null && echo "$c: $("$c" --version 2>/dev/null | head -n1 || "$c" version)"
    done
    command -v go >/dev/null && echo "go: $(go version)"
    printf '%s\n' "$SOURCES" | awk -F'|' 'NF { print "source:", $2, $3 }'
} > "$OUT/manifest.txt"

xargs -P "$jobs" -L1 "$0" --one "$OUT" < "$list"

echo
echo "binaries: $(find "$OUT/truth" -name '*.txt' | wc -l), in $(find "$OUT/truth" -mindepth 1 -maxdepth 1 -type d | wc -l) configs"
if [ -s "$OUT/failed.txt" ]; then
    echo "failed builds ($(wc -l < "$OUT/failed.txt")):"
    sed 's/^/  /' "$OUT/failed.txt"
fi
