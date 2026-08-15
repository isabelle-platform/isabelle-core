#!/bin/bash
# Stamp native-library rpaths into a freshly linked flavour binary.
#
# Build scripts of transitive dependencies (e.g. delta-api's, which links the
# native libasp) cannot inject linker rpaths into the final binary — cargo's
# `rustc-link-arg` does not propagate across crates — so their dylibs fail to
# load at runtime ("Library not loaded: @rpath/libasp.dylib"). By convention
# such build scripts publish the library dir as `cargo:lib_dir=` in their
# build output; collect those dirs here and add them as rpaths post-link.
#
# Usage: fix_rpath.sh <binary> <cargo-profile-dir>
#   <cargo-profile-dir> is the dir holding the binary and its build/ subdir,
#   e.g. generated/midair/target/debug
#
# macOS note: this invalidates the code signature; run.sh re-signs on start.

binary="$1"
profile_dir="$2"

if [ ! -f "$binary" ] ; then
    echo "fix_rpath: binary not found: $binary" >&2
    exit 1
fi

# Only the current build's dirs. `target/*/build/` accumulates one directory
# per build-script run and cargo never prunes them, so a project that has been
# built against two versions of a native library has both on disk. Taking all
# of them stamped the binary with an rpath to a library it was not linked
# against — and dyld, resolving @rpath in order, loaded that one. Here that
# meant an old libasp with a known crash being loaded into a binary built
# against the fixed one, which is a very confusing afternoon.
#
# Newest output per build-script package wins.
lib_dirs="$(
    ls -t "$profile_dir"/build/*/output 2>/dev/null | while read -r out ; do
        pkg="$(basename "$(dirname "$out")" | sed 's/-[0-9a-f]*$//')"
        grep -hs '^cargo:lib_dir=' "$out" \
            | sed "s|^cargo:lib_dir=|${pkg} |"
    done | awk '!seen[$1]++ { print $2 }'
)"
[ -n "$lib_dirs" ] || exit 0

case "$(uname -s)" in
    Darwin)
        # Drop rpaths this build did not ask for. A binary is usually relinked
        # fresh, but `install_name_tool` is also run on rebuilds, and a leftover
        # entry pointing at another version of the same library outranks the
        # right one if it comes first.
        for old_rpath in $(otool -l "$binary" \
                | awk '/cmd LC_RPATH/,/^$/' | awk '$1 == "path" { print $2 }') ; do
            case " $lib_dirs " in
                *" $old_rpath "*) continue ;;
            esac
            case "$old_rpath" in
                *asp-cache*|*"/build/"*)
                    install_name_tool -delete_rpath "$old_rpath" "$binary" 2>/dev/null \
                        && echo "fix_rpath: removed stale rpath $old_rpath"
                    ;;
            esac
        done
        for d in $lib_dirs ; do
            if otool -l "$binary" | grep -q " path $d " ; then
                continue
            fi
            # Loudly: a silent failure here is a binary that loads the wrong
            # library, or none at all, with nothing said at build time.
            if install_name_tool -add_rpath "$d" "$binary" ; then
                echo "fix_rpath: added rpath $d"
            else
                echo "fix_rpath: FAILED to add rpath $d — the binary may load a stale library" >&2
            fi
        done
        ;;
    Linux)
        if ! command -v patchelf > /dev/null 2>&1 ; then
            echo "fix_rpath: patchelf not found; native dylib deps may fail to load" >&2
            exit 0
        fi
        existing="$(patchelf --print-rpath "$binary" 2>/dev/null)"
        new="$existing"
        for d in $lib_dirs ; do
            case ":$new:" in
                *":$d:"*) ;;
                *) new="${new:+$new:}$d" ;;
            esac
        done
        if [ "$new" != "$existing" ] ; then
            patchelf --set-rpath "$new" "$binary" \
                && echo "fix_rpath: rpath = $new"
        fi
        ;;
esac

exit 0
