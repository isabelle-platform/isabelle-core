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

lib_dirs="$(grep -hs '^cargo:lib_dir=' "$profile_dir"/build/*/output \
    | sed 's/^cargo:lib_dir=//' | sort -u)"
[ -n "$lib_dirs" ] || exit 0

case "$(uname -s)" in
    Darwin)
        for d in $lib_dirs ; do
            if otool -l "$binary" | grep -q " path $d " ; then
                continue
            fi
            install_name_tool -add_rpath "$d" "$binary" \
                && echo "fix_rpath: added rpath $d"
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
