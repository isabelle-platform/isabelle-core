#!/bin/bash
# Release generation script for Isabelle Core project
# Usage: ./tools/release.sh [--out archive]
# Script is supposed to be run from main folder, e.g. ./tools/release.sh
output=""

. $(cd "$(dirname "$(which "$0")")"/.. ; pwd -P)/tools/lib/core.sh


while test -n "$1" ; do
    case $1 in
        --out)
            output="$2"
            shift 1
            ;;
        *)
            fail "Unknown argument: $1"
            ;;
    esac
    shift 1
done

function get_hash()
{
    pushd ${TOP_DIR} > /dev/null
    git rev-parse --short HEAD
    popd > /dev/null
}

if [ "$output" == "" ] ; then
    echo "No output set"
    exit 1
fi

# Get build & target folder, normalize output path
build_folder="$(cd ${build_folder} && pwd)"
if [ -d "${TOP_DIR}/target/x86_64-unknown-linux-gnu/release" ] ; then
    target_folder="$TOP_DIR/target/x86_64-unknown-linux-gnu/release"
else
    target_folder="$TOP_DIR/target/release"
fi

output="$(lib_core_normalize_filepath ${output})"

# Get to target folder
cd "${target_folder}"

# Get the repository hash
echo $(get_hash) > hash

# Get the top script to run the binary
cp ${TOP_DIR}/run.sh ./

if [ "$(uname)" != "Darwin" ] ; then
    patchelf --set-rpath '$ORIGIN' isabelle-core
fi

# Save the binary, hash and script to out.tar.xz
tar cJvf out.tar.xz isabelle-core hash run.sh

# Copy out the archive to output path
cp out.tar.xz "${output}"
