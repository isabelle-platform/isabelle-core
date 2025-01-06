#!/bin/bash
# Main run script for Isabelle Core
# Author: Maxim Menshikov

# Change into base directory of the project
TOP_DIR="$(cd "$(dirname "$(which "$0")")" ; pwd -P)"
cd "$TOP_DIR"

# Find the core binary
binary="${BINARY:-./target/debug/isabelle-core}"
if [ ! -f "${binary}" ] ; then
    binary="./isabelle-core"
fi

if [ ! -f "${binary}" ] ; then
    echo "Binary is not found: ${binary}" >&2
    exit 1
fi

# Fix up Python path on MacOS
if [ "$(uname)" == "Darwin" ] ; then
    py_path="/opt/homebrew/bin/python3"
else
    py_path="$(which python3)"
fi

if [ ! -f "${py_path}" ] ; then
    echo "Python binary is not found: ${py_path}" >&2
    exit 1
fi

# Parse arguments
first_run="${FIRST_RUN:+--first-run}"
port="8090"
pub_url="http://localhost:8081"
pub_fqdn="localhost"
data_path="$(pwd)/data-equestrian"
py_path=""
gc_path="$6"
database="isabelle"
gh_login=""
gh_password=""
plugin_dir=""
cookie_http_insecure=""

while test -n "$1" ; do
    case "$1" in
        --port)
            port="$2"
            shift 1
            ;;
        --pub-url)
            pub_url="$2"
            shift 1
            ;;
        --pub-fqdn)
            pub_fqdn="$2"
            shift 1
            ;;
        --data-path)
            data_path="$2"
            shift 1
            ;;
        --py-path)
            py_path="$2"
            shift 1
            ;;
        --gc-path)
            gc_path="$2"
            shift 1
            ;;
        --first-run)
            first_run="--first-run"
            ;;
        --database)
            database="$2"
            shift 1
            ;;
        --gh-login)
            gh_login="$2"
            shift 1
            ;;
        --gh-password)
            gh_password="$2"
            shift 1
            ;;
        --plugin-dir)
            plugin_dir="$2"
            shift 1
            ;;
        --cookie-http-insecure)
            cookie_http_insecure="true"
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
    shift 1
done

# Download and install Google Calendar integration
if [ "$gc_path" == "" ] ; then
    if [ ! -d isabelle-gc ] ; then
        creds=""
        if [ "$gh_login" != "" ] && [ "$gh_password" != "" ] ; then
            creds="${gh_login}:${gh_password}@"
        fi
        git clone https://${creds}github.com/isabelle-platform/isabelle-gc.git
        pushd isabelle-gc
        ./install.sh
        popd
    fi
    gc_path="$(pwd)/isabelle-gc"
fi

# Sign with temporary entitlements
if [ "$(uname)" == "Darwin" ] ; then
    /usr/libexec/PlistBuddy -c "Add :com.apple.security.get-task-allow bool true" tmp.entitlements
    for file in ${binary} $(ls libisabelle_plugin*) ; do
        codesign -s - -f --entitlements tmp.entitlements "$file"
    done
fi

# Run the binary
RUST_LOG=info RUST_BACKTRACE=1 "${binary}" \
    --port "${port}" \
    --pub-url "${pub_url}" \
    --pub-fqdn "${pub_fqdn}" \
    --data-path "${data_path}" \
    --gc-path "${gc_path}" \
    --database "${database}" \
    --py-path "${py_path}" \
    ${cookie_http_insecure:+--cookie-http-insecure} \
    ${plugin_dir+--plugin-dir} ${plugin_dir:+"${plugin_dir}"} \
    ${first_run}
