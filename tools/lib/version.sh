#!/bin/bash

function get_version()
{
	local top_dir="$1"
	local verkind="$2"

	# Single source of truth: the `[package] version` in Cargo.toml.
	local full
	full=$(grep -m1 '^version' "${top_dir}/Cargo.toml" \
		| sed -E 's/.*"([^"]+)".*/\1/')

	local major rest minor patchlevel
	major="${full%%.*}"
	rest="${full#*.}"
	minor="${rest%%.*}"
	patchlevel="${rest#*.}"

	case "${verkind}" in
		major)      echo "${major}" ;;
		minor)      echo "${minor}" ;;
		patchlevel) echo "${patchlevel}" ;;
		*)          echo "${full}" ;;
	esac
}

function get_mods()
{
    local top_dir="$1"
    cd "${top_dir}" || return 1
    git diff-index --quiet HEAD -- || echo "/mod"
    return 0
}

function get_commit_hash()
{
    local top_dir="$1"
    cd "${top_dir}" || return 1
    echo $(git rev-parse --short HEAD)
    return 0
}

function get_full_version()
{
	local top_dir="$1"

	echo $(get_version "${top_dir}")-$(get_commit_hash "${top_dir}")
}