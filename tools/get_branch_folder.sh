#!/bin/bash

branch="$1"

echo "$branch" | sed 's/\//_/g'
