#!/usr/bin/env bash
# one-shot: stage everything, commit, push
set -e

MSG="${1:-update}"

git add -A
git commit -m "$MSG" || echo "nothing to commit"
git push
