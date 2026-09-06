#!/usr/bin/env bash
set -euo pipefail
# Adapted from the source-pinned publisher; see dependencies/SOURCES.md.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG=''
MANIFEST=''
TAG=''
COMMIT=''
REMOTE=''
ASKPASS_FILE=''
TAG_OBJECT_FILE=''
TAG_MESSAGE_FILE=''
VERIFICATION_REF=''
CREATED_LOCAL_TAG=0
PUBLISH_COMPLETE=0
CANONICAL_CNB_REMOTE=''
REMOTE_KIND=''

die() {
  printf '%s\n' "$*" >&2
  exit 1
}

usage() {
  printf '%s\n' \
    'Usage: publish-candidate-tag.sh --config=<ci-config.json> --manifest=<path> --tag=<candidate-tag> --commit=<full-sha> --remote=<credential-free-remote>' >&2
}

cleanup() {
  if [[ -n "$ASKPASS_FILE" && -f "$ASKPASS_FILE" ]]; then
    rm -f -- "$ASKPASS_FILE"
  fi
  if [[ -n "$TAG_OBJECT_FILE" && -f "$TAG_OBJECT_FILE" ]]; then
    rm -f -- "$TAG_OBJECT_FILE"
  fi
  if [[ -n "$TAG_MESSAGE_FILE" && -f "$TAG_MESSAGE_FILE" ]]; then
    rm -f -- "$TAG_MESSAGE_FILE"
  fi
  if [[ -n "$VERIFICATION_REF" ]]; then
    git update-ref -d "$VERIFICATION_REF" >/dev/null 2>&1 || true
  fi
  if [[ "$CREATED_LOCAL_TAG" == 1 && "$PUBLISH_COMPLETE" == 0 && -n "$TAG" ]]; then
    git update-ref -d "refs/tags/$TAG" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

for argument in "$@"; do
  case "$argument" in
    --config=*) [[ -z "$CONFIG" ]] || die "duplicate config"; CONFIG="${argument#*=}" ;;
    --manifest=*) MANIFEST="${argument#*=}" ;;
    --tag=*) TAG="${argument#*=}" ;;
    --commit=*) COMMIT="${argument#*=}" ;;
    --remote=*) REMOTE="${argument#*=}" ;;
    *) usage; exit 1 ;;
  esac
done

[[ -f "$MANIFEST" ]] || die 'candidate manifest does not exist'
git check-ref-format "refs/tags/$TAG" >/dev/null 2>&1 || die 'candidate tag has an invalid format'
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || die 'candidate commit must be a full lowercase SHA'
[[ -n "$REMOTE" && "$REMOTE" != -* && "$REMOTE" != *$'\n'* && "$REMOTE" != *$'\r'* ]] || \
  die 'git remote is not allowed'

[[ -f "$CONFIG" ]] || die 'CI config does not exist'
CANONICAL_CNB_REMOTE="$(python3 - "$SCRIPT_DIR" "$CONFIG" <<'PYCONFIG'
import sys
sys.path.insert(0, sys.argv[1])
import candidate_manifest
config = candidate_manifest.validate_config(candidate_manifest.load_json(sys.argv[2]))
print("https://cnb.cool/" + config["cnb_repository"] + ".git")
PYCONFIG
)"
if [[ "$REMOTE" == "$CANONICAL_CNB_REMOTE" ]]; then
  REMOTE_KIND='cnb'
elif [[ "${CNB_CANDIDATE_TAG_ALLOW_LOCAL_BARE_REMOTE_FOR_TESTS:-}" == 1 && "$REMOTE" == /* ]]; then
  [[ "$(git --git-dir="$REMOTE" rev-parse --is-bare-repository 2>/dev/null || true)" == true ]] || \
    die 'local test remote must be a bare Git repository'
  REMOTE_KIND='local-test'
else
  die 'git remote is not allowed'
fi

python3 "$SCRIPT_DIR/candidate_manifest.py" validate \
  --config "$CONFIG" \
  --manifest "$MANIFEST" \
  --expected-tag "$TAG" \
  --expected-commit "$COMMIT"
git cat-file -e "$COMMIT^{commit}" 2>/dev/null || die 'candidate commit does not exist locally'

if [[ "$REMOTE_KIND" == cnb ]]; then
  [[ -n "${CNB_TOKEN:-}" ]] || die 'CNB_TOKEN is required for a CNB HTTPS remote'
  [[ "${CNB_TOKEN_USER_NAME:-cnb}" != *$'\n'* && "${CNB_TOKEN_USER_NAME:-cnb}" != *$'\r'* ]] || \
    die 'CNB token user name is invalid'
  umask 077
  ASKPASS_FILE="$(mktemp "${TMPDIR:-/tmp}/cnb-release-askpass.XXXXXX")"
  {
    printf '%s\n' '#!/usr/bin/env bash'
    printf '%s\n' 'case "$1" in'
    printf '%s\n' '  *Username*) printf '\''%s\n'\'' "${CNB_TOKEN_USER_NAME:-cnb}" ;;'
    printf '%s\n' '  *Password*) printf '\''%s\n'\'' "$CNB_TOKEN" ;;'
    printf '%s\n' '  *) exit 1 ;;'
    printf '%s\n' 'esac'
  } > "$ASKPASS_FILE"
  chmod 0700 "$ASKPASS_FILE"
  export GIT_ASKPASS="$ASKPASS_FILE"
  export GIT_TERMINAL_PROMPT=0
fi

compare_tag_message() {
  local tag_ref="$1"
  [[ "$(git cat-file -t "$tag_ref")" == tag ]] || die 'candidate tag is not annotated'
  if [[ -z "$TAG_OBJECT_FILE" ]]; then
    TAG_OBJECT_FILE="$(mktemp "${TMPDIR:-/tmp}/cnb-candidate-tag-object.XXXXXX")"
  fi
  if [[ -z "$TAG_MESSAGE_FILE" ]]; then
    TAG_MESSAGE_FILE="$(mktemp "${TMPDIR:-/tmp}/cnb-candidate-tag-message.XXXXXX")"
  fi
  git cat-file tag "$tag_ref" > "$TAG_OBJECT_FILE"
  python3 - "$TAG_OBJECT_FILE" "$TAG_MESSAGE_FILE" <<'PY'
from pathlib import Path
import sys

raw = Path(sys.argv[1]).read_bytes()
header, separator, message = raw.partition(b"\n\n")
if not separator or not header.startswith(b"object "):
    raise SystemExit("candidate tag object is malformed")
Path(sys.argv[2]).write_bytes(message)
PY
  cmp -s "$TAG_MESSAGE_FILE" "$MANIFEST" || \
    die 'existing candidate tag evidence does not match byte-for-byte'
}

verify_remote_tag() {
  local remote_refs="$1"
  local remote_tag_object
  local remote_commit

  remote_tag_object="$(
    printf '%s\n' "$remote_refs" | awk -v ref="refs/tags/$TAG" '$2 == ref { print $1 }'
  )"
  remote_commit="$(
    printf '%s\n' "$remote_refs" | awk -v ref="refs/tags/$TAG^{}" '$2 == ref { print $1 }'
  )"
  [[ -n "$remote_tag_object" && -n "$remote_commit" ]] || \
    die 'existing candidate tag is not annotated'
  [[ "$remote_commit" == "$COMMIT" ]] || \
    die 'existing candidate tag points to a different commit'

  VERIFICATION_REF="refs/cnb-candidate-verification/$$-${RANDOM}"
  git -c credential.helper= fetch --quiet --no-tags "$REMOTE" \
    "refs/tags/$TAG:$VERIFICATION_REF"
  [[ "$(git rev-parse "$VERIFICATION_REF")" == "$remote_tag_object" ]] || \
    die 'candidate tag changed while it was being verified'
  [[ "$(git rev-parse "$VERIFICATION_REF^{}")" == "$COMMIT" ]] || \
    die 'existing candidate tag points to a different commit after fetch'
  compare_tag_message "$VERIFICATION_REF"
}

remote_refs="$(
  git -c credential.helper= ls-remote --tags "$REMOTE" \
    "refs/tags/$TAG" "refs/tags/$TAG^{}"
)"
if [[ -n "$remote_refs" ]]; then
  verify_remote_tag "$remote_refs"
  printf 'candidate_tag=%s\n' "$TAG"
  printf 'status=existing\n'
  exit 0
fi

if git show-ref --verify --quiet "refs/tags/$TAG"; then
  die 'local candidate tag exists while the remote tag is absent'
fi

GIT_COMMITTER_NAME='CNB Release Pipeline' \
GIT_COMMITTER_EMAIL='cnb-release@cnb.invalid' \
  git tag --annotate "$TAG" "$COMMIT" --file "$MANIFEST" --cleanup=verbatim
CREATED_LOCAL_TAG=1
compare_tag_message "refs/tags/$TAG"
git -c credential.helper= push --quiet "$REMOTE" "refs/tags/$TAG"
remote_refs="$(
  git -c credential.helper= ls-remote --tags "$REMOTE" \
    "refs/tags/$TAG" "refs/tags/$TAG^{}"
)"
[[ -n "$remote_refs" ]] || die 'candidate tag is missing after push'
verify_remote_tag "$remote_refs"
PUBLISH_COMPLETE=1

printf 'candidate_tag=%s\n' "$TAG"
printf 'status=created\n'
