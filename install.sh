#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT=${VPS_WATCH_ROOT:-/}
ROOT=${ROOT%/}
dry=0
for arg in "$@"; do [[ $arg != --dry-run ]] || dry=1; done
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[[ -f "$ROOT/etc/os-release" ]] || fail 'Only Debian/Ubuntu systemd are supported; OpenWrt is not supported.'
# os-release is a root-owned system file, never fetched from the network.
. "$ROOT/etc/os-release"
[[ ${ID:-} == debian || ${ID:-} == ubuntu ]] || fail 'Only Debian/Ubuntu systemd are supported; OpenWrt is not supported.'
[[ -d "$ROOT/run/systemd/system" ]] || fail 'A running systemd host is required (not OpenWrt, chroot, or ordinary Docker).'
if [[ -z "$ROOT" ]]; then
  command -v systemctl >/dev/null || fail 'systemctl missing'
  [[ $(systemctl show baisi-watch.service -p ActiveState --value 2>/dev/null || :) != active ]] || fail 'baisi-watch already running: stop/migrate it explicitly to avoid duplicate monitors.'
fi
if (( dry )); then
  printf 'DRY RUN: would install missing python3 ca-certificates curl via apt; resolve main SHA; backup; preserve config/targets/baseline; enable vps-watch; verify health and Telegram. No writes performed.\n'
  exit 0
fi
[[ $EUID -eq 0 ]] || fail 'Run as root.'
[[ -z "$ROOT" ]] || fail 'VPS_WATCH_ROOT is supported for --dry-run and isolated Python tests only; refusing systemctl operations on a prefixed root.'
missing=()
command -v python3 >/dev/null || missing+=(python3)
command -v curl >/dev/null || missing+=(curl)
dpkg-query -W -f='${Status}' ca-certificates 2>/dev/null | /bin/grep -q 'install ok installed' || missing+=(ca-certificates)
if ((${#missing[@]})); then
  command -v apt-get >/dev/null || fail 'apt-get required'
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"
fi
python3 -c 'import sys; assert sys.version_info >= (3,9), "Python >=3.9 required"'
HERE=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# A checked-out/downloaded complete repository is the local install mode.
if [[ -f "$HERE/watch.py" && -f "$HERE/installer.py" && -f "$HERE/vps-watch.service" ]]; then
  exec python3 "$HERE/installer.py" "$@"
fi
TMP=$(mktemp -d "${TMPDIR:-/var/tmp}/vps-watch.XXXXXXXX")
trap 'rm -rf -- "$TMP"' EXIT
curl --fail --silent --show-error --location --retry 3 --connect-timeout 10 --max-time 60 \
  https://api.github.com/repos/sohu96480/vps-watch/commits/main -o "$TMP/commit.json"
SHA=$(python3 -c 'import json,re,sys; s=json.load(open(sys.argv[1]))["sha"]; assert re.fullmatch("[0-9a-f]{40}",s); print(s)' "$TMP/commit.json")
printf 'Installing reviewed source snapshot: %s\n' "$SHA"
curl --fail --silent --show-error --location --retry 3 --connect-timeout 10 --max-time 180 \
  "https://api.github.com/repos/sohu96480/vps-watch/tarball/$SHA" -o "$TMP/source.tar.gz"
# Validate/extract without trusting archive paths, links, or devices.
python3 - "$TMP" <<'PY'
import pathlib,sys,tarfile
p=pathlib.Path(sys.argv[1]); out=p/'source'; out.mkdir()
with tarfile.open(p/'source.tar.gz') as t:
    members=t.getmembers()
    for m in members:
        parts=pathlib.PurePosixPath(m.name).parts
        if not parts or '..' in parts or m.name.startswith('/') or not (m.isdir() or m.isfile()):
            raise SystemExit('Unsafe source archive')
        dest=out.joinpath(*parts[1:])
        if m.isdir():dest.mkdir(parents=True,exist_ok=True)
        else:
            dest.parent.mkdir(parents=True,exist_ok=True)
            with t.extractfile(m) as src, dest.open('wb') as dst: dst.write(src.read())
PY
python3 "$TMP/source/installer.py" "$@"
