#!/bin/bash
# Run from the private Desktop-access archive, as your normal Mac user.
set -euo pipefail
umask 077
source_dir=$(cd "$(dirname "$0")" && pwd)
destination="$HOME/Library/Application Support/MyVPN/Desktop"
[[ -f $source_dir/access.json && -f $source_dir/identity ]] || { echo 'Missing private access files' >&2; exit 1; }
if [[ -e $destination/access.json || -e $destination/identity ]]; then
  cmp -s "$source_dir/access.json" "$destination/access.json" && cmp -s "$source_dir/identity" "$destination/identity" && { echo 'Desktop access is already installed'; exit 0; }
  echo 'Different desktop access already exists; back it up before replacing it.' >&2
  exit 1
fi
install -d -m 700 "$destination"
install -m 600 "$source_dir/access.json" "$source_dir/identity" "$destination/"
echo 'Desktop access installed. Open My VPN → Рабочий стол США.'
