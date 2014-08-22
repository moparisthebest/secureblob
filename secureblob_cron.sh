#!/bin/bash
#     secureblob.php https://github.com/moparisthebest/secureblob
#     Copyright (C) 2014  moparisthebest (Travis Burtrum)
#
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU Affero General Public License as published by
#     the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.
# 
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU Affero General Public License for more details.
#
#     You should have received a copy of the GNU Affero General Public License
#     along with this program.  If not, see <http://www.gnu.org/licenses/>.

file_age_hours(){
    file="$1"
    from_date="$2"
    [ -z "$from_date" ] && from_date="$(date +%s)"
    seconds_diff="$(($from_date - $(stat -c '%Y' "$file")))"
    echo "$(($seconds_diff/60/60))"
}

from_date="$(date +%s)"
find /tmp/secureblob /run/shm/secureblob -type f -name failed-attempts -mmin +60 | while read file
do
    dir="$(dirname "$file")"
    [ "$(file_age_hours "$file" "$from_date")" -lt "$(cat "$dir/time-to-live")" ] 2>/dev/null || {
        # done this way so if time-to-live isn't a proper number we delete everything
        find "$dir" -type f -exec shred --force --remove '{}' \;
        rm -rf "$dir"
    }
done
exit

# set up tests
rm -rf /run/shm/secureblob /tmp/secureblob
mkdir -p /run/shm/secureblob /tmp/secureblob /tmp/secureblob/bob /tmp/secureblob/tom
touch /tmp/secureblob/tom/failed-attempts
echo 1 > /tmp/secureblob/tom/time-to-live
touch --date='3 hours ago' /tmp/secureblob/bob/failed-attempts
echo 2 > /tmp/secureblob/bob/time-to-live
# end tests
