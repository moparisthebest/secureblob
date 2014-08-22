#!/bin/bash
url="$1"
[ -z "$url" ] && echo "Must specify URL" && exit 1
file="$2"
[ -z "$file" ] && file="${BASH_SOURCE[0]}"
echo "uploading '$file' to '$url'"
sha1sum < "$file"
curl -s -F "file=@$file" -F 'id=bob' -F 'key=bob' -F 'failed-attempts=3' "$url" | sha1sum
curl -s -F 'id=bob' -F 'key=bob' "$url" | sha1sum
