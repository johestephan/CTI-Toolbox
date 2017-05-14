#!/bin/bash

echo ""
echo "HTTP (objects):"
echo "====================================="
cat $1 | egrep -o "http[a-zA-Z0-9./:]*" | sort -u | cut -d " " -f 2

for ITEM in `cat $1 | egrep -o "http[a-zA-Z0-9./:]*" | sort -u | cut -d " " -f 2`
do
        wget --timeout=3 -t 1 $ITEM
done
