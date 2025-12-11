#!/bin/bash

FILE=README.md

echo "# Rainfall" > $FILE
echo >> $FILE
for level in level{0..9} bonus{0..3}; do
    # Adjust the paths to be relative to the root directory
    sed -E "s#\]\(\./resources/#](./$level/resources/#g" "$level/README.md" >> "$FILE"
    echo -e -n "\n\n" >> $FILE
done
