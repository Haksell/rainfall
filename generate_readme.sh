#!/bin/bash

FILE=README.md

echo "# Rainfall" > $FILE
echo >> $FILE
# for level in level{0..9} bonus{0..3}; do
for level in level{0..1}; do
    # Adjust the image paths to be relative to the root directory
    sed "s|!\[Alt text\](|&$level/resources/|g" $level/README.md >> $FILE
    echo -e -n "\n\n" >> $FILE
done
