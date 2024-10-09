#! /bin/bash

options="-h -S -r -s --dyn-syms -d -l -g"
options="-h -S"
for option in $options; do
for file in /bin/sh tests/binary_input/elf_small.out; do
echo "=== readelf $option $file ==="
diff -c <(readelf $option $file) <(python ./examples/readelf.py $option --readelf=native $file 2>/dev/null)
done
done
