#!/bin/bash

make distclean || echo clean

rm -f config.status
./autogen.sh || echo done

CFLAGS="-O3 -march=native -mtune=native -Wall" ./configure

make -j ${nproc}
