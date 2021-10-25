#!/bin/bash

make distclean || echo clean

rm -f config.status
./autogen.sh || echo done

GCC_VERSION=$(gcc --version | grep ^gcc | sed 's/^.* //g')
GCC_MAJOR=$(echo $GCC_VERSION | cut -d. -f1)

# Allow for different uArch via build argument.
MARCH="native"
if [[ ! -z ${1} ]]; then
  MARCH="${1}"
fi

echo "Detected GCC ${GCC_VERSION} with Major ${GCC_MAJOR}"

if [[ $GCC_MAJOR == 8 || $GCC_MAJOR == 9 ]]; then

  CFLAGS="-O3 -march=${MARCH} -mtune=${MARCH}" \
  CXXFLAGS="$CFLAGS -std=c++2a -fconcepts -Wno-ignored-attributes" \
  ./configure

elif [[ $GCC_MAJOR -ge 10 ]]; then

  CFLAGS="-O3 -march=${MARCH} -mtune=${MARCH}" \
  CXXFLAGS="$CFLAGS -std=c++20 -Wno-ignored-attributes" \
  ./configure

else
  echo "GCC version >= 8 is required for compilation"
  exit
fi

make -j ${nproc}
