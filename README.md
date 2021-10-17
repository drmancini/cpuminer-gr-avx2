This is a cutdown version of the cpuminer-gr that only has gr_hash (Ghost Rider)
and any of the required by GR algorithm hashes.
It was created for easier creation of the C library that can be imported
and used by other software in GPLv2 friendly way in private or closed source
projects like other software or pools.

Build
------------

Run the building script that should create a native compilation of the library.
Some packages like gcc, make, automake, and automake are required for the build.

```
$ ./build.sh
```

Requirements
------------

1. A x86-64 architecture CPU with a minimum of SSE2 support. This includes
Intel Core2 and newer and AMD equivalents. Further optimizations are available
on some algoritms for CPUs with AES, AVX, AVX2, SHA, AVX512 and VAES.

ARM and Aarch64 CPUs are not supported, yet.

2. 64 bit Linux or Windows OS. Ubuntu and Fedora based distributions,
including Mint and Centos, are known to work and have all dependencies
in their repositories. Others may work but may require more effort. Older
versions such as Centos 6 don't work due to missing features. 
64 bit Windows OS is supported with mingw-w64 and msys or pre-built binaries.

MacOS, OSx and Android are not supported.
