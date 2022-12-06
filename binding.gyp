{
  "targets": [
    {
      "target_name": "gr",
      "type": "shared_library",
      "include_dirs": [
        "./",
      ],
      "sources": [
        "virtual_memory.c",
        "crypto/c_keccak.c",
        "algo/blake/sph_blake.c",
        "algo/bmw/sph_bmw.c",
        "algo/cubehash/cubehash_sse2.c",
        "algo/echo/sph_echo.c",
        "algo/echo/aes_ni/hash.c",
        "algo/fugue/fugue-aesni.c",
        "algo/fugue/sph_fugue.c",
        "algo/gr/gr.cpp",
        "algo/gr/gr-1way.cpp",
        "algo/gr/gr-2way.cpp",
        "algo/gr/gr-3way.cpp",
        "algo/gr/gr-4way.cpp",
        "algo/groestl/sph_groestl.c",
        "algo/groestl/aes_ni/hash-groestl.c",
        "algo/groestl/aes_ni/hash-groestl256.c",
        "algo/hamsi/sph_hamsi.c",
        "algo/jh/sph_jh.c",
        "algo/keccak/sph_keccak.c",
        "algo/luffa/luffa_for_sse2.c",
        "algo/shabal/sph_shabal.c",
        "algo/shavite/sph_shavite.c",
        "algo/shavite/sph-shavite-aesni.c",
        "algo/simd/nist.c",
        "algo/simd/vector.c",
        "algo/skein/sph_skein.c",
        "algo/whirlpool/sph_whirlpool.c",
      ],
    }
  ]
}

