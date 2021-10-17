#ifndef CRYPTONIGHT_H_
#define CRYPTONIGHT_H_

#ifdef __cplusplus
extern "C" {
#endif

// Helper functions for different types of Cryptonight variants.
void cryptonight_dark_hash(const void *input, void *output);
void cryptonight_darklite_hash(const void *input, void *output);
void cryptonight_fast_hash(const void *input, void *output);
void cryptonight_lite_hash(const void *input, void *output);
void cryptonight_turtle_hash(const void *input, void *output);
void cryptonight_turtlelite_hash(const void *input, void *output);

#ifdef __cplusplus
}
#endif

#endif // CRYPTONIGHT_H_
