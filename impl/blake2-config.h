#ifndef __BLAKE2_CONFIG_H__
#define __BLAKE2_CONFIG_H__

#ifndef _MSC_VER
# include <stdint.h>
#else
 typedef unsigned __int8  uint8_t;
 typedef unsigned __int32 uint32_t;
 typedef unsigned __int64 uint64_t;
# ifndef inline
#  define inline __forceinline
# endif
#endif

// These don't work everywhere
/*
#if defined(__SSE2__)
#define HAVE_SSE2
#endif

#if defined(__SSSE3__)
#define HAVE_SSSE3
#endif

#if defined(__SSE4_1__)
#define HAVE_SSE41
#endif

#if defined(__AVX__)
#define HAVE_AVX
#endif

#if defined(__XOP__)
#define HAVE_XOP
#endif
*/

#ifdef BLAKE2_COMPRESS_SSE2
#define BLAKE2_COMPRESS_SSE
#define HAVE_SSE2
#endif

#ifdef BLAKE2_COMPRESS_SSSE3
#define BLAKE2_COMPRESS_SSE
#define HAVE_SSSE3
#endif

#ifdef BLAKE2_COMPRESS_AVX
#define BLAKE2_COMPRESS_SSE
#define HAVE_AVX
#endif

#ifdef BLAKE2_COMPRESS_XOP
#define BLAKE2_COMPRESS_SSE
#define HAVE_XOP
#endif


#ifdef HAVE_AVX2
#ifndef HAVE_AVX
#define HAVE_AVX
#endif
#endif

#ifdef HAVE_XOP
#ifndef HAVE_AVX
#define HAVE_AVX
#endif
#endif

#ifdef HAVE_AVX
#ifndef HAVE_SSE41
#define HAVE_SSE41
#endif
#endif

#ifdef HAVE_SSE41
#ifndef HAVE_SSSE3
#define HAVE_SSSE3
#endif
#endif

#ifdef HAVE_SSSE3
#define HAVE_SSE2
#endif

#endif
