/*
   BLAKE2 reference source code package - optimized C implementations

   Written in 2012 by Samuel Neves <sneves@dei.uc.pt>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/
#pragma once
#ifndef __BLAKE2S_COMPRESS_SSE_H__
#define __BLAKE2S_COMPRESS_SSE_H__

#include <emmintrin.h>
#if defined(HAVE_SSSE3)
#include <tmmintrin.h>
#endif
#if defined(HAVE_SSE41)
#include <smmintrin.h>
#endif
#if defined(HAVE_AVX)
#include <immintrin.h>
#endif
#if defined(HAVE_XOP)
#include <x86intrin.h>
#endif

#include "blake2s-round.h"

static inline int blake2s_compress( blake2s_state *S, const uint8_t block[BLAKE2S_BLOCKBYTES] )
{
  __m128i row1, row2, row3, row4;
  __m128i buf1, buf2, buf3, buf4;
#if defined(HAVE_SSE41)
  __m128i t0, t1;
#if !defined(HAVE_XOP)
  __m128i t2;
#endif
#endif
  __m128i ff0, ff1;
#if defined(HAVE_SSSE3) && !defined(HAVE_XOP)
  const __m128i r8 = _mm_set_epi8( 12, 15, 14, 13, 8, 11, 10, 9, 4, 7, 6, 5, 0, 3, 2, 1 );
  const __m128i r16 = _mm_set_epi8( 13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2 );
#endif
#if defined(HAVE_SSE41)
  const __m128i m0 = LOADU( block +  00 );
  const __m128i m1 = LOADU( block +  16 );
  const __m128i m2 = LOADU( block +  32 );
  const __m128i m3 = LOADU( block +  48 );
#else
  const uint32_t  m0 = ( ( uint32_t * )block )[ 0];
  const uint32_t  m1 = ( ( uint32_t * )block )[ 1];
  const uint32_t  m2 = ( ( uint32_t * )block )[ 2];
  const uint32_t  m3 = ( ( uint32_t * )block )[ 3];
  const uint32_t  m4 = ( ( uint32_t * )block )[ 4];
  const uint32_t  m5 = ( ( uint32_t * )block )[ 5];
  const uint32_t  m6 = ( ( uint32_t * )block )[ 6];
  const uint32_t  m7 = ( ( uint32_t * )block )[ 7];
  const uint32_t  m8 = ( ( uint32_t * )block )[ 8];
  const uint32_t  m9 = ( ( uint32_t * )block )[ 9];
  const uint32_t m10 = ( ( uint32_t * )block )[10];
  const uint32_t m11 = ( ( uint32_t * )block )[11];
  const uint32_t m12 = ( ( uint32_t * )block )[12];
  const uint32_t m13 = ( ( uint32_t * )block )[13];
  const uint32_t m14 = ( ( uint32_t * )block )[14];
  const uint32_t m15 = ( ( uint32_t * )block )[15];
#endif
  row1 = ff0 = LOAD( &S->h[0] );
  row2 = ff1 = LOAD( &S->h[4] );
  row3 = _mm_setr_epi32( 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A );
  row4 = _mm_xor_si128( _mm_setr_epi32( 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19 ), LOAD( &S->t[0] ) );
  ROUND( 0 );
  ROUND( 1 );
  ROUND( 2 );
  ROUND( 3 );
  ROUND( 4 );
  ROUND( 5 );
  ROUND( 6 );
  ROUND( 7 );
  ROUND( 8 );
  ROUND( 9 );
  STORE( &S->h[0], _mm_xor_si128( ff0, _mm_xor_si128( row1, row3 ) ) );
  STORE( &S->h[4], _mm_xor_si128( ff1, _mm_xor_si128( row2, row4 ) ) );
  return 0;
}

#endif
