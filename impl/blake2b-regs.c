/*
   BLAKE2 reference source code package - reference C implementations

   Written in 2012 by Samuel Neves <sneves@dei.uc.pt>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "blake2.h"
#include "blake2-impl.h"

static const uint64_t blake2b_IV[8] =
{
  0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
  0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
  0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint8_t blake2b_sigma[12][16] =
{
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};


static inline int blake2b_set_lastnode( blake2b_state *S )
{
  S->f[1] = ~0ULL;
  return 0;
}

static inline int blake2b_clear_lastnode( blake2b_state *S )
{
  S->f[1] = 0ULL;
  return 0;
}

/* Some helper functions, not necessarily useful */
static inline int blake2b_set_lastblock( blake2b_state *S )
{
  if( S->last_node ) blake2b_set_lastnode( S );

  S->f[0] = ~0ULL;
  return 0;
}

static inline int blake2b_clear_lastblock( blake2b_state *S )
{
  if( S->last_node ) blake2b_clear_lastnode( S );

  S->f[0] = 0ULL;
  return 0;
}

static inline int blake2b_increment_counter( blake2b_state *S, const uint64_t inc )
{
  S->t[0] += inc;
  S->t[1] += ( S->t[0] < inc );
  return 0;
}



// Parameter-related functions
static inline int blake2b_param_set_digest_length( blake2b_param *P, const uint8_t digest_length )
{
  P->digest_length = digest_length;
  return 0;
}

static inline int blake2b_param_set_fanout( blake2b_param *P, const uint8_t fanout )
{
  P->fanout = fanout;
  return 0;
}

static inline int blake2b_param_set_max_depth( blake2b_param *P, const uint8_t depth )
{
  P->depth = depth;
  return 0;
}

static inline int blake2b_param_set_leaf_length( blake2b_param *P, const uint32_t leaf_length )
{
  store32( &P->leaf_length, leaf_length );
  return 0;
}

static inline int blake2b_param_set_node_offset( blake2b_param *P, const uint64_t node_offset )
{
  store64( &P->node_offset, node_offset );
  return 0;
}

static inline int blake2b_param_set_node_depth( blake2b_param *P, const uint8_t node_depth )
{
  P->node_depth = node_depth;
  return 0;
}

static inline int blake2b_param_set_inner_length( blake2b_param *P, const uint8_t inner_length )
{
  P->inner_length = inner_length;
  return 0;
}

static inline int blake2b_param_set_salt( blake2b_param *P, const uint8_t salt[BLAKE2B_SALTBYTES] )
{
  memcpy( P->salt, salt, BLAKE2B_SALTBYTES );
  return 0;
}

static inline int blake2b_param_set_personal( blake2b_param *P, const uint8_t personal[BLAKE2B_PERSONALBYTES] )
{
  memcpy( P->personal, personal, BLAKE2B_PERSONALBYTES );
  return 0;
}

static inline int blake2b_init0( blake2b_state *S )
{
  memset( S, 0, sizeof( blake2b_state ) );

  for( int i = 0; i < 8; ++i ) S->h[i] = blake2b_IV[i];

  return 0;
}

/* init xors IV with input parameter block */
int blake2b_init_param( blake2b_state *S, const blake2b_param *P )
{
  blake2b_init0( S );
  uint8_t *p = ( uint8_t * )( P );

  /* IV XOR ParamBlock */
  for( size_t i = 0; i < 8; ++i )
    S->h[i] ^= load64( p + sizeof( S->h[i] ) * i );

  return 0;
}



int blake2b_init( blake2b_state *S, const uint8_t outlen )
{
  blake2b_param P[1];

  if ( ( !outlen ) || ( outlen > BLAKE2B_OUTBYTES ) ) return -1;

  P->digest_length = outlen;
  P->key_length    = 0;
  P->fanout        = 1;
  P->depth         = 1;
  store32( &P->leaf_length, 0 );
  store64( &P->node_offset, 0 );
  P->node_depth    = 0;
  P->inner_length  = 0;
  memset( P->reserved, 0, sizeof( P->reserved ) );
  memset( P->salt,     0, sizeof( P->salt ) );
  memset( P->personal, 0, sizeof( P->personal ) );
  return blake2b_init_param( S, P );
}


int blake2b_init_key( blake2b_state *S, const uint8_t outlen, const void *key, const uint8_t keylen )
{
  blake2b_param P[1];

  if ( ( !outlen ) || ( outlen > BLAKE2B_OUTBYTES ) ) return -1;

  if ( !key || !keylen || keylen > BLAKE2B_KEYBYTES ) return -1;

  P->digest_length = outlen;
  P->key_length    = keylen;
  P->fanout        = 1;
  P->depth         = 1;
  store32( &P->leaf_length, 0 );
  store64( &P->node_offset, 0 );
  P->node_depth    = 0;
  P->inner_length  = 0;
  memset( P->reserved, 0, sizeof( P->reserved ) );
  memset( P->salt,     0, sizeof( P->salt ) );
  memset( P->personal, 0, sizeof( P->personal ) );

  if( blake2b_init_param( S, P ) < 0 ) return -1;

  {
    uint8_t block[BLAKE2B_BLOCKBYTES];
    memset( block, 0, BLAKE2B_BLOCKBYTES );
    memcpy( block, key, keylen );
    blake2b_update( S, block, BLAKE2B_BLOCKBYTES );
    secure_zero_memory( block, BLAKE2B_BLOCKBYTES ); /* Burn the key from stack */
  }
  return 0;
}

#define ROTR64(x, c) (((x) >> (c)) | ((x) << (64-(c))))

static int blake2b_compress( blake2b_state *S, const uint8_t block[BLAKE2B_BLOCKBYTES] )
{
    const uint64_t m0  = load64(&block[0]);
    const uint64_t m1  = load64(&block[8]);
    const uint64_t m2  = load64(&block[16]);
    const uint64_t m3  = load64(&block[24]);
    const uint64_t m4  = load64(&block[32]);
    const uint64_t m5  = load64(&block[40]);
    const uint64_t m6  = load64(&block[48]);
    const uint64_t m7  = load64(&block[56]);
    const uint64_t m8  = load64(&block[64]);
    const uint64_t m9  = load64(&block[72]);
    const uint64_t m10 = load64(&block[80]);
    const uint64_t m11 = load64(&block[88]);
    const uint64_t m12 = load64(&block[96]);
    const uint64_t m13 = load64(&block[104]);
    const uint64_t m14 = load64(&block[112]);
    const uint64_t m15 = load64(&block[120]);

    uint64_t v0  = S->h[0];
    uint64_t v1  = S->h[1];
    uint64_t v2  = S->h[2];
    uint64_t v3  = S->h[3];
    uint64_t v4  = S->h[4];
    uint64_t v5  = S->h[5];
    uint64_t v6  = S->h[6];
    uint64_t v7  = S->h[7];
    uint64_t v8  = blake2b_IV[0];
    uint64_t v9  = blake2b_IV[1];
    uint64_t v10 = blake2b_IV[2];
    uint64_t v11 = blake2b_IV[3];
    uint64_t v12 = S->t[0] ^ blake2b_IV[4];
    uint64_t v13 = S->t[1] ^ blake2b_IV[5];
    uint64_t v14 = S->f[0] ^ blake2b_IV[6];
    uint64_t v15 = S->f[1] ^ blake2b_IV[7];

    v0 = v0 + v4 + m0; 
    v12 = ROTR64(v12 ^ v0, 32); 
    v8 = v8 + v12; 
    v4 = ROTR64(v4 ^ v8, 24); 
    v0 = v0 + v4 + m1; 
    v12 = ROTR64(v12 ^ v0, 16); 
    v8 = v8 + v12; 
    v4 = ROTR64(v4 ^ v8, 63); 
    v1 = v1 + v5 + m2; 
    v13 = ROTR64(v13 ^ v1, 32); 
    v9 = v9 + v13; 
    v5 = ROTR64(v5 ^ v9, 24); 
    v1 = v1 + v5 + m3; 
    v13 = ROTR64(v13 ^ v1, 16); 
    v9 = v9 + v13; 
    v5 = ROTR64(v5 ^ v9, 63); 
    v2 = v2 + v6 + m4; 
    v14 = ROTR64(v14 ^ v2, 32); 
    v10 = v10 + v14; 
    v6 = ROTR64(v6 ^ v10, 24); 
    v2 = v2 + v6 + m5; 
    v14 = ROTR64(v14 ^ v2, 16); 
    v10 = v10 + v14; 
    v6 = ROTR64(v6 ^ v10, 63); 
    v3 = v3 + v7 + m6; 
    v15 = ROTR64(v15 ^ v3, 32); 
    v11 = v11 + v15; 
    v7 = ROTR64(v7 ^ v11, 24); 
    v3 = v3 + v7 + m7; 
    v15 = ROTR64(v15 ^ v3, 16); 
    v11 = v11 + v15; 
    v7 = ROTR64(v7 ^ v11, 63); 
    v0 = v0 + v5 + m8; 
    v15 = ROTR64(v15 ^ v0, 32); 
    v10 = v10 + v15; 
    v5 = ROTR64(v5 ^ v10, 24); 
    v0 = v0 + v5 + m9; 
    v15 = ROTR64(v15 ^ v0, 16); 
    v10 = v10 + v15; 
    v5 = ROTR64(v5 ^ v10, 63); 
    v1 = v1 + v6 + m10; 
    v12 = ROTR64(v12 ^ v1, 32); 
    v11 = v11 + v12; 
    v6 = ROTR64(v6 ^ v11, 24); 
    v1 = v1 + v6 + m11; 
    v12 = ROTR64(v12 ^ v1, 16); 
    v11 = v11 + v12; 
    v6 = ROTR64(v6 ^ v11, 63); 
    v2 = v2 + v7 + m12; 
    v13 = ROTR64(v13 ^ v2, 32); 
    v8 = v8 + v13; 
    v7 = ROTR64(v7 ^ v8, 24); 
    v2 = v2 + v7 + m13; 
    v13 = ROTR64(v13 ^ v2, 16); 
    v8 = v8 + v13; 
    v7 = ROTR64(v7 ^ v8, 63); 
    v3 = v3 + v4 + m14; 
    v14 = ROTR64(v14 ^ v3, 32); 
    v9 = v9 + v14; 
    v4 = ROTR64(v4 ^ v9, 24); 
    v3 = v3 + v4 + m15; 
    v14 = ROTR64(v14 ^ v3, 16); 
    v9 = v9 + v14; 
    v4 = ROTR64(v4 ^ v9, 63); 
    v0 = v0 + v4 + m14; 
    v12 = ROTR64(v12 ^ v0, 32); 
    v8 = v8 + v12; 
    v4 = ROTR64(v4 ^ v8, 24); 
    v0 = v0 + v4 + m10; 
    v12 = ROTR64(v12 ^ v0, 16); 
    v8 = v8 + v12; 
    v4 = ROTR64(v4 ^ v8, 63); 
    v1 = v1 + v5 + m4; 
    v13 = ROTR64(v13 ^ v1, 32); 
    v9 = v9 + v13; 
    v5 = ROTR64(v5 ^ v9, 24); 
    v1 = v1 + v5 + m8; 
    v13 = ROTR64(v13 ^ v1, 16); 
    v9 = v9 + v13; 
    v5 = ROTR64(v5 ^ v9, 63); 
    v2 = v2 + v6 + m9; 
    v14 = ROTR64(v14 ^ v2, 32); 
    v10 = v10 + v14; 
    v6 = ROTR64(v6 ^ v10, 24); 
    v2 = v2 + v6 + m15; 
    v14 = ROTR64(v14 ^ v2, 16); 
    v10 = v10 + v14; 
    v6 = ROTR64(v6 ^ v10, 63); 
    v3 = v3 + v7 + m13; 
    v15 = ROTR64(v15 ^ v3, 32); 
    v11 = v11 + v15; 
    v7 = ROTR64(v7 ^ v11, 24); 
    v3 = v3 + v7 + m6; 
    v15 = ROTR64(v15 ^ v3, 16); 
    v11 = v11 + v15; 
    v7 = ROTR64(v7 ^ v11, 63); 
    v0 = v0 + v5 + m1; 
    v15 = ROTR64(v15 ^ v0, 32); 
    v10 = v10 + v15; 
    v5 = ROTR64(v5 ^ v10, 24); 
    v0 = v0 + v5 + m12; 
    v15 = ROTR64(v15 ^ v0, 16); 
    v10 = v10 + v15; 
    v5 = ROTR64(v5 ^ v10, 63); 
    v1 = v1 + v6 + m0; 
    v12 = ROTR64(v12 ^ v1, 32); 
    v11 = v11 + v12; 
    v6 = ROTR64(v6 ^ v11, 24); 
    v1 = v1 + v6 + m2; 
    v12 = ROTR64(v12 ^ v1, 16); 
    v11 = v11 + v12; 
    v6 = ROTR64(v6 ^ v11, 63); 
    v2 = v2 + v7 + m11; 
    v13 = ROTR64(v13 ^ v2, 32); 
    v8 = v8 + v13; 
    v7 = ROTR64(v7 ^ v8, 24); 
    v2 = v2 + v7 + m7; 
    v13 = ROTR64(v13 ^ v2, 16); 
    v8 = v8 + v13; 
    v7 = ROTR64(v7 ^ v8, 63); 
    v3 = v3 + v4 + m5; 
    v14 = ROTR64(v14 ^ v3, 32); 
    v9 = v9 + v14; 
    v4 = ROTR64(v4 ^ v9, 24); 
    v3 = v3 + v4 + m3; 
    v14 = ROTR64(v14 ^ v3, 16); 
    v9 = v9 + v14; 
    v4 = ROTR64(v4 ^ v9, 63); 
    v0 = v0 + v4 + m11; 
    v12 = ROTR64(v12 ^ v0, 32); 
    v8 = v8 + v12; 
    v4 = ROTR64(v4 ^ v8, 24); 
    v0 = v0 + v4 + m8; 
    v12 = ROTR64(v12 ^ v0, 16); 
    v8 = v8 + v12; 
    v4 = ROTR64(v4 ^ v8, 63); 
    v1 = v1 + v5 + m12; 
    v13 = ROTR64(v13 ^ v1, 32); 
    v9 = v9 + v13; 
    v5 = ROTR64(v5 ^ v9, 24); 
    v1 = v1 + v5 + m0; 
    v13 = ROTR64(v13 ^ v1, 16); 
    v9 = v9 + v13; 
    v5 = ROTR64(v5 ^ v9, 63); 
    v2 = v2 + v6 + m5; 
    v14 = ROTR64(v14 ^ v2, 32); 
    v10 = v10 + v14; 
    v6 = ROTR64(v6 ^ v10, 24); 
    v2 = v2 + v6 + m2; 
    v14 = ROTR64(v14 ^ v2, 16); 
    v10 = v10 + v14; 
    v6 = ROTR64(v6 ^ v10, 63); 
    v3 = v3 + v7 + m15; 
    v15 = ROTR64(v15 ^ v3, 32); 
    v11 = v11 + v15; 
    v7 = ROTR64(v7 ^ v11, 24); 
    v3 = v3 + v7 + m13; 
    v15 = ROTR64(v15 ^ v3, 16); 
    v11 = v11 + v15; 
    v7 = ROTR64(v7 ^ v11, 63); 
    v0 = v0 + v5 + m10; 
    v15 = ROTR64(v15 ^ v0, 32); 
    v10 = v10 + v15; 
    v5 = ROTR64(v5 ^ v10, 24); 
    v0 = v0 + v5 + m14; 
    v15 = ROTR64(v15 ^ v0, 16); 
    v10 = v10 + v15; 
    v5 = ROTR64(v5 ^ v10, 63); 
    v1 = v1 + v6 + m3; 
    v12 = ROTR64(v12 ^ v1, 32); 
    v11 = v11 + v12; 
    v6 = ROTR64(v6 ^ v11, 24); 
    v1 = v1 + v6 + m6; 
    v12 = ROTR64(v12 ^ v1, 16); 
    v11 = v11 + v12; 
    v6 = ROTR64(v6 ^ v11, 63); 
    v2 = v2 + v7 + m7; 
    v13 = ROTR64(v13 ^ v2, 32); 
    v8 = v8 + v13; 
    v7 = ROTR64(v7 ^ v8, 24); 
    v2 = v2 + v7 + m1; 
    v13 = ROTR64(v13 ^ v2, 16); 
    v8 = v8 + v13; 
    v7 = ROTR64(v7 ^ v8, 63); 
    v3 = v3 + v4 + m9; 
    v14 = ROTR64(v14 ^ v3, 32); 
    v9 = v9 + v14; 
    v4 = ROTR64(v4 ^ v9, 24); 
    v3 = v3 + v4 + m4; 
    v14 = ROTR64(v14 ^ v3, 16); 
    v9 = v9 + v14; 
    v4 = ROTR64(v4 ^ v9, 63); 
    v0 = v0 + v4 + m7; 
    v12 = ROTR64(v12 ^ v0, 32); 
    v8 = v8 + v12; 
    v4 = ROTR64(v4 ^ v8, 24); 
    v0 = v0 + v4 + m9; 
    v12 = ROTR64(v12 ^ v0, 16); 
    v8 = v8 + v12; 
    v4 = ROTR64(v4 ^ v8, 63); 
    v1 = v1 + v5 + m3; 
    v13 = ROTR64(v13 ^ v1, 32); 
    v9 = v9 + v13; 
    v5 = ROTR64(v5 ^ v9, 24); 
    v1 = v1 + v5 + m1; 
    v13 = ROTR64(v13 ^ v1, 16); 
    v9 = v9 + v13; 
    v5 = ROTR64(v5 ^ v9, 63); 
    v2 = v2 + v6 + m13; 
    v14 = ROTR64(v14 ^ v2, 32); 
    v10 = v10 + v14; 
    v6 = ROTR64(v6 ^ v10, 24); 
    v2 = v2 + v6 + m12; 
    v14 = ROTR64(v14 ^ v2, 16); 
    v10 = v10 + v14; 
    v6 = ROTR64(v6 ^ v10, 63); 
    v3 = v3 + v7 + m11; 
    v15 = ROTR64(v15 ^ v3, 32); 
    v11 = v11 + v15; 
    v7 = ROTR64(v7 ^ v11, 24); 
    v3 = v3 + v7 + m14; 
    v15 = ROTR64(v15 ^ v3, 16); 
    v11 = v11 + v15; 
    v7 = ROTR64(v7 ^ v11, 63); 
    v0 = v0 + v5 + m2; 
    v15 = ROTR64(v15 ^ v0, 32); 
    v10 = v10 + v15; 
    v5 = ROTR64(v5 ^ v10, 24); 
    v0 = v0 + v5 + m6; 
    v15 = ROTR64(v15 ^ v0, 16); 
    v10 = v10 + v15; 
    v5 = ROTR64(v5 ^ v10, 63); 
    v1 = v1 + v6 + m5; 
    v12 = ROTR64(v12 ^ v1, 32); 
    v11 = v11 + v12; 
    v6 = ROTR64(v6 ^ v11, 24); 
    v1 = v1 + v6 + m10; 
    v12 = ROTR64(v12 ^ v1, 16); 
    v11 = v11 + v12; 
    v6 = ROTR64(v6 ^ v11, 63); 
    v2 = v2 + v7 + m4; 
    v13 = ROTR64(v13 ^ v2, 32); 
    v8 = v8 + v13; 
    v7 = ROTR64(v7 ^ v8, 24); 
    v2 = v2 + v7 + m0; 
    v13 = ROTR64(v13 ^ v2, 16); 
    v8 = v8 + v13; 
    v7 = ROTR64(v7 ^ v8, 63); 
    v3 = v3 + v4 + m15; 
    v14 = ROTR64(v14 ^ v3, 32); 
    v9 = v9 + v14; 
    v4 = ROTR64(v4 ^ v9, 24); 
    v3 = v3 + v4 + m8; 
    v14 = ROTR64(v14 ^ v3, 16); 
    v9 = v9 + v14; 
    v4 = ROTR64(v4 ^ v9, 63); 
    v0 = v0 + v4 + m9; 
    v12 = ROTR64(v12 ^ v0, 32); 
    v8 = v8 + v12; 
    v4 = ROTR64(v4 ^ v8, 24); 
    v0 = v0 + v4 + m0; 
    v12 = ROTR64(v12 ^ v0, 16); 
    v8 = v8 + v12; 
    v4 = ROTR64(v4 ^ v8, 63); 
    v1 = v1 + v5 + m5; 
    v13 = ROTR64(v13 ^ v1, 32); 
    v9 = v9 + v13; 
    v5 = ROTR64(v5 ^ v9, 24); 
    v1 = v1 + v5 + m7; 
    v13 = ROTR64(v13 ^ v1, 16); 
    v9 = v9 + v13; 
    v5 = ROTR64(v5 ^ v9, 63); 
    v2 = v2 + v6 + m2; 
    v14 = ROTR64(v14 ^ v2, 32); 
    v10 = v10 + v14; 
    v6 = ROTR64(v6 ^ v10, 24); 
    v2 = v2 + v6 + m4; 
    v14 = ROTR64(v14 ^ v2, 16); 
    v10 = v10 + v14; 
    v6 = ROTR64(v6 ^ v10, 63); 
    v3 = v3 + v7 + m10; 
    v15 = ROTR64(v15 ^ v3, 32); 
    v11 = v11 + v15; 
    v7 = ROTR64(v7 ^ v11, 24); 
    v3 = v3 + v7 + m15; 
    v15 = ROTR64(v15 ^ v3, 16); 
    v11 = v11 + v15; 
    v7 = ROTR64(v7 ^ v11, 63); 
    v0 = v0 + v5 + m14; 
    v15 = ROTR64(v15 ^ v0, 32); 
    v10 = v10 + v15; 
    v5 = ROTR64(v5 ^ v10, 24); 
    v0 = v0 + v5 + m1; 
    v15 = ROTR64(v15 ^ v0, 16); 
    v10 = v10 + v15; 
    v5 = ROTR64(v5 ^ v10, 63); 
    v1 = v1 + v6 + m11; 
    v12 = ROTR64(v12 ^ v1, 32); 
    v11 = v11 + v12; 
    v6 = ROTR64(v6 ^ v11, 24); 
    v1 = v1 + v6 + m12; 
    v12 = ROTR64(v12 ^ v1, 16); 
    v11 = v11 + v12; 
    v6 = ROTR64(v6 ^ v11, 63); 
    v2 = v2 + v7 + m6; 
    v13 = ROTR64(v13 ^ v2, 32); 
    v8 = v8 + v13; 
    v7 = ROTR64(v7 ^ v8, 24); 
    v2 = v2 + v7 + m8; 
    v13 = ROTR64(v13 ^ v2, 16); 
    v8 = v8 + v13; 
    v7 = ROTR64(v7 ^ v8, 63); 
    v3 = v3 + v4 + m3; 
    v14 = ROTR64(v14 ^ v3, 32); 
    v9 = v9 + v14; 
    v4 = ROTR64(v4 ^ v9, 24); 
    v3 = v3 + v4 + m13; 
    v14 = ROTR64(v14 ^ v3, 16); 
    v9 = v9 + v14; 
    v4 = ROTR64(v4 ^ v9, 63); 
    v0 = v0 + v4 + m2; 
    v12 = ROTR64(v12 ^ v0, 32); 
    v8 = v8 + v12; 
    v4 = ROTR64(v4 ^ v8, 24); 
    v0 = v0 + v4 + m12; 
    v12 = ROTR64(v12 ^ v0, 16); 
    v8 = v8 + v12; 
    v4 = ROTR64(v4 ^ v8, 63); 
    v1 = v1 + v5 + m6; 
    v13 = ROTR64(v13 ^ v1, 32); 
    v9 = v9 + v13; 
    v5 = ROTR64(v5 ^ v9, 24); 
    v1 = v1 + v5 + m10; 
    v13 = ROTR64(v13 ^ v1, 16); 
    v9 = v9 + v13; 
    v5 = ROTR64(v5 ^ v9, 63); 
    v2 = v2 + v6 + m0; 
    v14 = ROTR64(v14 ^ v2, 32); 
    v10 = v10 + v14; 
    v6 = ROTR64(v6 ^ v10, 24); 
    v2 = v2 + v6 + m11; 
    v14 = ROTR64(v14 ^ v2, 16); 
    v10 = v10 + v14; 
    v6 = ROTR64(v6 ^ v10, 63); 
    v3 = v3 + v7 + m8; 
    v15 = ROTR64(v15 ^ v3, 32); 
    v11 = v11 + v15; 
    v7 = ROTR64(v7 ^ v11, 24); 
    v3 = v3 + v7 + m3; 
    v15 = ROTR64(v15 ^ v3, 16); 
    v11 = v11 + v15; 
    v7 = ROTR64(v7 ^ v11, 63); 
    v0 = v0 + v5 + m4; 
    v15 = ROTR64(v15 ^ v0, 32); 
    v10 = v10 + v15; 
    v5 = ROTR64(v5 ^ v10, 24); 
    v0 = v0 + v5 + m13; 
    v15 = ROTR64(v15 ^ v0, 16); 
    v10 = v10 + v15; 
    v5 = ROTR64(v5 ^ v10, 63); 
    v1 = v1 + v6 + m7; 
    v12 = ROTR64(v12 ^ v1, 32); 
    v11 = v11 + v12; 
    v6 = ROTR64(v6 ^ v11, 24); 
    v1 = v1 + v6 + m5; 
    v12 = ROTR64(v12 ^ v1, 16); 
    v11 = v11 + v12; 
    v6 = ROTR64(v6 ^ v11, 63); 
    v2 = v2 + v7 + m15; 
    v13 = ROTR64(v13 ^ v2, 32); 
    v8 = v8 + v13; 
    v7 = ROTR64(v7 ^ v8, 24); 
    v2 = v2 + v7 + m14; 
    v13 = ROTR64(v13 ^ v2, 16); 
    v8 = v8 + v13; 
    v7 = ROTR64(v7 ^ v8, 63); 
    v3 = v3 + v4 + m1; 
    v14 = ROTR64(v14 ^ v3, 32); 
    v9 = v9 + v14; 
    v4 = ROTR64(v4 ^ v9, 24); 
    v3 = v3 + v4 + m9; 
    v14 = ROTR64(v14 ^ v3, 16); 
    v9 = v9 + v14; 
    v4 = ROTR64(v4 ^ v9, 63); 
    v0 = v0 + v4 + m12; 
    v12 = ROTR64(v12 ^ v0, 32); 
    v8 = v8 + v12; 
    v4 = ROTR64(v4 ^ v8, 24); 
    v0 = v0 + v4 + m5; 
    v12 = ROTR64(v12 ^ v0, 16); 
    v8 = v8 + v12; 
    v4 = ROTR64(v4 ^ v8, 63); 
    v1 = v1 + v5 + m1; 
    v13 = ROTR64(v13 ^ v1, 32); 
    v9 = v9 + v13; 
    v5 = ROTR64(v5 ^ v9, 24); 
    v1 = v1 + v5 + m15; 
    v13 = ROTR64(v13 ^ v1, 16); 
    v9 = v9 + v13; 
    v5 = ROTR64(v5 ^ v9, 63); 
    v2 = v2 + v6 + m14; 
    v14 = ROTR64(v14 ^ v2, 32); 
    v10 = v10 + v14; 
    v6 = ROTR64(v6 ^ v10, 24); 
    v2 = v2 + v6 + m13; 
    v14 = ROTR64(v14 ^ v2, 16); 
    v10 = v10 + v14; 
    v6 = ROTR64(v6 ^ v10, 63); 
    v3 = v3 + v7 + m4; 
    v15 = ROTR64(v15 ^ v3, 32); 
    v11 = v11 + v15; 
    v7 = ROTR64(v7 ^ v11, 24); 
    v3 = v3 + v7 + m10; 
    v15 = ROTR64(v15 ^ v3, 16); 
    v11 = v11 + v15; 
    v7 = ROTR64(v7 ^ v11, 63); 
    v0 = v0 + v5 + m0; 
    v15 = ROTR64(v15 ^ v0, 32); 
    v10 = v10 + v15; 
    v5 = ROTR64(v5 ^ v10, 24); 
    v0 = v0 + v5 + m7; 
    v15 = ROTR64(v15 ^ v0, 16); 
    v10 = v10 + v15; 
    v5 = ROTR64(v5 ^ v10, 63); 
    v1 = v1 + v6 + m6; 
    v12 = ROTR64(v12 ^ v1, 32); 
    v11 = v11 + v12; 
    v6 = ROTR64(v6 ^ v11, 24); 
    v1 = v1 + v6 + m3; 
    v12 = ROTR64(v12 ^ v1, 16); 
    v11 = v11 + v12; 
    v6 = ROTR64(v6 ^ v11, 63); 
    v2 = v2 + v7 + m9; 
    v13 = ROTR64(v13 ^ v2, 32); 
    v8 = v8 + v13; 
    v7 = ROTR64(v7 ^ v8, 24); 
    v2 = v2 + v7 + m2; 
    v13 = ROTR64(v13 ^ v2, 16); 
    v8 = v8 + v13; 
    v7 = ROTR64(v7 ^ v8, 63); 
    v3 = v3 + v4 + m8; 
    v14 = ROTR64(v14 ^ v3, 32); 
    v9 = v9 + v14; 
    v4 = ROTR64(v4 ^ v9, 24); 
    v3 = v3 + v4 + m11; 
    v14 = ROTR64(v14 ^ v3, 16); 
    v9 = v9 + v14; 
    v4 = ROTR64(v4 ^ v9, 63); 
    v0 = v0 + v4 + m13; 
    v12 = ROTR64(v12 ^ v0, 32); 
    v8 = v8 + v12; 
    v4 = ROTR64(v4 ^ v8, 24); 
    v0 = v0 + v4 + m11; 
    v12 = ROTR64(v12 ^ v0, 16); 
    v8 = v8 + v12; 
    v4 = ROTR64(v4 ^ v8, 63); 
    v1 = v1 + v5 + m7; 
    v13 = ROTR64(v13 ^ v1, 32); 
    v9 = v9 + v13; 
    v5 = ROTR64(v5 ^ v9, 24); 
    v1 = v1 + v5 + m14; 
    v13 = ROTR64(v13 ^ v1, 16); 
    v9 = v9 + v13; 
    v5 = ROTR64(v5 ^ v9, 63); 
    v2 = v2 + v6 + m12; 
    v14 = ROTR64(v14 ^ v2, 32); 
    v10 = v10 + v14; 
    v6 = ROTR64(v6 ^ v10, 24); 
    v2 = v2 + v6 + m1; 
    v14 = ROTR64(v14 ^ v2, 16); 
    v10 = v10 + v14; 
    v6 = ROTR64(v6 ^ v10, 63); 
    v3 = v3 + v7 + m3; 
    v15 = ROTR64(v15 ^ v3, 32); 
    v11 = v11 + v15; 
    v7 = ROTR64(v7 ^ v11, 24); 
    v3 = v3 + v7 + m9; 
    v15 = ROTR64(v15 ^ v3, 16); 
    v11 = v11 + v15; 
    v7 = ROTR64(v7 ^ v11, 63); 
    v0 = v0 + v5 + m5; 
    v15 = ROTR64(v15 ^ v0, 32); 
    v10 = v10 + v15; 
    v5 = ROTR64(v5 ^ v10, 24); 
    v0 = v0 + v5 + m0; 
    v15 = ROTR64(v15 ^ v0, 16); 
    v10 = v10 + v15; 
    v5 = ROTR64(v5 ^ v10, 63); 
    v1 = v1 + v6 + m15; 
    v12 = ROTR64(v12 ^ v1, 32); 
    v11 = v11 + v12; 
    v6 = ROTR64(v6 ^ v11, 24); 
    v1 = v1 + v6 + m4; 
    v12 = ROTR64(v12 ^ v1, 16); 
    v11 = v11 + v12; 
    v6 = ROTR64(v6 ^ v11, 63); 
    v2 = v2 + v7 + m8; 
    v13 = ROTR64(v13 ^ v2, 32); 
    v8 = v8 + v13; 
    v7 = ROTR64(v7 ^ v8, 24); 
    v2 = v2 + v7 + m6; 
    v13 = ROTR64(v13 ^ v2, 16); 
    v8 = v8 + v13; 
    v7 = ROTR64(v7 ^ v8, 63); 
    v3 = v3 + v4 + m2; 
    v14 = ROTR64(v14 ^ v3, 32); 
    v9 = v9 + v14; 
    v4 = ROTR64(v4 ^ v9, 24); 
    v3 = v3 + v4 + m10; 
    v14 = ROTR64(v14 ^ v3, 16); 
    v9 = v9 + v14; 
    v4 = ROTR64(v4 ^ v9, 63); 
    v0 = v0 + v4 + m6; 
    v12 = ROTR64(v12 ^ v0, 32); 
    v8 = v8 + v12; 
    v4 = ROTR64(v4 ^ v8, 24); 
    v0 = v0 + v4 + m15; 
    v12 = ROTR64(v12 ^ v0, 16); 
    v8 = v8 + v12; 
    v4 = ROTR64(v4 ^ v8, 63); 
    v1 = v1 + v5 + m14; 
    v13 = ROTR64(v13 ^ v1, 32); 
    v9 = v9 + v13; 
    v5 = ROTR64(v5 ^ v9, 24); 
    v1 = v1 + v5 + m9; 
    v13 = ROTR64(v13 ^ v1, 16); 
    v9 = v9 + v13; 
    v5 = ROTR64(v5 ^ v9, 63); 
    v2 = v2 + v6 + m11; 
    v14 = ROTR64(v14 ^ v2, 32); 
    v10 = v10 + v14; 
    v6 = ROTR64(v6 ^ v10, 24); 
    v2 = v2 + v6 + m3; 
    v14 = ROTR64(v14 ^ v2, 16); 
    v10 = v10 + v14; 
    v6 = ROTR64(v6 ^ v10, 63); 
    v3 = v3 + v7 + m0; 
    v15 = ROTR64(v15 ^ v3, 32); 
    v11 = v11 + v15; 
    v7 = ROTR64(v7 ^ v11, 24); 
    v3 = v3 + v7 + m8; 
    v15 = ROTR64(v15 ^ v3, 16); 
    v11 = v11 + v15; 
    v7 = ROTR64(v7 ^ v11, 63); 
    v0 = v0 + v5 + m12; 
    v15 = ROTR64(v15 ^ v0, 32); 
    v10 = v10 + v15; 
    v5 = ROTR64(v5 ^ v10, 24); 
    v0 = v0 + v5 + m2; 
    v15 = ROTR64(v15 ^ v0, 16); 
    v10 = v10 + v15; 
    v5 = ROTR64(v5 ^ v10, 63); 
    v1 = v1 + v6 + m13; 
    v12 = ROTR64(v12 ^ v1, 32); 
    v11 = v11 + v12; 
    v6 = ROTR64(v6 ^ v11, 24); 
    v1 = v1 + v6 + m7; 
    v12 = ROTR64(v12 ^ v1, 16); 
    v11 = v11 + v12; 
    v6 = ROTR64(v6 ^ v11, 63); 
    v2 = v2 + v7 + m1; 
    v13 = ROTR64(v13 ^ v2, 32); 
    v8 = v8 + v13; 
    v7 = ROTR64(v7 ^ v8, 24); 
    v2 = v2 + v7 + m4; 
    v13 = ROTR64(v13 ^ v2, 16); 
    v8 = v8 + v13; 
    v7 = ROTR64(v7 ^ v8, 63); 
    v3 = v3 + v4 + m10; 
    v14 = ROTR64(v14 ^ v3, 32); 
    v9 = v9 + v14; 
    v4 = ROTR64(v4 ^ v9, 24); 
    v3 = v3 + v4 + m5; 
    v14 = ROTR64(v14 ^ v3, 16); 
    v9 = v9 + v14; 
    v4 = ROTR64(v4 ^ v9, 63); 
    v0 = v0 + v4 + m10; 
    v12 = ROTR64(v12 ^ v0, 32); 
    v8 = v8 + v12; 
    v4 = ROTR64(v4 ^ v8, 24); 
    v0 = v0 + v4 + m2; 
    v12 = ROTR64(v12 ^ v0, 16); 
    v8 = v8 + v12; 
    v4 = ROTR64(v4 ^ v8, 63); 
    v1 = v1 + v5 + m8; 
    v13 = ROTR64(v13 ^ v1, 32); 
    v9 = v9 + v13; 
    v5 = ROTR64(v5 ^ v9, 24); 
    v1 = v1 + v5 + m4; 
    v13 = ROTR64(v13 ^ v1, 16); 
    v9 = v9 + v13; 
    v5 = ROTR64(v5 ^ v9, 63); 
    v2 = v2 + v6 + m7; 
    v14 = ROTR64(v14 ^ v2, 32); 
    v10 = v10 + v14; 
    v6 = ROTR64(v6 ^ v10, 24); 
    v2 = v2 + v6 + m6; 
    v14 = ROTR64(v14 ^ v2, 16); 
    v10 = v10 + v14; 
    v6 = ROTR64(v6 ^ v10, 63); 
    v3 = v3 + v7 + m1; 
    v15 = ROTR64(v15 ^ v3, 32); 
    v11 = v11 + v15; 
    v7 = ROTR64(v7 ^ v11, 24); 
    v3 = v3 + v7 + m5; 
    v15 = ROTR64(v15 ^ v3, 16); 
    v11 = v11 + v15; 
    v7 = ROTR64(v7 ^ v11, 63); 
    v0 = v0 + v5 + m15; 
    v15 = ROTR64(v15 ^ v0, 32); 
    v10 = v10 + v15; 
    v5 = ROTR64(v5 ^ v10, 24); 
    v0 = v0 + v5 + m11; 
    v15 = ROTR64(v15 ^ v0, 16); 
    v10 = v10 + v15; 
    v5 = ROTR64(v5 ^ v10, 63); 
    v1 = v1 + v6 + m9; 
    v12 = ROTR64(v12 ^ v1, 32); 
    v11 = v11 + v12; 
    v6 = ROTR64(v6 ^ v11, 24); 
    v1 = v1 + v6 + m14; 
    v12 = ROTR64(v12 ^ v1, 16); 
    v11 = v11 + v12; 
    v6 = ROTR64(v6 ^ v11, 63); 
    v2 = v2 + v7 + m3; 
    v13 = ROTR64(v13 ^ v2, 32); 
    v8 = v8 + v13; 
    v7 = ROTR64(v7 ^ v8, 24); 
    v2 = v2 + v7 + m12; 
    v13 = ROTR64(v13 ^ v2, 16); 
    v8 = v8 + v13; 
    v7 = ROTR64(v7 ^ v8, 63); 
    v3 = v3 + v4 + m13; 
    v14 = ROTR64(v14 ^ v3, 32); 
    v9 = v9 + v14; 
    v4 = ROTR64(v4 ^ v9, 24); 
    v3 = v3 + v4 + m0; 
    v14 = ROTR64(v14 ^ v3, 16); 
    v9 = v9 + v14; 
    v4 = ROTR64(v4 ^ v9, 63); 
    v0 = v0 + v4 + m0; 
    v12 = ROTR64(v12 ^ v0, 32); 
    v8 = v8 + v12; 
    v4 = ROTR64(v4 ^ v8, 24); 
    v0 = v0 + v4 + m1; 
    v12 = ROTR64(v12 ^ v0, 16); 
    v8 = v8 + v12; 
    v4 = ROTR64(v4 ^ v8, 63); 
    v1 = v1 + v5 + m2; 
    v13 = ROTR64(v13 ^ v1, 32); 
    v9 = v9 + v13; 
    v5 = ROTR64(v5 ^ v9, 24); 
    v1 = v1 + v5 + m3; 
    v13 = ROTR64(v13 ^ v1, 16); 
    v9 = v9 + v13; 
    v5 = ROTR64(v5 ^ v9, 63); 
    v2 = v2 + v6 + m4; 
    v14 = ROTR64(v14 ^ v2, 32); 
    v10 = v10 + v14; 
    v6 = ROTR64(v6 ^ v10, 24); 
    v2 = v2 + v6 + m5; 
    v14 = ROTR64(v14 ^ v2, 16); 
    v10 = v10 + v14; 
    v6 = ROTR64(v6 ^ v10, 63); 
    v3 = v3 + v7 + m6; 
    v15 = ROTR64(v15 ^ v3, 32); 
    v11 = v11 + v15; 
    v7 = ROTR64(v7 ^ v11, 24); 
    v3 = v3 + v7 + m7; 
    v15 = ROTR64(v15 ^ v3, 16); 
    v11 = v11 + v15; 
    v7 = ROTR64(v7 ^ v11, 63); 
    v0 = v0 + v5 + m8; 
    v15 = ROTR64(v15 ^ v0, 32); 
    v10 = v10 + v15; 
    v5 = ROTR64(v5 ^ v10, 24); 
    v0 = v0 + v5 + m9; 
    v15 = ROTR64(v15 ^ v0, 16); 
    v10 = v10 + v15; 
    v5 = ROTR64(v5 ^ v10, 63); 
    v1 = v1 + v6 + m10; 
    v12 = ROTR64(v12 ^ v1, 32); 
    v11 = v11 + v12; 
    v6 = ROTR64(v6 ^ v11, 24); 
    v1 = v1 + v6 + m11; 
    v12 = ROTR64(v12 ^ v1, 16); 
    v11 = v11 + v12; 
    v6 = ROTR64(v6 ^ v11, 63); 
    v2 = v2 + v7 + m12; 
    v13 = ROTR64(v13 ^ v2, 32); 
    v8 = v8 + v13; 
    v7 = ROTR64(v7 ^ v8, 24); 
    v2 = v2 + v7 + m13; 
    v13 = ROTR64(v13 ^ v2, 16); 
    v8 = v8 + v13; 
    v7 = ROTR64(v7 ^ v8, 63); 
    v3 = v3 + v4 + m14; 
    v14 = ROTR64(v14 ^ v3, 32); 
    v9 = v9 + v14; 
    v4 = ROTR64(v4 ^ v9, 24); 
    v3 = v3 + v4 + m15; 
    v14 = ROTR64(v14 ^ v3, 16); 
    v9 = v9 + v14; 
    v4 = ROTR64(v4 ^ v9, 63); 
    v0 = v0 + v4 + m14; 
    v12 = ROTR64(v12 ^ v0, 32); 
    v8 = v8 + v12; 
    v4 = ROTR64(v4 ^ v8, 24); 
    v0 = v0 + v4 + m10; 
    v12 = ROTR64(v12 ^ v0, 16); 
    v8 = v8 + v12; 
    v4 = ROTR64(v4 ^ v8, 63); 
    v1 = v1 + v5 + m4; 
    v13 = ROTR64(v13 ^ v1, 32); 
    v9 = v9 + v13; 
    v5 = ROTR64(v5 ^ v9, 24); 
    v1 = v1 + v5 + m8; 
    v13 = ROTR64(v13 ^ v1, 16); 
    v9 = v9 + v13; 
    v5 = ROTR64(v5 ^ v9, 63); 
    v2 = v2 + v6 + m9; 
    v14 = ROTR64(v14 ^ v2, 32); 
    v10 = v10 + v14; 
    v6 = ROTR64(v6 ^ v10, 24); 
    v2 = v2 + v6 + m15; 
    v14 = ROTR64(v14 ^ v2, 16); 
    v10 = v10 + v14; 
    v6 = ROTR64(v6 ^ v10, 63); 
    v3 = v3 + v7 + m13; 
    v15 = ROTR64(v15 ^ v3, 32); 
    v11 = v11 + v15; 
    v7 = ROTR64(v7 ^ v11, 24); 
    v3 = v3 + v7 + m6; 
    v15 = ROTR64(v15 ^ v3, 16); 
    v11 = v11 + v15; 
    v7 = ROTR64(v7 ^ v11, 63); 
    v0 = v0 + v5 + m1; 
    v15 = ROTR64(v15 ^ v0, 32); 
    v10 = v10 + v15; 
    v5 = ROTR64(v5 ^ v10, 24); 
    v0 = v0 + v5 + m12; 
    v15 = ROTR64(v15 ^ v0, 16); 
    v10 = v10 + v15; 
    v5 = ROTR64(v5 ^ v10, 63); 
    v1 = v1 + v6 + m0; 
    v12 = ROTR64(v12 ^ v1, 32); 
    v11 = v11 + v12; 
    v6 = ROTR64(v6 ^ v11, 24); 
    v1 = v1 + v6 + m2; 
    v12 = ROTR64(v12 ^ v1, 16); 
    v11 = v11 + v12; 
    v6 = ROTR64(v6 ^ v11, 63); 
    v2 = v2 + v7 + m11; 
    v13 = ROTR64(v13 ^ v2, 32); 
    v8 = v8 + v13; 
    v7 = ROTR64(v7 ^ v8, 24); 
    v2 = v2 + v7 + m7; 
    v13 = ROTR64(v13 ^ v2, 16); 
    v8 = v8 + v13; 
    v7 = ROTR64(v7 ^ v8, 63); 
    v3 = v3 + v4 + m5; 
    v14 = ROTR64(v14 ^ v3, 32); 
    v9 = v9 + v14; 
    v4 = ROTR64(v4 ^ v9, 24); 
    v3 = v3 + v4 + m3; 
    v14 = ROTR64(v14 ^ v3, 16); 
    v9 = v9 + v14; 
    v4 = ROTR64(v4 ^ v9, 63); 

    S->h[0] ^= v0 ^  v8;
    S->h[1] ^= v1 ^  v9;
    S->h[2] ^= v2 ^ v10;
    S->h[3] ^= v3 ^ v11;
    S->h[4] ^= v4 ^ v12;
    S->h[5] ^= v5 ^ v13;
    S->h[6] ^= v6 ^ v14;
    S->h[7] ^= v7 ^ v15;

    return 0;
}

/*
static int blake2b_compress( blake2b_state *S, const uint8_t block[BLAKE2B_BLOCKBYTES] )
{
  uint64_t m[16];
  uint64_t v[16];
  int i;

  for( i = 0; i < 16; ++i )
    m[i] = load64( block + i * sizeof( m[i] ) );

  for( i = 0; i < 8; ++i )
    v[i] = S->h[i];

  v[ 8] = blake2b_IV[0];
  v[ 9] = blake2b_IV[1];
  v[10] = blake2b_IV[2];
  v[11] = blake2b_IV[3];
  v[12] = S->t[0] ^ blake2b_IV[4];
  v[13] = S->t[1] ^ blake2b_IV[5];
  v[14] = S->f[0] ^ blake2b_IV[6];
  v[15] = S->f[1] ^ blake2b_IV[7];
#define G(r,i,a,b,c,d) \
  do { \
    a = a + b + m[blake2b_sigma[r][2*i+0]]; \
    d = rotr64(d ^ a, 32); \
    c = c + d; \
    b = rotr64(b ^ c, 24); \
    a = a + b + m[blake2b_sigma[r][2*i+1]]; \
    d = rotr64(d ^ a, 16); \
    c = c + d; \
    b = rotr64(b ^ c, 63); \
  } while(0)
#define ROUND(r)  \
  do { \
    G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
    G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
    G(r,2,v[ 2],v[ 6],v[10],v[14]); \
    G(r,3,v[ 3],v[ 7],v[11],v[15]); \
    G(r,4,v[ 0],v[ 5],v[10],v[15]); \
    G(r,5,v[ 1],v[ 6],v[11],v[12]); \
    G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
    G(r,7,v[ 3],v[ 4],v[ 9],v[14]); \
  } while(0)
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
  ROUND( 10 );
  ROUND( 11 );

  for( i = 0; i < 8; ++i )
    S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];

#undef G
#undef ROUND
  return 0;
}
*/

/* inlen now in bytes */
int blake2b_update( blake2b_state *S, const uint8_t *in, uint64_t inlen )
{
  while( inlen > 0 )
  {
    size_t left = S->buflen;
    size_t fill = 2 * BLAKE2B_BLOCKBYTES - left;

    if( inlen > fill )
    {
      memcpy( S->buf + left, in, fill ); // Fill buffer
      S->buflen += fill;
      blake2b_increment_counter( S, BLAKE2B_BLOCKBYTES );
      blake2b_compress( S, S->buf ); // Compress
      memcpy( S->buf, S->buf + BLAKE2B_BLOCKBYTES, BLAKE2B_BLOCKBYTES ); // Shift buffer left
      S->buflen -= BLAKE2B_BLOCKBYTES;
      in += fill;
      inlen -= fill;
    }
    else // inlen <= fill
    {
      memcpy( S->buf + left, in, inlen );
      S->buflen += inlen; // Be lazy, do not compress
      in += inlen;
      inlen -= inlen;
    }
  }

  return 0;
}

/* Is this correct? */
int blake2b_final( blake2b_state *S, uint8_t *out, uint8_t outlen )
{
  uint8_t buffer[BLAKE2B_OUTBYTES];

  if( S->buflen > BLAKE2B_BLOCKBYTES )
  {
    blake2b_increment_counter( S, BLAKE2B_BLOCKBYTES );
    blake2b_compress( S, S->buf );
    S->buflen -= BLAKE2B_BLOCKBYTES;
    memcpy( S->buf, S->buf + BLAKE2B_BLOCKBYTES, S->buflen );
  }

  blake2b_increment_counter( S, S->buflen );
  blake2b_set_lastblock( S );
  memset( S->buf + S->buflen, 0, 2 * BLAKE2B_BLOCKBYTES - S->buflen ); /* Padding */
  blake2b_compress( S, S->buf );

  for( int i = 0; i < 8; ++i ) /* Output full hash to temp buffer */
    store64( buffer + sizeof( S->h[i] ) * i, S->h[i] );

  memcpy( out, buffer, outlen );
  return 0;
}

/* inlen, at least, should be uint64_t. Others can be size_t. */
int blake2b( uint8_t *out, const void *in, const void *key, const uint8_t outlen, const uint64_t inlen, uint8_t keylen )
{
  blake2b_state S[1];

  /* Verify parameters */
  if ( NULL == in ) return -1;

  if ( NULL == out ) return -1;

  if( NULL == key ) keylen = 0;

  if( keylen > 0 )
  {
    if( blake2b_init_key( S, outlen, key, keylen ) < 0 ) return -1;
  }
  else
  {
    if( blake2b_init( S, outlen ) < 0 ) return -1;
  }

  blake2b_update( S, ( uint8_t * )in, inlen );
  blake2b_final( S, out, outlen );
  return 0;
}

#if defined(BLAKE2B_SELFTEST)
#include <string.h>
#include "blake2-kat.h"
int main( int argc, char **argv )
{
  uint8_t key[BLAKE2B_KEYBYTES];
  uint8_t buf[KAT_LENGTH];

  for( size_t i = 0; i < BLAKE2B_KEYBYTES; ++i )
    key[i] = ( uint8_t )i;

  for( size_t i = 0; i < KAT_LENGTH; ++i )
    buf[i] = ( uint8_t )i;

  for( size_t i = 0; i < KAT_LENGTH; ++i )
  {
    uint8_t hash[BLAKE2B_OUTBYTES];
    blake2b( hash, buf, key, BLAKE2B_OUTBYTES, i, BLAKE2B_KEYBYTES );

    if( 0 != memcmp( hash, blake2b_keyed_kat[i], BLAKE2B_OUTBYTES ) )
    {
      puts( "error" );
      return -1;
    }
  }

  puts( "ok" );
  return 0;
}
#endif

