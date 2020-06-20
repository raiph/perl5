#ifndef CHASKEY_HASH_H
#define CHASKEY_HASH_H

/*
   Chaskey reference C implementation (portable implementation)

   Written in 2015 by Nicky Mouha, based on SipHash

   To the extent possible under law, the author has dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

   This version was derived from https://mouha.be/wp-content/uploads/chaskey-portable.c
   it was modified only to follow perl build conventions, and to add namespace prefixes.
*/

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>


#define CHASKEY_ROUND \
  do { \
    v[0] += v[1]; v[1]=ROTL32(v[1], 5); v[1] ^= v[0]; v[0]=ROTL32(v[0],16); \
    v[2] += v[3]; v[3]=ROTL32(v[3], 8); v[3] ^= v[2]; \
    v[0] += v[3]; v[3]=ROTL32(v[3],13); v[3] ^= v[0]; \
    v[2] += v[1]; v[1]=ROTL32(v[1], 7); v[1] ^= v[2]; v[2]=ROTL32(v[2],16); \
  } while(0)
  
#define CHASKEY_PERMUTE \
  CHASKEY_ROUND; \
  CHASKEY_ROUND; \
  CHASKEY_ROUND; \
  CHASKEY_ROUND; \
  CHASKEY_ROUND; \
  CHASKEY_ROUND; \
  CHASKEY_ROUND; \
  CHASKEY_ROUND;

#define CHASKEY_TIMESTWO(out,in) \
  STMT_START { \
    out[0] = (in[0] << 1) ^ (in[3] >> 31 ? 0x87 : 0x00); \
    out[1] = (in[1] << 1) | (in[0] >> 31); \
    out[2] = (in[2] << 1) | (in[1] >> 31); \
    out[3] = (in[3] << 1) | (in[2] >> 31); \
  } STMT_END
    
PERL_STATIC_INLINE void
chaskey_seed_state ( const U8 *seed_ch, U8 *state_ch ) {
    U32 *k= (U32 *)seed_ch;
    U32 *k1= k+4; 
    U32 *k2= k1+4;

    k[0]= U8TO32_LE(state_ch);
    k[1]= U8TO32_LE(state_ch+4);
    k[2]= U8TO32_LE(state_ch+8);
    k[3]= U8TO32_LE(state_ch+12);
    CHASKEY_TIMESTWO(k1,k);
    CHASKEY_TIMESTWO(k2,k1);
}


PERL_STATIC_INLINE U32 
chaskey_hash_with_state(const U8 *state, const U8 *m, const U32 mlen) {
  U32 *k= (U32 *)state;
  U32 *k1= k+4;
  U32 *k2= k1+4;

  U32 b = 0;
  const U32 *l;
  U32 v[4] = { k[0], k[1], k[2], k[3] };
  
  const U8 *end = (mlen == 0) ? m : m + ((mlen-1) & 0xFFFFFFF0); /* pointer to last message block */
  const int left = (mlen == 0) ? 0 : ((mlen-1) & 0xF) + 1;

  for (; m != end; m += 16) {
#ifdef DEBUG
    printf("(%3d) v[0] %08X\n", mlen, v[0]);
    printf("(%3d) v[1] %08X\n", mlen, v[1]);
    printf("(%3d) v[2] %08X\n", mlen, v[2]);
    printf("(%3d) v[3] %08X\n", mlen, v[3]);
    printf("(%3d) compress %08X %08X %08X %08X\n", mlen, U8TO32_LE(m), U8TO32_LE(m+4), U8TO32_LE(m+8), U8TO32_LE(m+12));
#endif
    v[0] ^= U8TO32_LE(m     );
    v[1] ^= U8TO32_LE(m +  4);
    v[2] ^= U8TO32_LE(m +  8);
    v[3] ^= U8TO32_LE(m + 12);
    CHASKEY_PERMUTE;
  }
  
#define CHASKEY_PAD32(array,idx,num) ((num == idx) ? (( U32 ) 0x01) : (( U32 ) array[idx]))
  switch(left) {
    case 16:; /* FALLTHROUGH */
    case 15: b |= CHASKEY_PAD32(m,15,left) << 24;           /* FALLTHROUGH */
    case 14: b |= CHASKEY_PAD32(m,14,left) << 16;           /* FALLTHROUGH */
    case 13: b |= CHASKEY_PAD32(m,13,left) <<  8;           /* FALLTHROUGH */
    case 12: b |= CHASKEY_PAD32(m,12,left); v[3] ^= b; b=0; /* FALLTHROUGH */
    case 11: b |= CHASKEY_PAD32(m,11,left) << 24;           /* FALLTHROUGH */
    case 10: b |= CHASKEY_PAD32(m,10,left) << 16;           /* FALLTHROUGH */
    case  9: b |= CHASKEY_PAD32(m, 9,left) <<  8;           /* FALLTHROUGH */
    case  8: b |= CHASKEY_PAD32(m, 8,left); v[2] ^= b; b=0; /* FALLTHROUGH */
    case  7: b |= CHASKEY_PAD32(m, 7,left) << 24;           /* FALLTHROUGH */
    case  6: b |= CHASKEY_PAD32(m, 6,left) << 16;           /* FALLTHROUGH */
    case  5: b |= CHASKEY_PAD32(m, 5,left) <<  8;           /* FALLTHROUGH */
    case  4: b |= CHASKEY_PAD32(m, 4,left); v[1] ^= b; b=0; /* FALLTHROUGH */
    case  3: b |= CHASKEY_PAD32(m, 3,left) << 24;           /* FALLTHROUGH */
    case  2: b |= CHASKEY_PAD32(m, 2,left) << 16;           /* FALLTHROUGH */
    case  1: b |= CHASKEY_PAD32(m, 1,left) <<  8;           /* FALLTHROUGH */
    case  0: b |= CHASKEY_PAD32(m, 0,left); v[0] ^= b; b=0; /* FALLTHROUGH */
  }

  if ((mlen != 0) && ((mlen & 0xF) == 0)) {
    l = k1;
  } else {
    l = k2;
  }

#ifdef DEBUG
  printf("(%3d) v[0] %08X\n", mlen, v[0]);
  printf("(%3d) v[1] %08X\n", mlen, v[1]);
  printf("(%3d) v[2] %08X\n", mlen, v[2]);
  printf("(%3d) v[3] %08X\n", mlen, v[3]);
  printf("(%3d) last block\n", mlen);
#endif

  v[0] ^= l[0];
  v[1] ^= l[1];
  v[2] ^= l[2];
  v[3] ^= l[3];

  CHASKEY_PERMUTE;

#ifdef DEBUG
  printf("(%3d) v[0] %08X\n", mlen, v[0]);
  printf("(%3d) v[1] %08X\n", mlen, v[1]);
  printf("(%3d) v[2] %08X\n", mlen, v[2]);
  printf("(%3d) v[3] %08X\n", mlen, v[3]);
#endif

  v[0] ^= l[0];
  v[1] ^= l[1];
  v[2] ^= l[2];
  v[3] ^= l[3];

  return v[0];
}

#endif /* CHASKEY_HASH_H */
