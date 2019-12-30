////////////////////////////////////////////////////////////////
//////////////// Bijective MAC Time Stamped Test ///////////////
////////////////            bMAC_TS                   //////////
///////////////  For Arduino Nano ATmega 328          //////////
////////////////////////////////////////////////////////////////

/* Copyright (C) 2019 Pascal Urien (pascal.urien@gmail.com)
 * All rights reserved.
 * 
*/

// Arduino Nano
// Processor: ATmega328
// Clock=16MHz 32KB Flash (2KB bootloader), 2KB SRAM, 1KB EEPROM

// #define  SERIAL_RX_BUFFER_SIZE    16
// #define  SERIAL_TX_BUFFER_SIZE    16
// C:\arduino\arduino-1.6.11\hardware\arduino\avr\cores\arduino\HardwareSerial.h

#include <Arduino.h>
#include <EEPROM.h>

////////////////////////////////////////////////////////////////////
// unused FLASH memory SHOULD be filled by pseudo random values
///////////////////////////////////////////////////////////////////

// stack = 2142
// heap  = 1060

#define NPERM 1
#define NPERM2 2*NPERM

#define EEPROM_SIZE  1024
#define REG_SIZE      256
#define SRAM_SIZE    2048
#define FLASH_SIZE  32768

#define FREE_MEM_SIZE 800

// 35840 = (32+2+1) *1024
// 33792 + 220 + 800 = 34812

#define PRIME   35879  // SAFE PRIME
#define Q       17939 //  SOPHIE GERMAIN PRIME PRIME=2Q+1
// PRIME mod 8 = 7
// in Z/pZ*, q-1 generators, g= p - ((2**k) mod p), k from 1 to q-1

// number of bits for generators
#define NBITS 16
// Address Range  16 bits
#define USHORT uint16_t 
// Computing Range 2x16 = 32bits
#define ULONG  uint32_t

/*
 * keccak code
 * From https://github.com/brainhub/SHA3IUF/, Aug 2015. Andrey Jivsov. crypto@brainhub.org
 * Based on code from http://keccak.noekeon.org/ .
 * Adapted to AVR by Pascal Urien
 */

/* 'Words' here refers to uint64_t   200 bytes */
#define SHA3_KECCAK_SPONGE_WORDS \
  (((1600)/8/*bits to byte*/)/sizeof(uint64_t))

typedef struct sha3_context_ {
  uint64_t saved;             /* the portion of the input message that we didn't consume yet */
  union 
  {  /* Keccak's state */
    uint64_t s[SHA3_KECCAK_SPONGE_WORDS];
    uint8_t sb[SHA3_KECCAK_SPONGE_WORDS * 8]; // => digest 200 octets
  };
  uint32_t  byteIndex;         /* 0..7--the next byte after the set one
                                   (starts from 0; 0--none are buffered) */
  uint32_t wordIndex;         /* 0..24--the next word to integrate input
                                   (starts from 0) */
  uint32_t capacityWords;     /* the double size of the hash output in
                                   words (e.g. 16 for Keccak 512) */
} sha3_context;

typedef union hdata_ {
  sha3_context sha3; // 220 bytes
  struct
  { char prefix[8] ;
    char digest[32 ];
    char mybuf[168] ;
    uint16_t code[6];
  } buf; // 220 bytes
} hdata;


/* generally called after SHA3_KECCAK_SPONGE_WORDS-ctx->capacityWords words
   are XORed into the state s
*/
void keccakf(uint64_t s[25]);
void sha3_Init256(sha3_context * priv);
void sha3_Update(sha3_context *priv, void const *bufIn, size_t len);
void const * sha3_Finalize(sha3_context * priv);


union    
{
  uint32_t v32    ;
  uint16_t v16[2] ;
  uint8_t  v8[4]  ;
} time1;


uint32_t gettime1()
{ uint16_t v16 ;

  v16 = TCNT1  ;

  if (v16 < time1.v16[0])
    time1.v16[1] += 1 ;

  time1.v16[0] = v16;

  return time1.v32;
}


void delay1(uint32_t adelay)
{
  if (adelay == 0)
  {
    time1.v32= 0 ;
    TCCR1A  = 0  ;
    TCCR1B  = 0  ;
    TCNT1   = 0xFFF0  ; // wait 16*4=64 us
    TCCR1B |=  3 ; // prescale 64

    while (TCNT1 != 0);
    return ;
  }

  uint32_t v32 = gettime1();

  while (true)
  {
    uint32_t t32 = gettime1() ;
    if ((t32 - v32) >= adelay)
      break;
  }
}


hdata cs  ; // 220 octets

/*
  The free list structure as maintained by the
  avr-libc memory allocation routines.
*/

struct __freelist {
  size_t sz;
  struct __freelist *nx;
};

/* The head of the free list structure */
extern struct __freelist *__flp;
extern int __heap_start, *__brkval;

// in hardware/cores/arduino/wiring.c
extern unsigned long timer0_overflow_count ;
extern unsigned long timer0_millis ;
extern unsigned long timer0_fract  ;


typedef  union  ui16_
{ uint16_t v  ;
  uint8_t b[2];
} ui16 ;


typedef  union  ui32_
{ uint32_t v   ;
  uint8_t b[4] ;
} ui32 ;

#define cbi(sfr, bit) (_SFR_BYTE(sfr) &= ~_BV(bit))
#define sbi(sfr, bit) (_SFR_BYTE(sfr) |= _BV(bit))

/////////////////////////////
// Returns Stack Pointer   //
/////////////////////////////

uint16_t getstack(void)
{ char c;
  return (uint16_t)&c ;
}


void setup()
{
  uint8_t   buf[1] ;
  USHORT v         ;
  USHORT kv=0      ;
  ULONG  kq[NPERM2] ;
  ULONG  g[NPERM2]  ;
  ULONG  p2[NBITS] ;
  ULONG  gi[NBITS] ;
  USHORT skey[NPERM2];
  ULONG  x, y, bitn  ;
  int32_t a =  16807, m = 2147483647, q = 127773, r = 2836 , seed = 1234, hi = 0, lo = 0, test = 0;
  uint8_t * ptsram = NULL ;
  bool      tohash = false;
  uint32_t tt = 0 ;
  USHORT i = 0    ;
  struct
  {
    uint16_t  m_begin = 0;
    uint16_t   m_end  = 0;
  }
  sctx;
  uint16_t  s_end = 0  ;

 
  ///////////////////////////////////////////////////////////////////////
  cbi (TIMSK0, TOIE0); // disable Timer0 !!! delay() is now not available
  ///////////////////////////////////////////////////////////////////////

  ///////////////////////////
  // power of 2 modulo PRIME
  ///////////////////////////
  p2[0] = 2;
  for (uint8_t n = 1; n <= (NBITS-1); n++)
    p2[n] = (p2[n - 1] * p2[n - 1]) % ((ULONG)PRIME);

  ////////////////
  noInterrupts();
  ///////////////

  s_end = getstack()   ;
  sctx.m_begin        =  (uint16_t)&__heap_start;
  sctx.m_end          =  (uint16_t)&__heap_start + (uint16_t)FREE_MEM_SIZE  ;

  bool cfirst = true;

cloop:

  ////////////////
  noInterrupts();
  ///////////////


  // Stephen K.Park and Keith W.Miller
  // Random Numbers Generators: Good Ones Are Hard to Find
  // Communication of ACM October 1998, Volume 31, Number 10, pp1192-1201
  //
  // Fill free SRAM with pseudo random value
  // compute skey and kq pseudo random values


  //if (cfirst)
  {
  
  for (uint16_t ii = sctx.m_begin ; ii < (sctx.m_end + 4*NPERM) ; ii++)
  { hi = seed  / q ;
    lo = seed  % q ;
    test = a * lo - r * hi;
    if (test > 0) seed = test ;
    else          seed = test + m ;

    if (ii < sctx.m_end)
    {
      if (cfirst)
        *((char*)ii) = seed & 0xFF ;
    }

    else if ( (ii - sctx.m_end) < NPERM2 )
      kq[ii - sctx.m_end]=   (ULONG)(1 + (seed % (int32_t)(Q - 1))) ;
   
    else
      skey[ii - sctx.m_end - NPERM2]=   (USHORT)(1 + (seed % (int32_t)(PRIME - 1))) ;
 
  }
  }
  

  cfirst = false ;

  for (uint8_t j=0;j<NPERM2;j++)
  {
    //computute  2**kq mod PRIME
    bitn = kq[j];
    y = 1;
    for (uint8_t n = 1; n <= NBITS; n++)
    { if ( (bitn & 0x1) == 0x1)  y = (y * p2[n - 1]) % (ULONG)PRIME;
      bitn = bitn >> 1;
    }

    // g = PRIME - (2**kq mod PRIME)
    g[j] = y ;
    g[j] = (ULONG)PRIME - y ;
  }


  //////////////////////////
  delay1(0); // init timer1
  //////////////////////////

  sha3_Init256(&cs.sha3);

  kv = 0;
  
  for (uint8_t j = 0; j <NPERM; j++)
  {
    x = (ULONG)skey[2*j+1];

    gi[0] = g[2*j]; // G2j
    // compute square power of G2j
    for ( uint8_t n = 1; n <= (NBITS-1); n++)
      gi[n] = (gi[n - 1] * gi[n - 1]) % (ULONG)PRIME;

    for ( i = 1; i < (USHORT)PRIME; i++)
    { tohash = false;

      x = (x * g[2*j + 1]) % (ULONG)PRIME; // G2j+1
      bitn = x;
      y = 1;

      for (uint8_t n = 1; n <= NBITS; n++)
      { if ( (bitn & 0x1) == 0x1)  y = (y * gi[n - 1]) % (ULONG)PRIME;
        bitn = bitn >> 1;
      }

      v = (USHORT)(y - 1);

      if (v < FLASH_SIZE)
      { tohash = true;
        buf[0] = pgm_read_byte_near(v);
      }

      else if ( (v >= FLASH_SIZE) &&  (v < (FLASH_SIZE+SRAM_SIZE)) )
      {
        v = v - FLASH_SIZE + REG_SIZE ;
        if (  ( ((uint16_t)v >=  sctx.m_begin) && ((uint16_t)v < sctx.m_end))  || ( ((uint16_t)v >= (uint16_t)&cs) && ((uint16_t)v < ((uint16_t)&cs + (uint16_t)sizeof(cs)))) )
        { tohash = true   ;
          ptsram =  (uint16_t)v ;
          buf[0] = *ptsram ;
        }
      }

      else if ( (v >= (FLASH_SIZE+SRAM_SIZE)) && (v < (FLASH_SIZE+SRAM_SIZE+EEPROM_SIZE)) )
      {
        v -= (FLASH_SIZE+SRAM_SIZE); 
        tohash = true;
        buf[0] = EEPROM.read((uint16_t)v);
      }



      if (tohash)
      { sha3_Update(&cs.sha3, buf, 1);
        kv++;
      }

      ///////////////
      tt = gettime1();
      ///////////////

    }

  }

  sha3_Finalize(&cs.sha3) ;

  tt = gettime1();

  ///////////////
   interrupts();
  ///////////////

  Serial.begin(19200);

  Serial.println("OK");
  Serial.print("heap= ");
  Serial.println(sctx.m_begin); // Heap
  Serial.print("stack= ");
  Serial.println(s_end);        //Stack
  Serial.print("nvalue= ");Serial.print(" (should be "); Serial.print(FLASH_SIZE+EEPROM_SIZE+FREE_MEM_SIZE+sizeof(cs));Serial.println(")");
  Serial.println(kv); 
  Serial.println("Generators:");
  for ( uint8_t ii = 0; ii < NPERM2; ii++)
    Serial.println(g[ii]);      // Generators gi
  Serial.println("s values:");  
  for ( uint8_t ii= 0; ii < NPERM2; ii++)
    Serial.println(skey[ii]);   // skey values
  Serial.println("Generator exponents:");    
  for ( uint8_t ii = 0; ii < NPERM2; ii++)
  Serial.println(kq[ii]);  // generators exponent values


  Serial.println("bMAC:");
  bin2ascii(cs.buf.digest, 32, cs.buf.mybuf);
  Serial.println(cs.buf.mybuf) ;
  Serial.println("Computing time: (unit=4us= 64/16MHz)");
  Serial.println(tt);
  Serial.print(tt*4); Serial.println(" us");
 
  for(uint8_t ii=0;ii<4;ii++)
  cs.buf.digest[31-ii] ^= ((ui32 *)&tt)->b[ii];
  Serial.println("bMAC_TS:");
  bin2ascii(cs.buf.digest, 32, cs.buf.mybuf);
  Serial.println(cs.buf.mybuf) ;
  

  Serial.end();

  goto cloop;

}


void loop()
{
}


#define SHA3_ASSERT( x )
#define SHA3_USE_KECCAK
#define SHA3_CONST(x) x

#ifndef SHA3_ROTL64
#define SHA3_ROTL64(x, y) \
  (((x) << (y)) | ((x) >> ((sizeof(uint64_t)*8) - (y))))
#endif

#define KECCAK_ROUNDS 24



// https://www.arduino.cc/reference/en/language/variables/utilities/progmem/
// The following code WILL work, even if locally defined within a function:
// const static char long_str[] PROGMEM = "Hi, I would like to tell you a bit about myself.\n"

const static uint64_t keccakf_rndc[] PROGMEM = {
  SHA3_CONST(0x0000000000000001UL), SHA3_CONST(0x0000000000008082UL),
  SHA3_CONST(0x800000000000808aUL), SHA3_CONST(0x8000000080008000UL),
  SHA3_CONST(0x000000000000808bUL), SHA3_CONST(0x0000000080000001UL),
  SHA3_CONST(0x8000000080008081UL), SHA3_CONST(0x8000000000008009UL),
  SHA3_CONST(0x000000000000008aUL), SHA3_CONST(0x0000000000000088UL),
  SHA3_CONST(0x0000000080008009UL), SHA3_CONST(0x000000008000000aUL),
  SHA3_CONST(0x000000008000808bUL), SHA3_CONST(0x800000000000008bUL),
  SHA3_CONST(0x8000000000008089UL), SHA3_CONST(0x8000000000008003UL),
  SHA3_CONST(0x8000000000008002UL), SHA3_CONST(0x8000000000000080UL),
  SHA3_CONST(0x000000000000800aUL), SHA3_CONST(0x800000008000000aUL),
  SHA3_CONST(0x8000000080008081UL), SHA3_CONST(0x8000000000008080UL),
  SHA3_CONST(0x0000000080000001UL), SHA3_CONST(0x8000000080008008UL)
};

const static uint8_t  keccakf_rotc[KECCAK_ROUNDS] PROGMEM = {
  1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62,
  18, 39, 61, 20, 44
};

const static uint8_t  keccakf_piln[KECCAK_ROUNDS] PROGMEM = {
  10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20,
  14, 22, 9, 6, 1
};


void keccakf(uint64_t s[25])
{
  int i, j, round    ;
  uint64_t t, bc[5], v;

  for (round = 0; round < KECCAK_ROUNDS; round++) {

    /* Theta */
    for (i = 0; i < 5; i++)
      bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];

    for (i = 0; i < 5; i++) {
      t = bc[(i + 4) % 5] ^ SHA3_ROTL64(bc[(i + 1) % 5], 1);
      for (j = 0; j < 25; j += 5)
        s[j + i] ^= t;
    }

    /* Rho Pi */
    t = s[1];
    for (i = 0; i < 24; i++) {
      j = pgm_read_byte(keccakf_piln + i);
      bc[0] = s[j];
      s[j] = SHA3_ROTL64(t, pgm_read_byte(keccakf_rotc + i));
      t = bc[0];
    }

    /* Chi */
    for (j = 0; j < 25; j += 5) {
      for (i = 0; i < 5; i++)
        bc[i] = s[j + i];
      for (i = 0; i < 5; i++)
        s[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
    }

    /* Iota */
    //s[0] ^= keccakf_rndc[round];
    memcpy_P(&v, keccakf_rndc + round, 8);
    s[0] ^=  v ;


  }
}

/* *************************** Public Inteface ************************ */

/* For Init or Reset call these: */
void sha3_Init256(sha3_context * priv)
{
  sha3_context *ctx = (sha3_context *) priv;
  memset(ctx, 0, sizeof(*ctx));
  ctx->capacityWords = 2 * 256 / (8 * sizeof(uint64_t));
}

void sha3_Update(sha3_context *priv, void const *bufIn, size_t len)
{
  sha3_context *ctx = (sha3_context *) priv;

  /* 0...7 -- how much is needed to have a word */
  unsigned int old_tail = (8 - ctx->byteIndex) & 7;

  size_t words;
  unsigned int tail;
  size_t i;

  const uint8_t *buf = bufIn;

  SHA3_ASSERT(ctx->byteIndex < 8);
  SHA3_ASSERT(ctx->wordIndex < sizeof(ctx->s) / sizeof(ctx->s[0]));

  if (len < old_tail) {
    /* have no complete word or haven't started
                                   the word yet */
    // SHA3_TRACE("because %d<%d, store it and return", (unsigned)len,(unsigned)old_tail);
    /* endian-independent code follows: */

    while (len--)
      ctx->saved |= (uint64_t) (*(buf++)) << ((ctx->byteIndex++) * 8);
    SHA3_ASSERT(ctx->byteIndex < 8);
    return;
  }

  if (old_tail) {             /* will have one word to process */
    // SHA3_TRACE("completing one word with %d bytes", (unsigned)old_tail);
    /* endian-independent code follows: */
    len -= old_tail;
    while (old_tail--)
      ctx->saved |= (uint64_t) (*(buf++)) << ((ctx->byteIndex++) * 8);

    /* now ready to add saved to the sponge */
    ctx->s[ctx->wordIndex] ^= ctx->saved;
    SHA3_ASSERT(ctx->byteIndex == 8);
    ctx->byteIndex = 0;
    ctx->saved = 0;
    if (++ctx->wordIndex ==
        (SHA3_KECCAK_SPONGE_WORDS - ctx->capacityWords)) {
      keccakf(ctx->s);
      ctx->wordIndex = 0;
    }
  }

  /* now work in full words directly from input */

  SHA3_ASSERT(ctx->byteIndex == 0);

  words = len / sizeof(uint64_t);
  tail = (uint32_t)(len - words * sizeof(uint64_t));

  for (i = 0; i < words; i++, buf += sizeof(uint64_t)) {
    const uint64_t t = (uint64_t) (buf[0]) |
                       ((uint64_t) (buf[1]) << 8 * 1) |
                       ((uint64_t) (buf[2]) << 8 * 2) |
                       ((uint64_t) (buf[3]) << 8 * 3) |
                       ((uint64_t) (buf[4]) << 8 * 4) |
                       ((uint64_t) (buf[5]) << 8 * 5) |
                       ((uint64_t) (buf[6]) << 8 * 6) |
                       ((uint64_t) (buf[7]) << 8 * 7);
#if defined(__x86_64__ ) || defined(__i386__)
    SHA3_ASSERT(memcmp(&t, buf, 8) == 0);
#endif
    ctx->s[ctx->wordIndex] ^= t;
    if (++ctx->wordIndex ==
        (SHA3_KECCAK_SPONGE_WORDS - ctx->capacityWords)) {
      keccakf(ctx->s);
      ctx->wordIndex = 0;
    }
  }

  // SHA3_TRACE("have %d bytes left to process, save them", (unsigned)tail);

  /* finally, save the partial word */
  SHA3_ASSERT(ctx->byteIndex == 0 && tail < 8);
  while (tail--) {
    // SHA3_TRACE("Store byte %02x '%c'", *buf, *buf);
    ctx->saved |= (uint64_t) (*(buf++)) << ((ctx->byteIndex++) * 8);
  }
  SHA3_ASSERT(ctx->byteIndex < 8);
  // SHA3_TRACE("Have saved=0x%016" PRIx64 " at the end", ctx->saved);
}



void const * sha3_Finalize(sha3_context * priv)
{
  sha3_context *ctx = (sha3_context *) priv;

  // SHA3_TRACE("called with %d bytes in the buffer", ctx->byteIndex);

  /* Append 2-bit suffix 01, per SHA-3 spec. Instead of 1 for padding we
     use 1<<2 below. The 0x02 below corresponds to the suffix 01.
     Overall, we feed 0, then 1, and finally 1 to start padding. Without
     M || 01, we would simply use 1 to start padding. */


  /* For testing the "pure" Keccak version */
  ctx->s[ctx->wordIndex] ^=
    (ctx->saved ^ ((uint64_t) ((uint64_t) 1 << (ctx->byteIndex * 8))));

  ctx->s[SHA3_KECCAK_SPONGE_WORDS - ctx->capacityWords - 1] ^=
    SHA3_CONST(0x8000000000000000UL);
  keccakf(ctx->s);

  /* Return first bytes of the ctx->s.
     This conversion is not needed for little-endian platforms */

  /*
      uint32_t  i;
      for(i = 0; i < SHA3_KECCAK_SPONGE_WORDS; i++) {
          const uint32_t  t1 = (uint32_t) ctx->s[i];
          const uint32_t  t2 = (uint32_t) ((ctx->s[i] >> 16) >> 16);
          ctx->sb[i * 8 + 0] = (uint8_t) (t1);
          ctx->sb[i * 8 + 1] = (uint8_t) (t1 >> 8);
          ctx->sb[i * 8 + 2] = (uint8_t) (t1 >> 16);
          ctx->sb[i * 8 + 3] = (uint8_t) (t1 >> 24);
          ctx->sb[i * 8 + 4] = (uint8_t) (t2);
          ctx->sb[i * 8 + 5] = (uint8_t) (t2 >> 8);
          ctx->sb[i * 8 + 6] = (uint8_t) (t2 >> 16);
          ctx->sb[i * 8 + 7] = (uint8_t) (t2 >> 24);
  */


  return (ctx->sb);
}


void bin2ascii(char *bin, int len, char *buffer)
{
  for (int i = 0; i < len; i++)
  {
    char nib1 = (bin[i] >> 4) & 0x0F;
    char nib2 = (bin[i] >> 0) & 0x0F;
    buffer[i * 2 + 0] = nib1  < 0xA ? '0' + nib1  : 'a' + nib1  - 0xA;
    buffer[i * 2 + 1] = nib2  < 0xA ? '0' + nib2  : 'a' + nib2  - 0xA;
  }
  buffer[len * 2] = '\0';
}




