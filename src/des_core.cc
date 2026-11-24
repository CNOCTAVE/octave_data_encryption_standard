// Copyright (C) 2026 Yu Hongbo <yuhongbo@member.fsf.org>, CNOCTAVE
// SPDX-License-Identifier: GPL-3.0-or-later
//
// des_core.cc -- DES / 3DES primitives for octave_data_encryption_standard.
//
// Two bit-order variants are provided:
//   "standard" -- FIPS 46-3, MSB-first bit numbering.
//   "qqmusic"  -- the private bit order used by QQMusic / LyricTools.exe.
//                 This is the variant required by the QRC example.
//
// Build (Linux, normal mkoctfile linking):
//   mkoctfile --mex?  NO -- use:  mkoctfile -lz des_core.cc -o des_core.oct
// Build (Windows Octave 11):
//   mkoctfile -lz des_core.cc -o des_core.oct

#include <octave/oct.h>
#include <octave/octave.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include <zlib.h>

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
static std::vector<uint8_t> to_bytes (const octave_value& v, const char* name)
{
  if (! v.isnumeric ())
    error ("%s: numeric vector expected", name);

  if (v.is_uint8_type ())
    {
      uint8NDArray a = v.uint8_array_value ();
      std::vector<uint8_t> out;
      out.reserve (a.numel ());
      for (octave_idx_type i = 0; i < a.numel (); i++)
        out.push_back (static_cast<uint8_t> (a.elem (i)));
      return out;
    }

  NDArray a = v.array_value ();
  std::vector<uint8_t> out;
  out.reserve (a.numel ());
  for (octave_idx_type i = 0; i < a.numel (); i++)
    {
      double d = a.elem (i);
      if (! (d >= 0 && d <= 255 && d == std::floor (d)))
        error ("%s: values must be integers in [0,255]", name);
      out.push_back (static_cast<uint8_t> (d));
    }
  return out;
}

static octave_value bytes_to_ov (const std::vector<uint8_t>& b)
{
  uint8NDArray a (dim_vector (1, static_cast<octave_idx_type> (b.size ())));
  for (size_t i = 0; i < b.size (); i++)
    a.elem (i) = b[i];
  return octave_value (a);
}

static bool decrypt_flag (const octave_value& v, const char* name)
{
  if (v.islogical () || v.isnumeric ())
    {
      double d = v.scalar_value ();
      if (d != 0 && d != 1)
        error ("%s: direction must be 0 (decrypt) or 1 (encrypt)", name);
      return d == 0;
    }
  std::string s = v.string_value ();
  if (s == "decrypt" || s == "D" || s == "d")
    return true;
  if (s == "encrypt" || s == "E" || s == "e")
    return false;
  error ("%s: unknown direction '%s'", name, s.c_str ());
  return false;
}

static bool qq_flag (const octave_value& v)
{
  if (v.isnumeric () || v.islogical ())
    return v.scalar_value () == 0;
  std::string s = v.string_value ();
  return (s == "qqmusic" || s == "private" || s == "qq");
}

// ===========================================================================
// Standard DES (FIPS 46-3)
// ===========================================================================
namespace std_des
{
  static const int IP[] = {
    58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1, 59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7
  };
  static const int FP[] = {
    40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26, 33,1,41,9,49,17,57,25
  };
  static const int E[] = {
    32,1,2,3,4,5, 4,5,6,7,8,9, 8,9,10,11,12,13,
    12,13,14,15,16,17, 16,17,18,19,20,21, 20,21,22,23,24,25,
    24,25,26,27,28,29, 28,29,30,31,32,1
  };
  static const int P[] = {
    16,7,20,21, 29,12,28,17, 1,15,23,26, 5,18,31,10,
    2,8,24,14, 32,27,3,9, 19,13,30,6, 22,11,4,25
  };
  static const int PC1[] = {
    57,49,41,33,25,17,9, 1,58,50,42,34,26,18,
    10,2,59,51,43,35,27, 19,11,3,60,52,44,36,
    63,55,47,39,31,23,15, 7,62,54,46,38,30,22,
    14,6,61,53,45,37,29, 21,13,5,28,20,12,4
  };
  static const int PC2[] = {
    14,17,11,24,1,5, 3,28,15,6,21,10,
    23,19,12,4,26,8, 16,7,27,20,13,2,
    41,52,31,37,47,55, 30,40,51,45,33,48,
    44,49,39,56,34,53, 46,42,50,36,29,32
  };
  static const int SHIFT[] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
  static const uint8_t S[8][64] = {
    {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7, 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
     4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0, 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13},
    {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10, 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
     0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15, 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9},
    {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8, 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
     13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7, 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12},
    {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15, 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
     10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4, 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14},
    {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9, 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
     4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14, 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3},
    {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11, 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
     9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6, 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13},
    {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1, 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
     1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2, 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12},
    {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7, 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
     7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8, 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
  };

  static uint64_t permute (uint64_t in, const int* tbl, int n)
  {
    uint64_t out = 0;
    for (int i = 0; i < n; i++)
      {
        out <<= 1;
        out |= (in >> (64 - tbl[i])) & 1ULL;
      }
    return out;
  }

  static uint64_t pack64 (const uint8_t* b)
  {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
      v = (v << 8) | b[i];
    return v;
  }

  static void unpack64 (uint64_t v, uint8_t* b)
  {
    for (int i = 7; i >= 0; i--)
      {
        b[i] = static_cast<uint8_t> (v & 0xff);
        v >>= 8;
      }
  }

  static void schedule (const uint8_t* key8, uint64_t sub[16])
  {
    uint64_t k = permute (pack64 (key8), PC1, 56);
    uint32_t c = static_cast<uint32_t> (k >> 28);
    uint32_t d = static_cast<uint32_t> (k & 0x0fffffffULL);
    for (int i = 0; i < 16; i++)
      {
        int s = SHIFT[i];
        c = ((c << s) | (c >> (28 - s))) & 0x0fffffffU;
        d = ((d << s) | (d >> (28 - s))) & 0x0fffffffU;
        uint64_t cd = (static_cast<uint64_t> (c) << 28) | d;
        sub[i] = permute (cd << 8, PC2, 48);
      }
  }

  static uint32_t round_f (uint32_t r, uint64_t k)
  {
    uint64_t e = permute (static_cast<uint64_t> (r) << 32, E, 48) ^ k;
    uint32_t out = 0;
    for (int i = 0; i < 8; i++)
      {
        int six = static_cast<int> ((e >> (42 - 6*i)) & 0x3fULL);
        int row = ((six & 0x20) >> 4) | (six & 1);
        int col = (six >> 1) & 0x0f;
        out = (out << 4) | S[i][row*16 + col];
      }
    return static_cast<uint32_t> (permute (static_cast<uint64_t> (out) << 32, P, 32));
  }

  static void crypt (const uint8_t* in, uint8_t* out, const uint64_t sub[16], bool dec)
  {
    uint64_t ip = permute (pack64 (in), IP, 64);
    uint32_t l = static_cast<uint32_t> (ip >> 32);
    uint32_t r = static_cast<uint32_t> (ip & 0xffffffffULL);
    for (int i = 0; i < 16; i++)
      {
        uint32_t tmp = r;
        r = l ^ round_f (r, sub[dec ? 15 - i : i]);
        l = tmp;
      }
    unpack64 (permute ((static_cast<uint64_t> (r) << 32) | l, FP, 64), out);
  }
}

// ===========================================================================
// QQMusic private-bit-order DES (exact port of the verified JavaScript code)
// ===========================================================================
namespace qq_des
{
  static const uint8_t SBOX[8][64] = {
    {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7, 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
     4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0, 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13},
    {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10, 3,13,4,7,15,2,8,15,12,0,1,10,6,9,11,5,
     0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15, 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9},
    {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8, 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
     13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7, 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12},
    {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15, 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
     10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4, 3,15,0,6,10,10,13,8,9,4,5,11,12,7,2,14},
    {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9, 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
     4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14, 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3},
    {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11, 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
     9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6, 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13},
    {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1, 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
     1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2, 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12},
    {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7, 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
     7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8, 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
  };
  static const int SHIFT[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
  static const int PERM_C[28] = {
    56,48,40,32,24,16,8,0, 57,49,41,33,25,17,9,1,
    58,50,42,34,26,18,10,2, 59,51,43,35
  };
  static const int PERM_D[28] = {
    62,54,46,38,30,22,14,6, 61,53,45,37,29,21,13,5,
    60,52,44,36,28,20,12,4, 27,19,11,3
  };
  static const int COMP[48] = {
    13,16,10,23,0,4,2,27, 14,5,20,9,22,18,11,3,
    25,7,15,6,26,19,12,1, 40,51,30,36,46,54,29,39,
    50,44,32,47,43,48,38,55, 33,52,45,41,49,35,28,31
  };

  inline uint32_t bitnum (const uint8_t* a, int b, int c)
  {
    int idx = (b / 32) * 4 + 3 - ((b % 32) / 8);
    return static_cast<uint32_t> (((a[idx] >> (7 - (b % 8))) & 1) << c);
  }
  inline uint32_t bitnum_intr (uint32_t a, int b, int c)
  {
    return ((a >> (31 - b)) & 1U) << c;
  }
  inline uint32_t bitnum_intl (uint32_t a, int b, int c)
  {
    return ((a << b) & 0x80000000U) >> c;
  }
  inline int sbox_bit (uint32_t a)
  {
    return static_cast<int> ((a & 32) | ((a & 31) >> 1) | ((a & 1) << 4));
  }

  static void initial_permutation (const uint8_t* d, uint32_t& s0, uint32_t& s1)
  {
    s0 = bitnum(d,57,31)|bitnum(d,49,30)|bitnum(d,41,29)|bitnum(d,33,28)|
         bitnum(d,25,27)|bitnum(d,17,26)|bitnum(d,9,25)|bitnum(d,1,24)|
         bitnum(d,59,23)|bitnum(d,51,22)|bitnum(d,43,21)|bitnum(d,35,20)|
         bitnum(d,27,19)|bitnum(d,19,18)|bitnum(d,11,17)|bitnum(d,3,16)|
         bitnum(d,61,15)|bitnum(d,53,14)|bitnum(d,45,13)|bitnum(d,37,12)|
         bitnum(d,29,11)|bitnum(d,21,10)|bitnum(d,13,9)|bitnum(d,5,8)|
         bitnum(d,63,7)|bitnum(d,55,6)|bitnum(d,47,5)|bitnum(d,39,4)|
         bitnum(d,31,3)|bitnum(d,23,2)|bitnum(d,15,1)|bitnum(d,7,0);
    s1 = bitnum(d,56,31)|bitnum(d,48,30)|bitnum(d,40,29)|bitnum(d,32,28)|
         bitnum(d,24,27)|bitnum(d,16,26)|bitnum(d,8,25)|bitnum(d,0,24)|
         bitnum(d,58,23)|bitnum(d,50,22)|bitnum(d,42,21)|bitnum(d,34,20)|
         bitnum(d,26,19)|bitnum(d,18,18)|bitnum(d,10,17)|bitnum(d,2,16)|
         bitnum(d,60,15)|bitnum(d,52,14)|bitnum(d,44,13)|bitnum(d,36,12)|
         bitnum(d,28,11)|bitnum(d,20,10)|bitnum(d,12,9)|bitnum(d,4,8)|
         bitnum(d,62,7)|bitnum(d,54,6)|bitnum(d,46,5)|bitnum(d,38,4)|
         bitnum(d,30,3)|bitnum(d,22,2)|bitnum(d,14,1)|bitnum(d,6,0);
  }

  static void inverse_permutation (uint32_t s0, uint32_t s1, uint8_t* d)
  {
    d[3] = bitnum_intr(s1,7,7)|bitnum_intr(s0,7,6)|bitnum_intr(s1,15,5)|
           bitnum_intr(s0,15,4)|bitnum_intr(s1,23,3)|bitnum_intr(s0,23,2)|
           bitnum_intr(s1,31,1)|bitnum_intr(s0,31,0);
    d[2] = bitnum_intr(s1,6,7)|bitnum_intr(s0,6,6)|bitnum_intr(s1,14,5)|
           bitnum_intr(s0,14,4)|bitnum_intr(s1,22,3)|bitnum_intr(s0,22,2)|
           bitnum_intr(s1,30,1)|bitnum_intr(s0,30,0);
    d[1] = bitnum_intr(s1,5,7)|bitnum_intr(s0,5,6)|bitnum_intr(s1,13,5)|
           bitnum_intr(s0,13,4)|bitnum_intr(s1,21,3)|bitnum_intr(s0,21,2)|
           bitnum_intr(s1,29,1)|bitnum_intr(s0,29,0);
    d[0] = bitnum_intr(s1,4,7)|bitnum_intr(s0,4,6)|bitnum_intr(s1,12,5)|
           bitnum_intr(s0,12,4)|bitnum_intr(s1,20,3)|bitnum_intr(s0,20,2)|
           bitnum_intr(s1,28,1)|bitnum_intr(s0,28,0);
    d[7] = bitnum_intr(s1,3,7)|bitnum_intr(s0,3,6)|bitnum_intr(s1,11,5)|
           bitnum_intr(s0,11,4)|bitnum_intr(s1,19,3)|bitnum_intr(s0,19,2)|
           bitnum_intr(s1,27,1)|bitnum_intr(s0,27,0);
    d[6] = bitnum_intr(s1,2,7)|bitnum_intr(s0,2,6)|bitnum_intr(s1,10,5)|
           bitnum_intr(s0,10,4)|bitnum_intr(s1,18,3)|bitnum_intr(s0,18,2)|
           bitnum_intr(s1,26,1)|bitnum_intr(s0,26,0);
    d[5] = bitnum_intr(s1,1,7)|bitnum_intr(s0,1,6)|bitnum_intr(s1,9,5)|
           bitnum_intr(s0,9,4)|bitnum_intr(s1,17,3)|bitnum_intr(s0,17,2)|
           bitnum_intr(s1,25,1)|bitnum_intr(s0,25,0);
    d[4] = bitnum_intr(s1,0,7)|bitnum_intr(s0,0,6)|bitnum_intr(s1,8,5)|
           bitnum_intr(s0,8,4)|bitnum_intr(s1,16,3)|bitnum_intr(s0,16,2)|
           bitnum_intr(s1,24,1)|bitnum_intr(s0,24,0);
  }

  static uint32_t f (uint32_t state, const uint8_t* key)
  {
    uint32_t t1 = bitnum_intl(state,31,0)|((state & 0xf0000000U)>>1)|
                  bitnum_intl(state,4,5)|bitnum_intl(state,3,6)|
                  ((state & 0x0f000000U)>>3)|bitnum_intl(state,8,11)|
                  bitnum_intl(state,7,12)|((state & 0x00f00000U)>>5)|
                  bitnum_intl(state,12,17)|bitnum_intl(state,11,18)|
                  ((state & 0x000f0000U)>>7)|bitnum_intl(state,16,23);
    uint32_t t2 = bitnum_intl(state,15,0)|((state & 0x0000f000U)<<15)|
                  bitnum_intl(state,20,5)|bitnum_intl(state,19,6)|
                  ((state & 0x00000f00U)<<13)|bitnum_intl(state,24,11)|
                  bitnum_intl(state,23,12)|((state & 0x000000f0U)<<11)|
                  bitnum_intl(state,28,17)|bitnum_intl(state,27,18)|
                  ((state & 0x0000000fU)<<9)|bitnum_intl(state,0,23);
    uint8_t lg[6] = {
      static_cast<uint8_t>((t1 >> 24) & 0xff), static_cast<uint8_t>((t1 >> 16) & 0xff),
      static_cast<uint8_t>((t1 >>  8) & 0xff), static_cast<uint8_t>((t2 >> 24) & 0xff),
      static_cast<uint8_t>((t2 >> 16) & 0xff), static_cast<uint8_t>((t2 >>  8) & 0xff)
    };
    for (int i = 0; i < 6; i++) lg[i] ^= key[i];
    uint32_t s = (static_cast<uint32_t>(SBOX[0][sbox_bit(lg[0] >> 2)]) << 28) |
                 (static_cast<uint32_t>(SBOX[1][sbox_bit(((lg[0] & 3) << 4) | (lg[1] >> 4))]) << 24) |
                 (static_cast<uint32_t>(SBOX[2][sbox_bit(((lg[1] & 15) << 2) | (lg[2] >> 6))]) << 20) |
                 (static_cast<uint32_t>(SBOX[3][sbox_bit(lg[2] & 63)]) << 16) |
                 (static_cast<uint32_t>(SBOX[4][sbox_bit(lg[3] >> 2)]) << 12) |
                 (static_cast<uint32_t>(SBOX[5][sbox_bit(((lg[3] & 3) << 4) | (lg[4] >> 4))]) << 8) |
                 (static_cast<uint32_t>(SBOX[6][sbox_bit(((lg[4] & 15) << 2) | (lg[5] >> 6))]) << 4) |
                  static_cast<uint32_t>(SBOX[7][sbox_bit(lg[5] & 63)]);
    return bitnum_intl(s,15,0)|bitnum_intl(s,6,1)|bitnum_intl(s,19,2)|bitnum_intl(s,20,3)|
           bitnum_intl(s,28,4)|bitnum_intl(s,11,5)|bitnum_intl(s,27,6)|bitnum_intl(s,16,7)|
           bitnum_intl(s,0,8)|bitnum_intl(s,14,9)|bitnum_intl(s,22,10)|bitnum_intl(s,25,11)|
           bitnum_intl(s,4,12)|bitnum_intl(s,17,13)|bitnum_intl(s,30,14)|bitnum_intl(s,9,15)|
           bitnum_intl(s,1,16)|bitnum_intl(s,7,17)|bitnum_intl(s,23,18)|bitnum_intl(s,13,19)|
           bitnum_intl(s,31,20)|bitnum_intl(s,26,21)|bitnum_intl(s,2,22)|bitnum_intl(s,8,23)|
           bitnum_intl(s,18,24)|bitnum_intl(s,12,25)|bitnum_intl(s,29,26)|bitnum_intl(s,5,27)|
           bitnum_intl(s,21,28)|bitnum_intl(s,10,29)|bitnum_intl(s,3,30)|bitnum_intl(s,24,31);
  }

  typedef uint8_t schedule_t[16][6];

  static void key_schedule (const uint8_t* subkey, bool dec, schedule_t schedule)
  {
    for (int i = 0; i < 16; i++) memset (schedule[i], 0, 6);
    uint32_t c = 0, d = 0;
    for (int i = 0; i < 28; i++) c |= bitnum (subkey, PERM_C[i], 31 - i);
    for (int i = 0; i < 28; i++) d |= bitnum (subkey, PERM_D[i], 31 - i);
    for (int i = 0; i < 16; i++)
      {
        int sh = SHIFT[i];
        c = ((c << sh) | (c >> (28 - sh))) & 0xfffffff0U;
        d = ((d << sh) | (d >> (28 - sh))) & 0xfffffff0U;
        int togen = dec ? 15 - i : i;
        for (int j = 0; j < 48; j++)
          {
            int bit = (j < 24) ? COMP[j] : COMP[j] - 27;
            schedule[togen][j >> 3] |= static_cast<uint8_t> (
              bitnum_intr (j < 24 ? c : d, bit, 7 - (j % 8)));
          }
      }
  }

  static void setup (const uint8_t* key24, bool dec, schedule_t keys[3])
  {
    const uint8_t* k1 = key24;
    const uint8_t* k2 = key24 + 8;
    const uint8_t* k3 = key24 + 16;
    if (! dec)
      {
        key_schedule (k1, false, keys[0]);
        key_schedule (k2, true,  keys[1]);
        key_schedule (k3, false, keys[2]);
      }
    else
      {
        key_schedule (k3, true,  keys[0]);
        key_schedule (k2, false, keys[1]);
        key_schedule (k1, true,  keys[2]);
      }
  }

  static void crypt_block (const uint8_t* in, uint8_t* out, const schedule_t keys[3])
  {
    uint8_t data[8];
    memcpy (data, in, 8);
    for (int round = 0; round < 3; round++)
      {
        uint32_t s0, s1;
        initial_permutation (data, s0, s1);
        for (int i = 0; i < 15; i++)
          {
            uint32_t prev = s1;
            s1 = f (s1, keys[round][i]) ^ s0;
            s0 = prev;
          }
        s0 = f (s1, keys[round][15]) ^ s0;
        inverse_permutation (s0, s1, data);
      }
    memcpy (out, data, 8);
  }
}

// ---------------------------------------------------------------------------
// Octave entry points
// ---------------------------------------------------------------------------
DEFUN_DLD (des_blockcrypt_core, args, ,
  "-*- texinfo -*-\n\
@deftypefn {} {} des_blockcrypt_core (@var{block}, @var{key}, @var{direction}, @var{variant})\n\
Encrypt or decrypt one 8-byte DES block.\n\
@var{direction} is 1/'encrypt' or 0/'decrypt'.  @var{variant} is\n\
'standard' (FIPS 46-3) or 'qqmusic' (private bit order, used by QRC).\n\
@end deftypefn")
{
  octave_value_list retval;
  if (args.length () < 4)
    error ("des_blockcrypt_core: need block, key, direction, variant");

  std::vector<uint8_t> block = to_bytes (args(0), "des_blockcrypt_core block");
  std::vector<uint8_t> key = to_bytes (args(1), "des_blockcrypt_core key");
  if (block.size () != 8) error ("des_blockcrypt_core: block must be 8 bytes");
  if (key.size () != 8) error ("des_blockcrypt_core: key must be 8 bytes");
  bool dec = decrypt_flag (args(2), "des_blockcrypt_core");
  bool qq = qq_flag (args(3));

  uint8_t out[8];
  if (qq)
    {
      qq_des::schedule_t k;
      qq_des::key_schedule (key.data (), dec, k);
      uint8_t tmp[8];
      // key_schedule produces 16 subkeys; crypt_block needs 3 groups.  Use a
      // direct single-DES path below instead.
      uint32_t s0, s1;
      qq_des::initial_permutation (block.data (), s0, s1);
      for (int i = 0; i < 15; i++)
        {
          uint32_t prev = s1;
          s1 = qq_des::f (s1, k[i]) ^ s0;
          s0 = prev;
        }
      s0 = qq_des::f (s1, k[15]) ^ s0;
      qq_des::inverse_permutation (s0, s1, tmp);
      memcpy (out, tmp, 8);
    }
  else
    {
      uint64_t sub[16];
      std_des::schedule (key.data (), sub);
      std_des::crypt (block.data (), out, sub, dec);
    }

  retval(0) = bytes_to_ov (std::vector<uint8_t> (out, out + 8));
  return retval;
}

DEFUN_DLD (des3_ecb_crypt, args, ,
  "-*- texinfo -*-\n\
@deftypefn {} {} des3_ecb_crypt (@var{data}, @var{key24}, @var{direction}, @var{variant})\n\
3DES-ECB over a uint8 vector whose length is a multiple of 8.\n\
@end deftypefn")
{
  octave_value_list retval;
  if (args.length () < 4)
    error ("des3_ecb_crypt: need data, key24, direction, variant");

  std::vector<uint8_t> data = to_bytes (args(0), "des3_ecb_crypt data");
  std::vector<uint8_t> key = to_bytes (args(1), "des3_ecb_crypt key");
  if (key.size () != 24) error ("des3_ecb_crypt: key must be 24 bytes");
  if (data.size () % 8 != 0) error ("des3_ecb_crypt: data length must be a multiple of 8");
  bool dec = decrypt_flag (args(2), "des3_ecb_crypt");
  bool qq = qq_flag (args(3));

  qq_des::schedule_t keys[3];
  if (qq)
    qq_des::setup (key.data (), dec, keys);

  std::vector<uint8_t> out (data.size ());
  for (size_t off = 0; off < data.size (); off += 8)
    {
      if (qq)
        qq_des::crypt_block (data.data () + off, out.data () + off, keys);
      else
        {
          // Encrypt: E(K1) -> D(K2) -> E(K3).  Decrypt: D(K3) -> E(K2) -> D(K1).
          // Seed the chain with this plaintext block, then transform in place.
          memcpy (out.data () + off, data.data () + off, 8);
          uint64_t sub[16];
          uint8_t tmp[8];
          const int order[3] = {0, 1, 2};
          for (int k = 0; k < 3; k++)
            {
              int idx = dec ? order[2 - k] : order[k];
              bool this_dec = dec ? (k != 1) : (k == 1);
              std_des::schedule (key.data () + 8 * idx, sub);
              std_des::crypt (out.data () + off, tmp, sub, this_dec);
              memcpy (out.data () + off, tmp, 8);
            }
        }
    }
  retval(0) = bytes_to_ov (out);
  return retval;
}

// LyricTools.exe @ 0x2e33d0, 256 bytes.
static const uint8_t QRC_XOR_TBL[256] = {
  0x77,0x48,0x32,0x73,0xde,0xf2,0xc0,0xc8,0x95,0xec,0x30,0xb2,0x51,0xc3,0xe1,0xa0,
  0x9e,0xe6,0x9d,0xcf,0xfa,0x7f,0x14,0xd1,0xce,0xb8,0xdc,0xc3,0x4a,0x67,0x93,0xd6,
  0x28,0xc2,0x91,0x70,0xca,0x8d,0xa2,0xa4,0xf0,0x08,0x61,0x90,0x7e,0x6f,0xa2,0xe0,
  0xeb,0xae,0x3e,0xb6,0x67,0xc7,0x92,0xf4,0x91,0xb5,0xf6,0x6c,0x5e,0x84,0x40,0xf7,
  0xf3,0x1b,0x02,0x7f,0xd5,0xab,0x41,0x89,0x28,0xf4,0x25,0xcc,0x52,0x11,0xad,0x43,
  0x68,0xa6,0x41,0x8b,0x84,0xb5,0xff,0x2c,0x92,0x4a,0x26,0xd8,0x47,0x6a,0x7c,0x95,
  0x61,0xcc,0xe6,0xcb,0xbb,0x3f,0x47,0x58,0x89,0x75,0xc3,0x75,0xa1,0xd9,0xaf,0xcc,
  0x08,0x73,0x17,0xdc,0xaa,0x9a,0xa2,0x16,0x41,0xd8,0xa2,0x06,0xc6,0x8b,0xfc,0x66,
  0x34,0x9f,0xcf,0x18,0x23,0xa0,0x0a,0x74,0xe7,0x2b,0x27,0x70,0x92,0xe9,0xaf,0x37,
  0xe6,0x8c,0xa7,0xbc,0x62,0x65,0x9c,0xc2,0x08,0xc9,0x88,0xb3,0xf3,0x43,0xac,0x74,
  0x2c,0x0f,0xd4,0xaf,0xa1,0xc3,0x01,0x64,0x95,0x4e,0x48,0x9f,0xf4,0x35,0x78,0x95,
  0x7a,0x39,0xd6,0x6a,0xa0,0x6d,0x40,0xe8,0x4f,0xa8,0xef,0x11,0x1d,0xf3,0x1b,0x3f,
  0x3f,0x07,0xdd,0x6f,0x5b,0x19,0x30,0x19,0xfb,0xef,0x0e,0x37,0xf0,0x0e,0xcd,0x16,
  0x49,0xfe,0x53,0x47,0x13,0x1a,0xbd,0xa4,0xf1,0x40,0x19,0x60,0x0e,0xed,0x68,0x09,
  0x06,0x5f,0x4d,0xcf,0x3d,0x1a,0xfe,0x20,0x77,0xe4,0xd9,0xda,0xf9,0xa4,0x2b,0x76,
  0x1c,0x71,0xdb,0x00,0xbc,0xfd,0x0c,0x6c,0xa5,0x47,0xf7,0xf6,0x00,0x79,0x4a,0x11
};

static std::vector<uint8_t> qrc_xor_apply (const std::vector<uint8_t>& in)
{
  std::vector<uint8_t> out (in.size ());
  for (size_t i = 0; i < in.size (); i++)
    out[i] = in[i] ^ QRC_XOR_TBL[(i * i + 22 * i + 148) & 0xff];
  return out;
}

DEFUN_DLD (qrc_xor_pre, args, ,
  "-*- texinfo -*-\n\
@deftypefn {} {} qrc_xor_pre (@var{data})\n\
Undo the 256-byte XOR pre-obfuscation used by LyricTools.exe before 3DES.\n\
Index: (@var{i}^2 + 22*@var{i} + 148) mod 256, @var{i} starting at 0.\n\
@end deftypefn")
{
  octave_value_list retval;
  if (args.length () < 1) error ("qrc_xor_pre: need data");
  std::vector<uint8_t> in = to_bytes (args(0), "qrc_xor_pre data");

  retval(0) = bytes_to_ov (qrc_xor_apply (in));
  return retval;
}

DEFUN_DLD (qrc_raw_decrypt, args, ,
  "-*- texinfo -*-\n\
@deftypefn {} {} qrc_raw_decrypt (@var{path})\n\
Decrypt a LyricTools.exe .qrc file.  Returns the UTF-8 XML as a char row\n\
vector, or an empty string when the file does not have the QRC magic.\n\
Pipeline: strip 11-byte magic -> XOR pre-layer -> 3DES-ECB -> zlib inflate.\n\
@end deftypefn")
{
  octave_value_list retval;
  if (args.length () < 1) error ("qrc_raw_decrypt: need file path");
  std::string path = args(0).string_value ();
  std::ifstream f (path.c_str (), std::ios::binary);
  if (! f) error ("qrc_raw_decrypt: cannot open '%s'", path.c_str ());
  std::vector<uint8_t> raw ((std::istreambuf_iterator<char> (f)),
                            std::istreambuf_iterator<char> ());
  f.close ();

  static const uint8_t magic[11] = {
    0x98,0x25,0xb0,0xac,0xe3,0x02,0x83,0x68,0xe8,0xfc,0x6c
  };
  static const char* keystr = "!@#)(*$%123ZXC!@!@#)(NHL";
  if (raw.size () < 11) { retval(0) = octave_value (""); return retval; }
  if (! std::equal (magic, magic + 11, raw.begin ()))
    { retval(0) = octave_value (""); return retval; }

  std::vector<uint8_t> body (raw.begin () + 11, raw.end ());
  std::vector<uint8_t> xored = qrc_xor_apply (body);
  size_t n = (xored.size () / 8) * 8;
  xored.resize (n);

  const uint8_t* k = reinterpret_cast<const uint8_t*> (keystr);
  std::vector<uint8_t> key (k, k + 24);
  qq_des::schedule_t keys[3];
  qq_des::setup (key.data (), true, keys);
  std::vector<uint8_t> dec (n);
  for (size_t off = 0; off < n; off += 8)
    qq_des::crypt_block (xored.data () + off, dec.data () + off, keys);

  // zlib inflate: grow the output buffer until Z_STREAM_END.
  std::vector<uint8_t> plain;
  uLongf cap = static_cast<uLongf> (std::max<size_t> (4096, dec.size () * 4));
  for (int attempt = 0; attempt < 8; attempt++)
    {
      plain.resize (cap);
      uLongf dest_len = cap;
      int z = uncompress (plain.data (), &dest_len, dec.data (),
                          static_cast<uLong> (dec.size ()));
      if (z == Z_OK)
        {
          plain.resize (dest_len);
          std::string text (reinterpret_cast<const char*> (plain.data ()), plain.size ());
          retval(0) = octave_value (text);
          return retval;
        }
      if (z != Z_BUF_ERROR) break;
      cap *= 2;
    }
  retval(0) = octave_value ("");
  return retval;
}
