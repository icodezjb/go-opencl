/*
* "sipcscrypt" kernel implementation.
*
* ==========================(LICENSE BEGIN)============================
*
* Copyright (c) 2019  icodezjb
*
* Permission is hereby granted, free of charge, to any person obtaining
* a copy of this software and associated documentation files (the
* "Software"), to deal in the Software without restriction, including
* without limitation the rights to use, copy, modify, merge, publish,
* distribute, sublicense, and/or sell copies of the Software, and to
* permit persons to whom the Software is furnished to do so, subject to
* the following conditions:
*
* The above copyright notice and this permission notice shall be
* included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*
* ===========================(LICENSE END)=============================
*
* @author   icodezjb
* base on ckolivas and yescrypt
*/

__constant uint ES[2] = { 0x00FF00FF, 0xFF00FF00 };
#define ROL32(x, n)  rotate(x, (uint) n)
#define SWAP32(n) (ROL32(n & ES[0], 24U)|ROL32(n & ES[1], 8U))
#define SWAP64(n) \
  (((n) << 56)					\
   | (((n) & 0xff00) << 40)			\
   | (((n) & 0xff0000) << 24)			\
   | (((n) & 0xff000000) << 8)			\
   | (((n) >> 8) & 0xff000000)			\
   | (((n) >> 24) & 0xff0000)			\
   | (((n) >> 40) & 0xff00)			\
| ((n) >> 56))


static __constant uint16 pad1 =
{
	0x36363636, 0x36363636, 0x36363636, 0x36363636,
	0x36363636, 0x36363636, 0x36363636, 0x36363636,
	0x36363636, 0x36363636, 0x36363636, 0x36363636,
	0x36363636, 0x36363636, 0x36363636, 0x36363636
};

static __constant uint16 pad2 =
{
	0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c,
	0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c,
	0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c,
	0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c
};

static __constant uint16 pad5 =
{
	0x00000001, 0x80000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000620
};

static __constant uint16 pad3 =
{
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x80000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x000004a0
};

static __constant uint16 padsha80 =
{
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x80000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000280
};

static __constant uint8 pad4 =
{
	0x80000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000300
};

static __constant  uint8 H256 = {
	0x6A09E667, 0xBB67AE85, 0x3C6EF372,
	0xA54FF53A, 0x510E527F, 0x9B05688C,
	0x1F83D9AB, 0x5BE0CD19
};

inline uint8 swapvec(uint8 buf)
{
	uint8 vec;
	vec.s0 = SWAP32(buf.s0);
	vec.s1 = SWAP32(buf.s1);
	vec.s2 = SWAP32(buf.s2);
	vec.s3 = SWAP32(buf.s3);
	vec.s4 = SWAP32(buf.s4);
	vec.s5 = SWAP32(buf.s5);
	vec.s6 = SWAP32(buf.s6);
	vec.s7 = SWAP32(buf.s7);
	return vec;
}

inline uint8 revswapvec(uint8 buf)
{
	uint8 vec;
	vec.s0 = SWAP32(buf.s7);
	vec.s1 = SWAP32(buf.s6);
	vec.s2 = SWAP32(buf.s5);
	vec.s3 = SWAP32(buf.s4);
	vec.s4 = SWAP32(buf.s3);
	vec.s5 = SWAP32(buf.s2);
	vec.s6 = SWAP32(buf.s1);
	vec.s7 = SWAP32(buf.s0);
	return vec;
}

inline uint16 swapvec16(uint16 buf)
{
	uint16 vec;
	vec.s0 = SWAP32(buf.s0);
	vec.s1 = SWAP32(buf.s1);
	vec.s2 = SWAP32(buf.s2);
	vec.s3 = SWAP32(buf.s3);
	vec.s4 = SWAP32(buf.s4);
	vec.s5 = SWAP32(buf.s5);
	vec.s6 = SWAP32(buf.s6);
	vec.s7 = SWAP32(buf.s7);
	vec.s8 = SWAP32(buf.s8);
	vec.s9 = SWAP32(buf.s9);
	vec.sa = SWAP32(buf.sa);
	vec.sb = SWAP32(buf.sb);
	vec.sc = SWAP32(buf.sc);
	vec.sd = SWAP32(buf.sd);
	vec.se = SWAP32(buf.se);
	vec.sf = SWAP32(buf.sf);
	return vec;
}

#define SHR(x, n)    ((x) >> n)
#define S0(x) (ROL32(x, 25) ^ ROL32(x, 14) ^  SHR(x, 3))
#define S1(x) (ROL32(x, 15) ^ ROL32(x, 13) ^  SHR(x, 10))
#define S2(x) (ROL32(x, 30) ^ ROL32(x, 19) ^ ROL32(x, 10))
#define S3(x) (ROL32(x, 26) ^ ROL32(x, 21) ^ ROL32(x, 7))
#define F0(y, x, z) bitselect(z, y, z ^ x)
#define F1(x, y, z) bitselect(z, y, x)

#define P(a,b,c,d,e,f,g,h,x,K)                  \
{                                               \
    temp1 = h + S3(e) + F1(e,f,g) + (K + x);      \
    d += temp1; h = temp1 + S2(a) + F0(a,b,c);  \
}

#define R0 (W0 = S1(W14) + W9 + S0(W1) + W0)
#define R1 (W1 = S1(W15) + W10 + S0(W2) + W1)
#define R2 (W2 = S1(W0) + W11 + S0(W3) + W2)
#define R3 (W3 = S1(W1) + W12 + S0(W4) + W3)
#define R4 (W4 = S1(W2) + W13 + S0(W5) + W4)
#define R5 (W5 = S1(W3) + W14 + S0(W6) + W5)
#define R6 (W6 = S1(W4) + W15 + S0(W7) + W6)
#define R7 (W7 = S1(W5) + W0 + S0(W8) + W7)
#define R8 (W8 = S1(W6) + W1 + S0(W9) + W8)
#define R9 (W9 = S1(W7) + W2 + S0(W10) + W9)
#define R10 (W10 = S1(W8) + W3 + S0(W11) + W10)
#define R11 (W11 = S1(W9) + W4 + S0(W12) + W11)
#define R12 (W12 = S1(W10) + W5 + S0(W13) + W12)
#define R13 (W13 = S1(W11) + W6 + S0(W14) + W13)
#define R14 (W14 = S1(W12) + W7 + S0(W15) + W14)
#define R15 (W15 = S1(W13) + W8 + S0(W0) + W15)

#define RD14 (S1(W12) + W7 + S0(W15) + W14)
#define RD15 (S1(W13) + W8 + S0(W0) + W15)

/// generic sha transform
inline uint8 sha256_Transform(uint16 data, uint8 state)
{
uint temp1;
    uint8 res = state;
	uint W0 = data.s0;
	uint W1 = data.s1;
	uint W2 = data.s2;
	uint W3 = data.s3;
	uint W4 = data.s4;
	uint W5 = data.s5;
	uint W6 = data.s6;
	uint W7 = data.s7;
	uint W8 = data.s8;
	uint W9 = data.s9;
	uint W10 = data.sA;
	uint W11 = data.sB;
	uint W12 = data.sC;
	uint W13 = data.sD;
	uint W14 = data.sE;
	uint W15 = data.sF;

#define v0  res.s0
#define v1  res.s1
#define v2  res.s2
#define v3  res.s3
#define v4  res.s4
#define v5  res.s5
#define v6  res.s6
#define v7  res.s7

	P(v0, v1, v2, v3, v4, v5, v6, v7, W0, 0x428A2F98);
	P(v7, v0, v1, v2, v3, v4, v5, v6, W1, 0x71374491);
	P(v6, v7, v0, v1, v2, v3, v4, v5, W2, 0xB5C0FBCF);
	P(v5, v6, v7, v0, v1, v2, v3, v4, W3, 0xE9B5DBA5);
	P(v4, v5, v6, v7, v0, v1, v2, v3, W4, 0x3956C25B);
	P(v3, v4, v5, v6, v7, v0, v1, v2, W5, 0x59F111F1);
	P(v2, v3, v4, v5, v6, v7, v0, v1, W6, 0x923F82A4);
	P(v1, v2, v3, v4, v5, v6, v7, v0, W7, 0xAB1C5ED5);
	P(v0, v1, v2, v3, v4, v5, v6, v7, W8, 0xD807AA98);
	P(v7, v0, v1, v2, v3, v4, v5, v6, W9, 0x12835B01);
	P(v6, v7, v0, v1, v2, v3, v4, v5, W10, 0x243185BE);
	P(v5, v6, v7, v0, v1, v2, v3, v4, W11, 0x550C7DC3);
	P(v4, v5, v6, v7, v0, v1, v2, v3, W12, 0x72BE5D74);
	P(v3, v4, v5, v6, v7, v0, v1, v2, W13, 0x80DEB1FE);
	P(v2, v3, v4, v5, v6, v7, v0, v1, W14, 0x9BDC06A7);
	P(v1, v2, v3, v4, v5, v6, v7, v0, W15, 0xC19BF174);

	P(v0, v1, v2, v3, v4, v5, v6, v7, R0, 0xE49B69C1);
	P(v7, v0, v1, v2, v3, v4, v5, v6, R1, 0xEFBE4786);
	P(v6, v7, v0, v1, v2, v3, v4, v5, R2, 0x0FC19DC6);
	P(v5, v6, v7, v0, v1, v2, v3, v4, R3, 0x240CA1CC);
	P(v4, v5, v6, v7, v0, v1, v2, v3, R4, 0x2DE92C6F);
	P(v3, v4, v5, v6, v7, v0, v1, v2, R5, 0x4A7484AA);
	P(v2, v3, v4, v5, v6, v7, v0, v1, R6, 0x5CB0A9DC);
	P(v1, v2, v3, v4, v5, v6, v7, v0, R7, 0x76F988DA);
	P(v0, v1, v2, v3, v4, v5, v6, v7, R8, 0x983E5152);
	P(v7, v0, v1, v2, v3, v4, v5, v6, R9, 0xA831C66D);
	P(v6, v7, v0, v1, v2, v3, v4, v5, R10, 0xB00327C8);
	P(v5, v6, v7, v0, v1, v2, v3, v4, R11, 0xBF597FC7);
	P(v4, v5, v6, v7, v0, v1, v2, v3, R12, 0xC6E00BF3);
	P(v3, v4, v5, v6, v7, v0, v1, v2, R13, 0xD5A79147);
	P(v2, v3, v4, v5, v6, v7, v0, v1, R14, 0x06CA6351);
	P(v1, v2, v3, v4, v5, v6, v7, v0, R15, 0x14292967);

	P(v0, v1, v2, v3, v4, v5, v6, v7, R0, 0x27B70A85);
	P(v7, v0, v1, v2, v3, v4, v5, v6, R1, 0x2E1B2138);
	P(v6, v7, v0, v1, v2, v3, v4, v5, R2, 0x4D2C6DFC);
	P(v5, v6, v7, v0, v1, v2, v3, v4, R3, 0x53380D13);
	P(v4, v5, v6, v7, v0, v1, v2, v3, R4, 0x650A7354);
	P(v3, v4, v5, v6, v7, v0, v1, v2, R5, 0x766A0ABB);
	P(v2, v3, v4, v5, v6, v7, v0, v1, R6, 0x81C2C92E);
	P(v1, v2, v3, v4, v5, v6, v7, v0, R7, 0x92722C85);
	P(v0, v1, v2, v3, v4, v5, v6, v7, R8, 0xA2BFE8A1);
	P(v7, v0, v1, v2, v3, v4, v5, v6, R9, 0xA81A664B);
	P(v6, v7, v0, v1, v2, v3, v4, v5, R10, 0xC24B8B70);
	P(v5, v6, v7, v0, v1, v2, v3, v4, R11, 0xC76C51A3);
	P(v4, v5, v6, v7, v0, v1, v2, v3, R12, 0xD192E819);
	P(v3, v4, v5, v6, v7, v0, v1, v2, R13, 0xD6990624);
	P(v2, v3, v4, v5, v6, v7, v0, v1, R14, 0xF40E3585);
	P(v1, v2, v3, v4, v5, v6, v7, v0, R15, 0x106AA070);

	P(v0, v1, v2, v3, v4, v5, v6, v7, R0, 0x19A4C116);
	P(v7, v0, v1, v2, v3, v4, v5, v6, R1, 0x1E376C08);
	P(v6, v7, v0, v1, v2, v3, v4, v5, R2, 0x2748774C);
	P(v5, v6, v7, v0, v1, v2, v3, v4, R3, 0x34B0BCB5);
	P(v4, v5, v6, v7, v0, v1, v2, v3, R4, 0x391C0CB3);
	P(v3, v4, v5, v6, v7, v0, v1, v2, R5, 0x4ED8AA4A);
	P(v2, v3, v4, v5, v6, v7, v0, v1, R6, 0x5B9CCA4F);
	P(v1, v2, v3, v4, v5, v6, v7, v0, R7, 0x682E6FF3);
	P(v0, v1, v2, v3, v4, v5, v6, v7, R8, 0x748F82EE);
	P(v7, v0, v1, v2, v3, v4, v5, v6, R9, 0x78A5636F);
	P(v6, v7, v0, v1, v2, v3, v4, v5, R10, 0x84C87814);
	P(v5, v6, v7, v0, v1, v2, v3, v4, R11, 0x8CC70208);
	P(v4, v5, v6, v7, v0, v1, v2, v3, R12, 0x90BEFFFA);
	P(v3, v4, v5, v6, v7, v0, v1, v2, R13, 0xA4506CEB);
	P(v2, v3, v4, v5, v6, v7, v0, v1, RD14, 0xBEF9A3F7);
	P(v1, v2, v3, v4, v5, v6, v7, v0, RD15, 0xC67178F2);
#undef v0
#undef v1
#undef v2
#undef v3
#undef v4
#undef v5
#undef v6
#undef v7
	return (res+state);
}


static inline uint8 sha256_round1(uint16 data)
{
	uint temp1;
    uint8 res;
	uint W0 = data.s0;
	uint W1 = data.s1;
	uint W2 = data.s2;
	uint W3 = data.s3;
	uint W4 = data.s4;
	uint W5 = data.s5;
	uint W6 = data.s6;
	uint W7 = data.s7;
	uint W8 = data.s8;
	uint W9 = data.s9;
	uint W10 = data.sA;
	uint W11 = data.sB;
	uint W12 = data.sC;
	uint W13 = data.sD;
	uint W14 = data.sE;
	uint W15 = data.sF;

	uint v0 = 0x6A09E667;
	uint v1 = 0xBB67AE85;
	uint v2 = 0x3C6EF372;
	uint v3 = 0xA54FF53A;
	uint v4 = 0x510E527F;
	uint v5 = 0x9B05688C;
	uint v6 = 0x1F83D9AB;
	uint v7 = 0x5BE0CD19;

	P(v0, v1, v2, v3, v4, v5, v6, v7, W0, 0x428A2F98);
	P(v7, v0, v1, v2, v3, v4, v5, v6, W1, 0x71374491);
	P(v6, v7, v0, v1, v2, v3, v4, v5, W2, 0xB5C0FBCF);
	P(v5, v6, v7, v0, v1, v2, v3, v4, W3, 0xE9B5DBA5);
	P(v4, v5, v6, v7, v0, v1, v2, v3, W4, 0x3956C25B);
	P(v3, v4, v5, v6, v7, v0, v1, v2, W5, 0x59F111F1);
	P(v2, v3, v4, v5, v6, v7, v0, v1, W6, 0x923F82A4);
	P(v1, v2, v3, v4, v5, v6, v7, v0, W7, 0xAB1C5ED5);
	P(v0, v1, v2, v3, v4, v5, v6, v7, W8, 0xD807AA98);
	P(v7, v0, v1, v2, v3, v4, v5, v6, W9, 0x12835B01);
	P(v6, v7, v0, v1, v2, v3, v4, v5, W10, 0x243185BE);
	P(v5, v6, v7, v0, v1, v2, v3, v4, W11, 0x550C7DC3);
	P(v4, v5, v6, v7, v0, v1, v2, v3, W12, 0x72BE5D74);
	P(v3, v4, v5, v6, v7, v0, v1, v2, W13, 0x80DEB1FE);
	P(v2, v3, v4, v5, v6, v7, v0, v1, W14, 0x9BDC06A7);
	P(v1, v2, v3, v4, v5, v6, v7, v0, W15, 0xC19BF174);

	P(v0, v1, v2, v3, v4, v5, v6, v7, R0, 0xE49B69C1);
	P(v7, v0, v1, v2, v3, v4, v5, v6, R1, 0xEFBE4786);
	P(v6, v7, v0, v1, v2, v3, v4, v5, R2, 0x0FC19DC6);
	P(v5, v6, v7, v0, v1, v2, v3, v4, R3, 0x240CA1CC);
	P(v4, v5, v6, v7, v0, v1, v2, v3, R4, 0x2DE92C6F);
	P(v3, v4, v5, v6, v7, v0, v1, v2, R5, 0x4A7484AA);
	P(v2, v3, v4, v5, v6, v7, v0, v1, R6, 0x5CB0A9DC);
	P(v1, v2, v3, v4, v5, v6, v7, v0, R7, 0x76F988DA);
	P(v0, v1, v2, v3, v4, v5, v6, v7, R8, 0x983E5152);
	P(v7, v0, v1, v2, v3, v4, v5, v6, R9, 0xA831C66D);
	P(v6, v7, v0, v1, v2, v3, v4, v5, R10, 0xB00327C8);
	P(v5, v6, v7, v0, v1, v2, v3, v4, R11, 0xBF597FC7);
	P(v4, v5, v6, v7, v0, v1, v2, v3, R12, 0xC6E00BF3);
	P(v3, v4, v5, v6, v7, v0, v1, v2, R13, 0xD5A79147);
	P(v2, v3, v4, v5, v6, v7, v0, v1, R14, 0x06CA6351);
	P(v1, v2, v3, v4, v5, v6, v7, v0, R15, 0x14292967);

	P(v0, v1, v2, v3, v4, v5, v6, v7, R0, 0x27B70A85);
	P(v7, v0, v1, v2, v3, v4, v5, v6, R1, 0x2E1B2138);
	P(v6, v7, v0, v1, v2, v3, v4, v5, R2, 0x4D2C6DFC);
	P(v5, v6, v7, v0, v1, v2, v3, v4, R3, 0x53380D13);
	P(v4, v5, v6, v7, v0, v1, v2, v3, R4, 0x650A7354);
	P(v3, v4, v5, v6, v7, v0, v1, v2, R5, 0x766A0ABB);
	P(v2, v3, v4, v5, v6, v7, v0, v1, R6, 0x81C2C92E);
	P(v1, v2, v3, v4, v5, v6, v7, v0, R7, 0x92722C85);
	P(v0, v1, v2, v3, v4, v5, v6, v7, R8, 0xA2BFE8A1);
	P(v7, v0, v1, v2, v3, v4, v5, v6, R9, 0xA81A664B);
	P(v6, v7, v0, v1, v2, v3, v4, v5, R10, 0xC24B8B70);
	P(v5, v6, v7, v0, v1, v2, v3, v4, R11, 0xC76C51A3);
	P(v4, v5, v6, v7, v0, v1, v2, v3, R12, 0xD192E819);
	P(v3, v4, v5, v6, v7, v0, v1, v2, R13, 0xD6990624);
	P(v2, v3, v4, v5, v6, v7, v0, v1, R14, 0xF40E3585);
	P(v1, v2, v3, v4, v5, v6, v7, v0, R15, 0x106AA070);

	P(v0, v1, v2, v3, v4, v5, v6, v7, R0, 0x19A4C116);
	P(v7, v0, v1, v2, v3, v4, v5, v6, R1, 0x1E376C08);
	P(v6, v7, v0, v1, v2, v3, v4, v5, R2, 0x2748774C);
	P(v5, v6, v7, v0, v1, v2, v3, v4, R3, 0x34B0BCB5);
	P(v4, v5, v6, v7, v0, v1, v2, v3, R4, 0x391C0CB3);
	P(v3, v4, v5, v6, v7, v0, v1, v2, R5, 0x4ED8AA4A);
	P(v2, v3, v4, v5, v6, v7, v0, v1, R6, 0x5B9CCA4F);
	P(v1, v2, v3, v4, v5, v6, v7, v0, R7, 0x682E6FF3);
	P(v0, v1, v2, v3, v4, v5, v6, v7, R8, 0x748F82EE);
	P(v7, v0, v1, v2, v3, v4, v5, v6, R9, 0x78A5636F);
	P(v6, v7, v0, v1, v2, v3, v4, v5, R10, 0x84C87814);
	P(v5, v6, v7, v0, v1, v2, v3, v4, R11, 0x8CC70208);
	P(v4, v5, v6, v7, v0, v1, v2, v3, R12, 0x90BEFFFA);
	P(v3, v4, v5, v6, v7, v0, v1, v2, R13, 0xA4506CEB);
	P(v2, v3, v4, v5, v6, v7, v0, v1, RD14, 0xBEF9A3F7);
	P(v1, v2, v3, v4, v5, v6, v7, v0, RD15, 0xC67178F2);

	res.s0 = v0 + 0x6A09E667;
	res.s1 = v1 + 0xBB67AE85;
	res.s2 = v2 + 0x3C6EF372;
	res.s3 = v3 + 0xA54FF53A;
	res.s4 = v4 + 0x510E527F;
	res.s5 = v5 + 0x9B05688C;
	res.s6 = v6 + 0x1F83D9AB;
	res.s7 = v7 + 0x5BE0CD19;
	return (res);
}


static inline uint8 sha256_round2(uint16 data,uint8 buf)
{
	uint temp1;
	uint8 res;
	uint W0 = data.s0;
	uint W1 = data.s1;
	uint W2 = data.s2;
	uint W3 = data.s3;
	uint W4 = data.s4;
	uint W5 = data.s5;
	uint W6 = data.s6;
	uint W7 = data.s7;
	uint W8 = data.s8;
	uint W9 = data.s9;
	uint W10 = data.sA;
	uint W11 = data.sB;
	uint W12 = data.sC;
	uint W13 = data.sD;
	uint W14 = data.sE;
	uint W15 = data.sF;

	uint v0 = buf.s0;
	uint v1 = buf.s1;
	uint v2 = buf.s2;
	uint v3 = buf.s3;
	uint v4 = buf.s4;
	uint v5 = buf.s5;
	uint v6 = buf.s6;
	uint v7 = buf.s7;

	P(v0, v1, v2, v3, v4, v5, v6, v7, W0, 0x428A2F98);
	P(v7, v0, v1, v2, v3, v4, v5, v6, W1, 0x71374491);
	P(v6, v7, v0, v1, v2, v3, v4, v5, W2, 0xB5C0FBCF);
	P(v5, v6, v7, v0, v1, v2, v3, v4, W3, 0xE9B5DBA5);
	P(v4, v5, v6, v7, v0, v1, v2, v3, W4, 0x3956C25B);
	P(v3, v4, v5, v6, v7, v0, v1, v2, W5, 0x59F111F1);
	P(v2, v3, v4, v5, v6, v7, v0, v1, W6, 0x923F82A4);
	P(v1, v2, v3, v4, v5, v6, v7, v0, W7, 0xAB1C5ED5);
	P(v0, v1, v2, v3, v4, v5, v6, v7, W8, 0xD807AA98);
	P(v7, v0, v1, v2, v3, v4, v5, v6, W9, 0x12835B01);
	P(v6, v7, v0, v1, v2, v3, v4, v5, W10, 0x243185BE);
	P(v5, v6, v7, v0, v1, v2, v3, v4, W11, 0x550C7DC3);
	P(v4, v5, v6, v7, v0, v1, v2, v3, W12, 0x72BE5D74);
	P(v3, v4, v5, v6, v7, v0, v1, v2, W13, 0x80DEB1FE);
	P(v2, v3, v4, v5, v6, v7, v0, v1, W14, 0x9BDC06A7);
	P(v1, v2, v3, v4, v5, v6, v7, v0, W15, 0xC19BF174);

	P(v0, v1, v2, v3, v4, v5, v6, v7, R0, 0xE49B69C1);
	P(v7, v0, v1, v2, v3, v4, v5, v6, R1, 0xEFBE4786);
	P(v6, v7, v0, v1, v2, v3, v4, v5, R2, 0x0FC19DC6);
	P(v5, v6, v7, v0, v1, v2, v3, v4, R3, 0x240CA1CC);
	P(v4, v5, v6, v7, v0, v1, v2, v3, R4, 0x2DE92C6F);
	P(v3, v4, v5, v6, v7, v0, v1, v2, R5, 0x4A7484AA);
	P(v2, v3, v4, v5, v6, v7, v0, v1, R6, 0x5CB0A9DC);
	P(v1, v2, v3, v4, v5, v6, v7, v0, R7, 0x76F988DA);
	P(v0, v1, v2, v3, v4, v5, v6, v7, R8, 0x983E5152);
	P(v7, v0, v1, v2, v3, v4, v5, v6, R9, 0xA831C66D);
	P(v6, v7, v0, v1, v2, v3, v4, v5, R10, 0xB00327C8);
	P(v5, v6, v7, v0, v1, v2, v3, v4, R11, 0xBF597FC7);
	P(v4, v5, v6, v7, v0, v1, v2, v3, R12, 0xC6E00BF3);
	P(v3, v4, v5, v6, v7, v0, v1, v2, R13, 0xD5A79147);
	P(v2, v3, v4, v5, v6, v7, v0, v1, R14, 0x06CA6351);
	P(v1, v2, v3, v4, v5, v6, v7, v0, R15, 0x14292967);

	P(v0, v1, v2, v3, v4, v5, v6, v7, R0, 0x27B70A85);
	P(v7, v0, v1, v2, v3, v4, v5, v6, R1, 0x2E1B2138);
	P(v6, v7, v0, v1, v2, v3, v4, v5, R2, 0x4D2C6DFC);
	P(v5, v6, v7, v0, v1, v2, v3, v4, R3, 0x53380D13);
	P(v4, v5, v6, v7, v0, v1, v2, v3, R4, 0x650A7354);
	P(v3, v4, v5, v6, v7, v0, v1, v2, R5, 0x766A0ABB);
	P(v2, v3, v4, v5, v6, v7, v0, v1, R6, 0x81C2C92E);
	P(v1, v2, v3, v4, v5, v6, v7, v0, R7, 0x92722C85);
	P(v0, v1, v2, v3, v4, v5, v6, v7, R8, 0xA2BFE8A1);
	P(v7, v0, v1, v2, v3, v4, v5, v6, R9, 0xA81A664B);
	P(v6, v7, v0, v1, v2, v3, v4, v5, R10, 0xC24B8B70);
	P(v5, v6, v7, v0, v1, v2, v3, v4, R11, 0xC76C51A3);
	P(v4, v5, v6, v7, v0, v1, v2, v3, R12, 0xD192E819);
	P(v3, v4, v5, v6, v7, v0, v1, v2, R13, 0xD6990624);
	P(v2, v3, v4, v5, v6, v7, v0, v1, R14, 0xF40E3585);
	P(v1, v2, v3, v4, v5, v6, v7, v0, R15, 0x106AA070);

	P(v0, v1, v2, v3, v4, v5, v6, v7, R0, 0x19A4C116);
	P(v7, v0, v1, v2, v3, v4, v5, v6, R1, 0x1E376C08);
	P(v6, v7, v0, v1, v2, v3, v4, v5, R2, 0x2748774C);
	P(v5, v6, v7, v0, v1, v2, v3, v4, R3, 0x34B0BCB5);
	P(v4, v5, v6, v7, v0, v1, v2, v3, R4, 0x391C0CB3);
	P(v3, v4, v5, v6, v7, v0, v1, v2, R5, 0x4ED8AA4A);
	P(v2, v3, v4, v5, v6, v7, v0, v1, R6, 0x5B9CCA4F);
	P(v1, v2, v3, v4, v5, v6, v7, v0, R7, 0x682E6FF3);
	P(v0, v1, v2, v3, v4, v5, v6, v7, R8, 0x748F82EE);
	P(v7, v0, v1, v2, v3, v4, v5, v6, R9, 0x78A5636F);
	P(v6, v7, v0, v1, v2, v3, v4, v5, R10, 0x84C87814);
	P(v5, v6, v7, v0, v1, v2, v3, v4, R11, 0x8CC70208);
	P(v4, v5, v6, v7, v0, v1, v2, v3, R12, 0x90BEFFFA);
	P(v3, v4, v5, v6, v7, v0, v1, v2, R13, 0xA4506CEB);
	P(v2, v3, v4, v5, v6, v7, v0, v1, RD14, 0xBEF9A3F7);
	P(v1, v2, v3, v4, v5, v6, v7, v0, RD15, 0xC67178F2);

	res.s0 = (v0 + buf.s0);
	res.s1 = (v1 + buf.s1);
	res.s2 = (v2 + buf.s2);
	res.s3 = (v3 + buf.s3);
	res.s4 = (v4 + buf.s4);
	res.s5 = (v5 + buf.s5);
	res.s6 = (v6 + buf.s6);
	res.s7 = (v7 + buf.s7);
	return (res);
}

//--------scrypt_core---start--------
void shittify(uint4 B[8])
{
	uint4 tmp[4];
	tmp[0] = (uint4)(B[1].x,B[2].y,B[3].z,B[0].w);
	tmp[1] = (uint4)(B[2].x,B[3].y,B[0].z,B[1].w);
	tmp[2] = (uint4)(B[3].x,B[0].y,B[1].z,B[2].w);
	tmp[3] = (uint4)(B[0].x,B[1].y,B[2].z,B[3].w);

#pragma unroll
	for(uint i=0; i<4; ++i)
		B[i] = SWAP32(tmp[i]);

	tmp[0] = (uint4)(B[5].x,B[6].y,B[7].z,B[4].w);
	tmp[1] = (uint4)(B[6].x,B[7].y,B[4].z,B[5].w);
	tmp[2] = (uint4)(B[7].x,B[4].y,B[5].z,B[6].w);
	tmp[3] = (uint4)(B[4].x,B[5].y,B[6].z,B[7].w);

#pragma unroll
	for(uint i=0; i<4; ++i)
		B[i+4] = SWAP32(tmp[i]);
}

void unshittify(uint4 B[8])
{
	uint4 tmp[4];
	tmp[0] = (uint4)(B[3].x,B[2].y,B[1].z,B[0].w);
	tmp[1] = (uint4)(B[0].x,B[3].y,B[2].z,B[1].w);
	tmp[2] = (uint4)(B[1].x,B[0].y,B[3].z,B[2].w);
	tmp[3] = (uint4)(B[2].x,B[1].y,B[0].z,B[3].w);

#pragma unroll
	for(uint i=0; i<4; ++i)
		B[i] = SWAP32(tmp[i]);

	tmp[0] = (uint4)(B[7].x,B[6].y,B[5].z,B[4].w);
	tmp[1] = (uint4)(B[4].x,B[7].y,B[6].z,B[5].w);
	tmp[2] = (uint4)(B[5].x,B[4].y,B[7].z,B[6].w);
	tmp[3] = (uint4)(B[6].x,B[5].y,B[4].z,B[7].w);

#pragma unroll
	for(uint i=0; i<4; ++i)
		B[i+4] = SWAP32(tmp[i]);
}

void salsa(uint4 B[8])
{
	uint4 w[4];

#pragma unroll
	for(uint i=0; i<4; ++i)
		w[i] = (B[i]^=B[i+4]);

#pragma unroll
	for(uint i=0; i<4; ++i)
	{
		w[0] ^= ROL32(w[3]     +w[2]     , 7U);
		w[1] ^= ROL32(w[0]     +w[3]     , 9U);
		w[2] ^= ROL32(w[1]     +w[0]     ,13U);
		w[3] ^= ROL32(w[2]     +w[1]     ,18U);
		w[2] ^= ROL32(w[3].wxyz+w[0].zwxy, 7U);
		w[1] ^= ROL32(w[2].wxyz+w[3].zwxy, 9U);
		w[0] ^= ROL32(w[1].wxyz+w[2].zwxy,13U);
		w[3] ^= ROL32(w[0].wxyz+w[1].zwxy,18U);
	}

#pragma unroll
	for(uint i=0; i<4; ++i)
		w[i] = (B[i+4]^=(B[i]+=w[i]));

#pragma unroll
	for(uint i=0; i<4; ++i)
	{
		w[0] ^= ROL32(w[3]     +w[2]     , 7U);
		w[1] ^= ROL32(w[0]     +w[3]     , 9U);
		w[2] ^= ROL32(w[1]     +w[0]     ,13U);
		w[3] ^= ROL32(w[2]     +w[1]     ,18U);
		w[2] ^= ROL32(w[3].wxyz+w[0].zwxy, 7U);
		w[1] ^= ROL32(w[2].wxyz+w[3].zwxy, 9U);
		w[0] ^= ROL32(w[1].wxyz+w[2].zwxy,13U);
		w[3] ^= ROL32(w[0].wxyz+w[1].zwxy,18U);
	}

#pragma unroll
	for(uint i=0; i<4; ++i)
		B[i+4] += w[i];
}

#define Coord(x,y,z) x+y*(x ## SIZE)+z*(y ## SIZE)*(x ## SIZE)
#define CO Coord(z,x,y)

//#define LOOKUP_GAP 1
//#define CONCURRENT_THREADS 1
//#define WORKSIZE 1

void scrypt_core(const uint gid, uint4 X[8], __global uint4 * restrict lookup)
{
	shittify(X);
	const uint zSIZE = 8;
	const uint ySIZE = (1024/LOOKUP_GAP+(1024%LOOKUP_GAP>0));
	const uint xSIZE = CONCURRENT_THREADS;
	const uint x = gid % xSIZE;

	for(uint y=0; y<1024/LOOKUP_GAP; ++y)
	{
#pragma unroll
		for(uint z=0; z<zSIZE; ++z){
			lookup[CO] = X[z];
		}
		for(uint i=0; i<LOOKUP_GAP; ++i)
			salsa(X);
	}
#if (LOOKUP_GAP != 1) && (LOOKUP_GAP != 2) && (LOOKUP_GAP != 4) && (LOOKUP_GAP != 8)
	{
		uint y = (1024/LOOKUP_GAP);
#pragma unroll
		for(uint z=0; z<zSIZE; ++z)
			lookup[CO] = X[z];
		for(uint i=0; i<1024%LOOKUP_GAP; ++i)
			salsa(X);
	}
#endif
	for (uint i=0; i<1024; ++i)
	{
		uint4 V[8];
		uint j = X[7].x & 0x000003FFU;
		uint y = (j/LOOKUP_GAP);
#pragma unroll
		for(uint z=0; z<zSIZE; ++z)
			V[z] = lookup[CO];

#if (LOOKUP_GAP == 1)
#elif (LOOKUP_GAP == 2)
		if (j&1)
			salsa(V);
#else
		uint val = j%LOOKUP_GAP;
		for (uint z=0; z<val; ++z)
			salsa(V);
#endif

#pragma unroll
		for(uint z=0; z<zSIZE; ++z)
			X[z] ^= V[z];
		salsa(X);
	}
	unshittify(X);
}
//--------scrypt_core---end----------


static inline uint8 sha256_80(uint* data)
{

    uint8 buf = sha256_round1( ((uint16*)data)[0]);
    uint16 in = padsha80;
    in.s0 = data[16];
    in.s1 = data[17];
    in.s2 = data[18];
    in.s3 = data[19];

    return(sha256_round2(in,buf));
}

static inline void pbkdf2_sha256_80_32(uint* data, uint16 *X, uint8* hmac_init_state, uint8* outhash){
    uint16 in;
    //uint8 state1, state2, hmac_pw;

    //HMAC init
    uint8 state1 = hmac_init_state[0];
    uint8 state2 = hmac_init_state[1];

    //SHA256 Update
    in = swapvec16(X[0]);
    state1 = sha256_Transform(in, state1);
    in = swapvec16(X[1]);
    state1 = sha256_Transform(in, state1);

    //SHA256 PADING
    in = pad5;
    state1 = sha256_Transform(in, state1);
    in.lo = state1;
    in.hi = pad4;

    //SHA256 result
    *outhash = swapvec(sha256_Transform(in, state2));
}

static void inline pbkdf2_sha256_80_120(uint *data, uint16 *X, uint8* hmac_init_state) {
    uint16 in;
    uint8 state1, state2;
    uint8 hmac_pw = sha256_80(data);

    //pbkdf
    in.lo = pad1.lo ^ hmac_pw;
    in.hi = pad1.hi;
    state1 = hmac_init_state[0] = sha256_Transform(in, H256);

    in.lo = pad2.lo ^ hmac_pw;
    in.hi = pad2.hi;
    state2 = hmac_init_state[1] = sha256_Transform(in, H256);

    in = ((uint16*)data)[0];
    state1 = sha256_Transform(in, state1);

    //first 32-bytes
    in = pad3;
    in.s0 = data[16];
    in.s1 = data[17];
    in.s2 = data[18];
    in.s3 = data[19];
    in.s4 = 0x1;
    in.lo = sha256_Transform(in, state1);
    in.hi = pad4;
    X[0].lo = sha256_Transform(in, state2);

    //second 32-bytes
    in = pad3;
    in.s0 = data[16];
    in.s1 = data[17];
    in.s2 = data[18];
    in.s3 = data[19];
    in.s4 = 0x2;
    in.lo = sha256_Transform(in, state1);
    in.hi = pad4;
    X[0].hi = sha256_Transform(in, state2);

    //third 32-bytes
    in = pad3;
    in.s0 = data[16];
    in.s1 = data[17];
    in.s2 = data[18];
    in.s3 = data[19];
    in.s4 = 0x3;
    in.lo = sha256_Transform(in, state1);
    in.hi = pad4;
    X[1].lo = sha256_Transform(in, state2);

    //last 32-bytes
    in = pad3;
    in.s0 = data[16];
    in.s1 = data[17];
    in.s2 = data[18];
    in.s3 = data[19];
    in.s4 = 0x4;
    in.lo = sha256_Transform(in, state1);
    in.hi = pad4;
    X[1].hi = sha256_Transform(in, state2);
}


__kernel void test(__global uint4 * restrict padcache)
{
    int i ;
    uint16 X[2],tmpX[2];
    uint8 hmac_init_state[2],outhash;

    uint data[20]={
        0x885c778d, 0x7eedb688, 0x76b1377e, 0x216ed1d2,
        0xc2417b0f, 0xca06b66c, 0xa4facae7, 0x9ae5330d,
        0x885c778d, 0x7eedb688, 0x76b1377e, 0x216ed1d2,
        0xc2417b0f, 0xca06b66c, 0xa4facae7, 0x9ae5330d,
        0x0       , 0x0       , 0x2d19df98, 0x782ac54c
    };

    pbkdf2_sha256_80_120(data,X,hmac_init_state);

    scrypt_core(0,X,padcache);

    tmpX[0] = swapvec16(X[0]);
    tmpX[1] = swapvec16(X[1]);

    tmpX[0].s0 += (0x30 << 24);

    pbkdf2_sha256_80_32(data,tmpX,hmac_init_state,&outhash);

    //should print
    //"outhash=65a09aec 95e56979 6d54b614 f506c736 b12516aa a9571f4 94006a9e 97823052"
    //printf("outhash=%x %x %x %x %x %x %x %x\n",revswapvec(outhash).s01234567);
    uint8 expect = (uint8)(0x65a09aec,0x95e56979,0x6d54b614,0xf506c736,0xb12516aa,0xa9571f4,0x94006a9e,0x97823052);
    uint8 result = revswapvec(outhash);

    bool test_pass = result.s0 == expect.s0 &&
                     result.s1 == expect.s1 &&
                     result.s2 == expect.s2 &&
                     result.s3 == expect.s3 &&
                     result.s4 == expect.s4 &&
                     result.s5 == expect.s5 &&
                     result.s6 == expect.s6 &&
                     result.s7 == expect.s7;
    if (test_pass) {
        printf("Test Pass!\n");
    } else {
        printf("Test failed!\n");
        printf("expect:65a09aec 95e56979 6d54b614 f506c736 b12516aa a9571f4 94006a9e 97823052\n");
        printf("result:%x %x %x %x %x %x %x %x\n",result.s01234567);
    }
}

