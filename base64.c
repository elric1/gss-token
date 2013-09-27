/*	$NetBSD: auth-bozo.c,v 1.10 2011/11/18 09:51:31 mrg Exp $	*/
/*	$eterna: auth-bozo.c,v 1.17 2011/11/18 09:21:15 mrg Exp $	*/

/*
 * Copyright (c) 1997-2011 Matthew R. Green
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer and
 *    dedication in the documentation and/or other materials provided
 *    with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <sys/types.h>

#include <malloc.h>
#include <string.h>

#include "base64.h"

/*
 * Translation Table from RFC1113:
 */
static const char cb64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 * base64_encode returns a nul-terminated malloc(3)ed string.
 * written by Roland C. Dowdeswell.
 */

char *
base64_encode(const unsigned char *str, ssize_t len)
{
	size_t		 pos;
	unsigned char	 remainder;
	unsigned char	*outbuf;
	unsigned char	*out;

	if (len == -1)
		len = strlen((const char *)str);

	outbuf = malloc((len / 3 + 1) * 4 + 1);
	if (outbuf == NULL)
		return NULL;

	out = outbuf;
	for (pos = 0, remainder = 0; pos < (size_t)len; pos++) {
		switch (pos % 3) {
		case 0:
			*out++ = cb64[str[pos] >> 2];
			remainder = (str[pos] & 0x3) << 4;
			break;

		case 1:
			*out++ = cb64[str[pos] >> 4 | remainder];
			remainder = (str[pos] & 0x0f) << 2;
			break;

		case 2:
			*out++ = cb64[str[pos] >> 6 | remainder];
			*out++ = cb64[str[pos] & 0x3f];
			break;
		}
	}

	switch (pos % 3) {
	case 1:
		*out++ = cb64[remainder];
		*out++ = '=';
		*out++ = '=';
		break;

	case 2:
		*out++ = cb64[remainder];
		*out++ = '=';
		break;
	}

	*out = '\0';

	return (char *)outbuf;
}

/*
 * Decode len bytes starting at in using base64 encoding into out.
 * Result is *not* NUL terminated.
 * Written by Luke Mewburn <lukem@NetBSD.org>
 */
const unsigned char decodetable[] = {
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255,  62, 255, 255, 255,  63,
	 52,  53,  54,  55,  56,  57,  58,  59,
	 60,  61, 255, 255, 255,   0, 255, 255,
	255,   0,   1,   2,   3,   4,   5,   6,
	  7,   8,   9,  10,  11,  12,  13,  14,
	 15,  16,  17,  18,  19,  20,  21,  22,
	 23,  24,  25, 255, 255, 255, 255, 255,
	255,  26,  27,  28,  29,  30,  31,  32,
	 33,  34,  35,  36,  37,  38,  39,  40,
	 41,  42,  43,  44,  45,  46,  47,  48,
	 49,  50,  51, 255, 255, 255, 255, 255,
};

ssize_t
base64_decode(const unsigned char *in, size_t ilen, unsigned char *out,
	      size_t olen)
{
	unsigned char *cp;
	size_t	 i;

	cp = out;
	for (i = 0; i < ilen; i += 4) {
		if (cp + 3 > out + olen)
			return (-1);
#define IN_CHECK(x) \
		if ((x) > sizeof(decodetable) || decodetable[(x)] == 255) \
			    return(-1)

		IN_CHECK(in[i + 0]);
		/*LINTED*/
		*(cp++) = decodetable[in[i + 0]] << 2
			| decodetable[in[i + 1]] >> 4;
		IN_CHECK(in[i + 1]);
		/*LINTED*/
		*(cp++) = decodetable[in[i + 1]] << 4
			| decodetable[in[i + 2]] >> 2;
		IN_CHECK(in[i + 2]);
		*(cp++) = decodetable[in[i + 2]] << 6
			| decodetable[in[i + 3]];
#undef IN_CHECK
	}
	while (in[i - 1] == '=')
		cp--,i--;
	return (cp - out);
}
