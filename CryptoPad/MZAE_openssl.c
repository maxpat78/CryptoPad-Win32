/*
 *  Copyright (C) 2016  <maxpat78> <https://github.com/maxpat78>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
	Cryptographic functions built on top of OpenSSL/LibreSSL
*/

#include <mZipAES.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>


#ifdef BYTE_ORDER_1234
void betole64(unsigned long long *x) {
*x = (*x & 0x00000000FFFFFFFF) << 32 | (*x & 0xFFFFFFFF00000000) >> 32;
*x = (*x & 0x0000FFFF0000FFFF) << 16 | (*x & 0xFFFF0000FFFF0000) >> 16;
*x = (*x & 0x00FF00FF00FF00FF) << 8  | (*x & 0xFF00FF00FF00FF00) >> 8;
}
#endif



int MZAE_gen_salt(char* salt, int saltlen)
{
	RAND_poll();
	RAND_screen();

	if (saltlen != 8 && saltlen != 12 && saltlen != 16)
		return 1;
	
	if (!RAND_bytes(salt, saltlen) || !RAND_pseudo_bytes(salt, saltlen))
		return 2;
	
	return 0;
}



int MZAE_derive_keys(char* password, char* salt, int saltlen, char** aes_key, char** hmac_key, char** vv)
{
	int keylen = 0;
	char *kdfbuf;

	if (saltlen == 8)
		keylen = 16;
	else if (saltlen == 12)
		keylen = 24;
	else if (saltlen == 16)
		keylen = 32;
	else
		return 1;
	
	kdfbuf = (char*) malloc(2*keylen+2);
	if (! kdfbuf)
		return 2;
	
	if (!PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), salt, saltlen, 1000, 2*keylen+2, kdfbuf))
		return 3;
	
	*aes_key = kdfbuf;
	*hmac_key = kdfbuf+keylen;
	*vv = kdfbuf+2*keylen;

	return 0;
}



int MZAE_ctr_crypt(char* key, unsigned int keylen, char* src, unsigned int srclen, char** dst)
{
	AES_KEY aes_key;
	char ctr_counter_le[16];
	char ctr_encrypted_counter[16];
#ifdef BYTE_ORDER_1234
	char ctr_counter_be[16];
#endif
	const char* p = ctr_encrypted_counter;
	const char* q = p+8;
	char *pbuf;
	unsigned int i;

	if (!keylen || !srclen)
		return -1;

	if (AES_set_encrypt_key(key, keylen*8, &aes_key))
		return 1;

#ifdef BYTE_ORDER_1234
	memset(ctr_counter_be, 0, 16);
#else
	memset(ctr_counter_le, 0, 16);
#endif
	
	*dst = pbuf = (char*) malloc(srclen);
	if (!pbuf)
		return 2;

	for (i=0; i < srclen/16; i++) {
#ifndef BYTE_ORDER_1234
		(*((unsigned long long*) ctr_counter_le))++;
#else	
		(*((unsigned long long*) ctr_counter_be))++;
		*((unsigned long long*) ctr_counter_le) = *((unsigned long long*) ctr_counter_be);
		betole64((unsigned long long*)ctr_counter_le);
#endif
		AES_ecb_encrypt(ctr_counter_le, ctr_encrypted_counter, &aes_key, 1);
		*((unsigned long long*) pbuf) = *((unsigned long long*) src) ^ *((unsigned long long*) p);
		pbuf+=sizeof(long long);
		src+=sizeof(long long);
		*((unsigned long long*) pbuf) = *((unsigned long long*) src) ^ *((unsigned long long*) q);
		pbuf+=sizeof(long long);
		src+=sizeof(long long);
	}

	if ((i = srclen%16)) {
#ifndef BYTE_ORDER_1234
		(*((unsigned long long*) ctr_counter_le))++;
#else	
		(*((unsigned long long*) ctr_counter_be))++;
		*((unsigned long long*) ctr_counter_le) = *((unsigned long long*) ctr_counter_be);
		betole64((unsigned long long*)ctr_counter_le);
#endif
		AES_ecb_encrypt(ctr_counter_le, ctr_encrypted_counter, &aes_key, 1);
		while (i--)
			*pbuf++ = *src++ ^ *p++;
	}

	return 0;
}



int MZAE_hmac_sha1_80(char* key, unsigned int keylen, char* src, unsigned int srclen, char** hmac)
{
	if (!keylen || !srclen)
		return -1;

	*hmac = HMAC(EVP_sha1(), key, keylen, src, srclen, 0, 0);

	return 0;
}
