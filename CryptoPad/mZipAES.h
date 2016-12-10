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
   mZipAES.h

   A micro reader & writer for AES encrypted ZIP archives.

   Functions are provided to create in memory a deflated and AES-256 encrypted
   ZIP archive from a single input, and to extract from such an archive.

   Zlib is required to support Deflate algorithm.
   
   Cryptographic functions (i.e. PBKDF2 keys derivation, SHA-1 HMAC, AES 
   encryption) require one of these kits: OpenSSL or LibreSSL, Botan,
   GNU libgcrypt or Mozilla NSS.
*/

#if !defined(__MZIPAES__)
#define __MZIPAES__

# ifdef  __cplusplus
extern "C" {
# endif

#define MZAE_ERR_SUCCESS			0
#define MZAE_ERR_PARAMS				1
#define MZAE_ERR_CODEC				2
#define MZAE_ERR_SALT				3
#define MZAE_ERR_KDF				4
#define MZAE_ERR_AES				5
#define MZAE_ERR_HMAC				6
#define MZAE_ERR_NOMEM				7
#define MZAE_ERR_BUFFER				8
#define MZAE_ERR_BADZIP				9
#define MZAE_ERR_BADVV				10
#define MZAE_ERR_BADHMAC			11
#define MZAE_ERR_BADCRC				12
#define MZAE_ERR_NOPW				13



/*
	Translates one of the error codes above into a textual message.
	
	Returns a pointer to the error message.
*/
char* MZAE_errmsg(int code);



/*
	Creates a Deflated and AES-256 encrypted ZIP archive in memory from a single
	input. The unique archived file name defaults to "data".

	src		uncompressed data to archive
	srcLen		length of src buffer
	dst		pre allocated buffer receiving the resulting ZIP archive
	dstLen		length of dst buffer
	password	ASCII password used to encrypt

	Returns zero for success.
	If called with dstLen set to zero, fills it with the required number of bytes.
*/
int MiniZipAE1Write(char* src, unsigned long srcLen, char** dst, unsigned long *dstLen, char* password);



/*
	Extracts in memory the single file from a Deflated and AES encrypted ZIP
	archive created with MiniZipAE1Write function (accepts any key strength).

	src		compatible ZIP archive to extract from
	srcLen		length of src buffer
	dst		pre allocated buffer for the extracted data
	dstLen		length of dst buffer
	password	ASCII password required to decrypt

	Returns zero for success.
	If called with dstLen set to zero, fills it with the required number of bytes.
*/
int MiniZipAE1Read(char* src, unsigned long srcLen, char** dst, unsigned long *dstLen, char* password);



/*
	Generates a random salt for the keys derivation function.
	
	salt		a pre allocated buffer receiving the salt
	saltlen		length of the required salt (must be 8, 12 or 16)

	Returns zero for success.
*/
int MZAE_gen_salt(char* salt, int saltlen);


/*
	Generates keys for AES encryption and HMAC-SHA1, plus a 16-bit verification
	value, from a password and a random salt.
	
	password	password to encrypt and authenticate archive contents
	salt		the random salt generated with AE_gen_salt
	saltlen		its length
	aes_key		pointer receiving the address of the generated AES key
	hmac_key	pointer receiving the address of the generated HMAC key
	vv			pointer receiving the address of the verification value

	Returns zero for success.
*/
int MZAE_derive_keys(char* password, char* salt, int saltlen, char** aes_key, char** hmac_key, char** vv);


/*
	Encrypts data into a newly allocated buffer, using AES in CTR mode with a
	little endian counter.
	
	key			the AES key computated with AE_derive_keys
	keylen		its length in bytes
	src			points to the data to encrypt
	srclen		length of the data to encrypt
	dst			pointer receiving the address of the encrypted data buffer

	Returns zero for success.
*/
int MZAE_ctr_crypt(char* key, unsigned int keylen, char* src, unsigned int srclen, char** dst);


/*
	Computates the HMAC-SHA1 for a given buffer.
	
	key			the HMAC key computated with AE_derive_keys
	keylen		its length in bytes
	src			points to the data to calculate the HMAC for
	srclen		length of such data
	dst			pointer receiving the address of the HMAC string

	Returns zero for success.
*/
int MZAE_hmac_sha1_80(char* key, unsigned int keylen, char* src, unsigned int srclen, char** hmac);


/*
	Computates the ZIP crc32.
	
	crc			initial crc value to update
	src			source buffer
	srclen		its length

	Returns the computated CRC.
*/
unsigned long MZAE_crc(unsigned long crc, char* src, unsigned int srclen);


/*
	One pass deflate.
	
	src			uncompressed data
	srclen		its length
	dst			pointer receiving the address of the compressed data
	dstlen		pointer receiving the length of the compressed data


	Returns zero for success.
*/
int MZAE_deflate(char* src, unsigned int srclen, char** dst, unsigned int* dstlen);


/*
	One pass inflate.
	
	src			compressed data
	srclen		its length
	dst			pre-allocated buffer receiving the uncompressed data
	dstlen		its length


	Returns zero for success.
*/
int MZAE_inflate(char* src, unsigned int srclen, char* dst, unsigned int dstlen);

# ifdef  __cplusplus
}
# endif

#endif // __MZIPAES__
