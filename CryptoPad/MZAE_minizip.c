/*
 *  Copyright (C) 2016, 2019  <maxpat78> <https://github.com/maxpat78>
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
   Provides high level functions to create and extract a deflated & AES-256
   encrypted ZIP archive in memory.

   My simplified document format imposes:
   1) a fixed filename length of 4 bytes ("data");
   2) a single extra field (the AES header);
   3) Deflate compression always;
   4) 256-bit key strength (but can decrypt with smaller keys);
   5) text encoded in UTF-8 with BOM, CR-LF ended.

   A summary of ZIP archive with strong encryption layout (according to WinZip
   specs: look at http://www.winzip.com/aes_info.htm) follows.
   
  Local file header:
    local file header signature     4 bytes  (0x04034b50)
    version needed to extract       2 bytes
    general purpose bit flag        2 bytes
    compression method              2 bytes
    last mod file time              2 bytes
    last mod file date              2 bytes
    crc-32                          4 bytes
    compressed size                 4 bytes
    uncompressed size               4 bytes
    filename length                 2 bytes
    extra field length              2 bytes

    filename (variable size)
    extra field (variable size)

  Extended AES header (both local & central) based on WinZip 9 specs:
    extra field header      2 bytes  (0x9901)
    size                    2 bytes  (7)
    version                 2 bytes  (1 or 2)
    ZIP vendor              2 bytes  (actually, AE)
    strength                1 byte   (AES 1=128-bit key, 2=192, 3=256)
    actual compression      2 byte   (becomes 0x99 in LENT & CENT)

    content data, as follows:
    random salt (8, 12 or 16 byte depending on key size)
    2-byte password verification value (from PBKDF2 with SHA-1, 1000 rounds)
    AES encrypted data (CTR mode, little endian counter)
    10-byte authentication code for encrypted data from HMAC-SHA1

NOTE: AE-1 preserves CRC-32 on uncompressed data, AE-2 sets it to zero.

  Central File header:
    central file header signature   4 bytes  (0x02014b50)
    version made by                 2 bytes
    version needed to extract       2 bytes
    general purpose bit flag        2 bytes
    compression method              2 bytes
    last mod file time              2 bytes
    last mod file date              2 bytes
    crc-32                          4 bytes
    compressed size                 4 bytes
    uncompressed size               4 bytes
    filename length                 2 bytes
    extra field length              2 bytes
    file comment length             2 bytes
    disk number start               2 bytes
    internal file attributes        2 bytes
    external file attributes        4 bytes
    relative offset of local header 4 bytes

    filename (variable size)
    extra field (variable size)
    file comment (variable size)

  End of central dir record:
    end of central dir signature    4 bytes  (0x06054b50)
    number of this disk             2 bytes
    number of the disk with the
    start of the central directory  2 bytes
    total number of entries in
    the central dir on this disk    2 bytes
    total number of entries in
    the central dir                 2 bytes
    size of the central directory   4 bytes
    offset of start of central
    directory with respect to
    the starting disk number        4 bytes
    zipfile comment length          2 bytes
    zipfile comment (variable size)
*/
#include <mZipAES.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef BYTE_ORDER_1234
	// In the ZIP format numbers are Little Endian
	#define BS16(x) (x & 0xFF00) >> 8 | (x & 0xFF) << 8
	#define BS32(x) (x & 0xFF000000) >> 24 | ((x & 0xFF0000) >> 16) << 8 | ((x & 0xFF00) >> 8) << 16 | (x & 0xFF) << 24 
#endif



int MiniZipAE1Write(char* src, unsigned long srcLen, char** dst, unsigned long *dstLen, char* password)
{
	char *tmpbuf = NULL;
	unsigned int buflen;
	long crc = 0;
	char salt[16];
	char* aes_key;
	char* hmac_key;
	char* vv;
	char *ppbuf;
	char *digest, *p;
	unsigned char ucLocalHeader[45] = {
		0x50, 0x4B, 0x03, 0x04, 0x33, 0x00, 0x01, 0x00,
		0x63, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x04, 0x00, 0x0B, 0x00, 0x64, 0x61,
		0x74, 0x61, 0x01, 0x99, 0x07, 0x00, 0x01, 0x00,
		0x41, 0x45, 0x03, 0x08, 0x00 
	};
	unsigned char ucCentralHeader[61] = {
		0x50, 0x4B, 0x01, 0x02, 0x33, 0x00, 0x33, 0x00,
		0x01, 0x00, 0x63, 0x00, 0x00, 0x00, 0x21, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x0B, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x61,
		0x74, 0x61, 0x01, 0x99, 0x07, 0x00, 0x01, 0x00,
		0x41, 0x45, 0x03, 0x08, 0x00 
	};
	unsigned char ucEndHeader[22] = {
		0x50, 0x4B, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x01, 0x00, 0x3D, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00 
	};
#ifdef USE_TIME
	time_t t;
	struct tm *ptm;
#endif

	if (!srcLen)
		return MZAE_ERR_PARAMS;

	if (MZAE_deflate(src, srcLen, &tmpbuf, &buflen))
		return MZAE_ERR_CODEC;
	
	if (! *dstLen)
	{
		*dstLen = buflen + 156; //(45+28)+61+22
		free(tmpbuf);
		return MZAE_ERR_SUCCESS;
	}

	if (!password || !password[0])
	{
		free(tmpbuf);
		return MZAE_ERR_NOPW;
	}

	if (! *dst || *dstLen < (buflen + 156))
	{
		free(tmpbuf);
		return MZAE_ERR_BUFFER;
	}

	if (MZAE_gen_salt(salt, 16))
	{
		free(tmpbuf);
		return MZAE_ERR_SALT;
	}

	// Encrypts with AES-256 always!
	if (MZAE_derive_keys(password, salt, 16, &aes_key, &hmac_key, &vv))
	{
		free(tmpbuf);
		return MZAE_ERR_KDF;
	}
	
	if (MZAE_ctr_crypt(aes_key, 32, tmpbuf, buflen, &ppbuf))
	{
		free(tmpbuf);
		return MZAE_ERR_AES;
	}

	if (MZAE_hmac_sha1_80(hmac_key, 32, ppbuf, buflen, &digest))
	{
		free(tmpbuf);
		return MZAE_ERR_HMAC;
	}

	crc = MZAE_crc(0, src, srcLen);

	p = *dst;
	memcpy(p, ucLocalHeader, sizeof(ucLocalHeader));

#ifdef BYTE_ORDER_1234
	#define PDW(a, b) *((int*)(p+a)) = BS32(b)
	#define PW(a, b) *((short*)(p+a)) = BS16(b)
#else
	#define PDW(a, b) *((int*)(p+a)) = b
	#define PW(a, b) *((short*)(p+a)) = b
#endif

	// Builds the ZIP Local File Header
#ifdef USE_TIME
	time(&t);
	ptm = localtime(&t);
	PW(10, ptm->tm_hour << 11 | ptm->tm_min << 5 | (ptm->tm_sec / 2));
	PW(12, (ptm->tm_year - 80) << 9 | (ptm->tm_mon+1) << 5 | ptm->tm_mday);
#endif
	PDW(14, crc);
	PDW(18, buflen+28);
	PDW(22, srcLen);

	// Copies the raw contents: salt, check word, encrypted data and HMAC
	memcpy(p + 45, salt, 16);
	memcpy(p + 61, vv, 2);
	memcpy(p + 63, ppbuf, buflen);
	memcpy(p + 63 + buflen, digest, 10);

	p = *dst + 63 + buflen + 10;
	memcpy(p, ucCentralHeader, sizeof(ucCentralHeader));

	// Builds the ZIP Central File Header
#ifdef USE_TIME
	PW(12, ptm->tm_hour << 11 | ptm->tm_min << 5 | (ptm->tm_sec / 2));
	PW(14, (ptm->tm_year - 80) << 9 | (ptm->tm_mon+1) << 5 | ptm->tm_mday);
#endif
	PDW(16, crc);
	PDW(20, buflen + 28);
	PDW(24, srcLen);

	p += 61;
	memcpy(p, ucEndHeader, sizeof(ucEndHeader));
	
	// Builds the End Of Central Dir Record
	PDW(16, 63 + buflen + 10);

	free(tmpbuf);
	free(ppbuf);
	
	return MZAE_ERR_SUCCESS;
}



int MiniZipAE1Read(char* src, unsigned long srcLen, char** dst, unsigned long *dstLen, char* password)
{
	long crc = 0;
	unsigned long compSize, uncompSize, keyLen;
	char *salt, *compdata;
	char* aes_key;
	char* hmac_key;
	char* vv;
	char *digest, *pbuf;

	if (!srcLen)
		return MZAE_ERR_PARAMS;

#ifdef BYTE_ORDER_1234
	#define GDW(a) BS32(*((unsigned int*)(src+a)))
	#define GW(a) BS16(*((unsigned short*)(src+a)))
#else
	#define GDW(a) *((unsigned int*)(src+a))
	#define GW(a) *((unsigned short*)(src+a))
#endif

	// Some sanity checks to ensure it is a compatible ZIP
	if (srcLen < 151)
		return MZAE_ERR_BADZIP;

	keyLen = *((char*)(src + 42));

	if (! (0 < keyLen < 4))
		return MZAE_ERR_BADZIP;

	// Here a ZIP with item name >4 (field 26) is bad, too
	if (GDW(0) != 0x04034B50 || GW(8) != 99 ||
		GW(28) != 11 || GW(34) != 0x9901 || GW(38) != 1 || GW(40) != 0x4541)
		return MZAE_ERR_BADZIP;

	compSize = GDW(18)-(12+(4+keyLen*4)); // size & offset depend on salt size!
	uncompSize = GDW(22);

	if (! *dstLen)
	{
		*dstLen = uncompSize;
		return MZAE_ERR_SUCCESS;
	}

	if (! *dst || *dstLen < uncompSize)
		return MZAE_ERR_BUFFER;

	if (!password || !password[0])
		return MZAE_ERR_NOPW;

	salt = src + 45;
	compdata = src+(45+(4+keyLen*4)+2);
	
	// Here we regenerate the AES key, the HMAC key and the 16-bit verification value
	if (MZAE_derive_keys(password, salt, 4+keyLen*4, &aes_key, &hmac_key, &vv))
		return MZAE_ERR_KDF;
	
	// Compares the 16-bit verification values
	if (GW(45+(4+keyLen*4)) != *((unsigned short*)vv))
		return MZAE_ERR_BADVV;

	// Compares the HMACs
	if (MZAE_hmac_sha1_80(hmac_key, 8*(keyLen+1), compdata, compSize, &digest))
		return MZAE_ERR_HMAC;
	if (memcmp(digest, compdata+compSize, 10))
		return MZAE_ERR_BADHMAC;

	// Decrypts into a temporary buffer
	if (MZAE_ctr_crypt(aes_key, 8*(keyLen+1), compdata, compSize, &pbuf))
		return MZAE_ERR_AES;

	if (MZAE_inflate(pbuf, compSize, *dst, uncompSize))
		return MZAE_ERR_CODEC;
	
	crc = MZAE_crc(0, *dst, uncompSize);

	// Compares the CRCs on uncompressed data
	if (crc != GDW(14))
		return MZAE_ERR_BADCRC;

	free(pbuf);

	return MZAE_ERR_SUCCESS;
}



#ifdef MAIN
#include <stdio.h>
void main()
{
#ifdef MAIN_SAVES
	FILE *f = fopen("test.zip", "wb");
#endif
	char *s = "Questo testo è la sorgente da comprimere e cifrare con MiniZipAE1Write, per poi verificarne l'uguaglianza con il prodotto di MiniZipAE1Read!";
	char *out1, *out2;
	int len1=0, len2=0, r;
	r = MiniZipAE1Write(s, strlen(s), &out1, &len1, "kazookazaa");
	printf("MiniZipAE1Write returned %d: %s (requires %d bytes buffer)\n", r, MZAE_errmsg(r), len1);
	out1 = (char*) malloc(len1);
	r = MiniZipAE1Write(s, strlen(s), &out1, &len1, "kazookazaa");
	printf("MiniZipAE1Write returned %d: %s\n", r, MZAE_errmsg(r));

	r = MiniZipAE1Read(out1, len1, &out2, &len2, "kazookazaa");
	printf("MiniZipAE1Read returned %d: %s (requires %d bytes buffer)\n", r, MZAE_errmsg(r), len2);
	out2 = (char*) malloc(len2);
	r = MiniZipAE1Read(out1, len1, &out2, &len2, "kazookazaa");
	printf("MiniZipAE1Read returned %d: %s\n", r, MZAE_errmsg(r));

	if (len2 != strlen(s) || memcmp(s, out2, len2) != 0)
		printf("SELF TEST FAILED!");
	else
		printf("SELF TEST PASSED!");
#ifdef MAIN_SAVES
	fwrite(out1, 1, len1, f);
	fclose(f);
#endif
}
#endif
