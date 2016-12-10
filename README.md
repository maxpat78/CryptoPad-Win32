CryptoPad
=========

This is a Win32 partner of my Python CryptoPad (https://github.com/maxpat78/CryptoPad) and Java JCryptoPad (https://github.com/maxpat78/JCryptoPad) projects, built on top of CryptoCmd stuff (https://github.com/maxpat78/CryptoCmd) and licensed under GNU GPL v2.

Unlike previous projects, in addition to special ZIP AE-1 format this notepad app can handle plain text files in major Windows encodings (ASCII, UTF-16 LE & BE, UTF-8) and with any line endings (CR, LF, CRLF).

Thanks to the CryptoCmd high level API, it is able to read and write its own special text documents, which are simple ZIP archives deflated and encrypted with AES for maximum security and portability.

My simplified document format imposes some restrictions on the resulting ZIP archive:

1. a fixed filename length of 4 bytes ("data");
2. a single extra field (the AES header);
3. Deflate compression always;
4. 256-bit key strength (but can decrypt with smaller keys);
5. text encoded in UTF-8 without BOM, CR-LF ended.

The well known AE-1 specification from WinZip[1] is implemented, so one of the following cryptographic toolkits/libraries is required to run the app:

- libeay32/libcrypto from OpenSSL[2] or LibreSSL[3]: actually this is the only crypto driver included by default
- Botan[4]
- NSS3 from Mozilla[5]
- Libgcrypt from GNU project[6]


[1] See http://www.winzip.com/aes_info.htm

[2] See https://www.openssl.org/

[3] See https://www.libressl.org/

[4] See http://botan.randombit.net/

[5] See https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS

[6] See https://www.gnu.org/software/libgcrypt/

