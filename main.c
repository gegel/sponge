 ///////////////////////////////////////////////
//
// **************************
// ** ENGLISH - 14/03/2013 **
//
// Project/Software name: sponge.lib
// Author: "Van Gegel" <gegelcopy@ukr.net>
//
// THIS IS A FREE SOFTWARE  AND FOR TEST ONLY!!!
// Please do not use it in the case of life and death
// This software is released under GNU LGPL:
//
// * LGPL 3.0 <http://www.gnu.org/licenses/lgpl.html>
//
// You’re free to copy, distribute and make commercial use
// of this software under the following conditions:
//
// * You have to cite the author (and copyright owner): Van Gegel
// * You have to provide a link to the author’s Homepage: <http://torfone.org>
//
///////////////////////////////////////////////


#include <stdio.h>
#include <stdlib.h>
#include<string.h>
#include "sponge.h"
#include "sprng.h"

#pragma argsused

void ihex2asc(unsigned  char* input, int bytes, char* info)
{
 int i;
 char output[257];
 if(bytes>128) bytes=128;
 output[0]=0;
 if(bytes) for (i=0;i<bytes;i++) sprintf(output+strlen(output), "%02X", (unsigned int)input[i]);
 printf("%s%s\r\n", info, output);
}




  int
main(int argc, char **argv) {
//Keccak page: http://keccak.noekeon.org/files.html

//Reference document: http://keccak.noekeon.org/Keccak-reference-3.0.pdf

//Sponge theory:
//http://sponge.noekeon.org/CSF-0.1.pdf
//http://sponge.noekeon.org/SpongePRNG.pdf
//http://www.wil.waw.pl/art_prac/2013/MCC/5.pdf
//http://csrc.nist.gov/groups/ST/hash/sha-3/Round2/Aug2010/documents/presentations/DAEMEN_SpongeDuplexSantaBarbaraSlides.pdf
//http://eprint.iacr.org/2011/499.pdf

//Code source:
//http://keccak.noekeon.org/Keccak-reference-3.0-files.zip
//Keccak-compact.c
//mode B/R = 1600/576

//Test vectors:
//http://keccak.noekeon.org/KeccakKAT-3.zip
//ShortMsgKAT_512.txt
//
/*
Line 37:
Len = 8
Msg = CC
MD = 8630C13CBD066EA74BBE7FE468FEC1DEE10EDC1254FB4C1B7C5FD69B646E44160B8CE01D05A0908CA790DFB080F4B513BC3B6225ECE7A810371441A5AC666EB9

Line 69:
Len = 16
Msg = 41FB
MD = 551DA6236F8B96FCE9F97F1190E901324F0B45E06DBBB5CDB8355D6ED1DC34B3F0EAE7DCB68622FF232FA3CECE0D4616CDEB3931F93803662A28DF1CD535B731
*/

const unsigned char data1[1]={0xCC};
const unsigned char vect1[64]={0x86, 0x30, 0xC1, 0x3C,
 0xBD, 0x06, 0x6E, 0xA7, 0x4B, 0xBE, 0x7F, 0xE4, 0x68,
 0xFE, 0xC1, 0xDE, 0xE1, 0x0E, 0xDC, 0x12, 0x54, 0xFB,
 0x4C, 0x1B, 0x7C, 0x5F, 0xD6, 0x9B, 0x64, 0x6E, 0x44,
 0x16, 0x0B, 0x8C, 0xE0, 0x1D, 0x05, 0xA0, 0x90, 0x8C,
 0xA7, 0x90, 0xDF, 0xB0, 0x80, 0xF4, 0xB5, 0x13, 0xBC,
 0x3B, 0x62, 0x25, 0xEC, 0xE7, 0xA8, 0x10, 0x37, 0x14,
 0x41, 0xA5, 0xAC, 0x66, 0x6E, 0xB9};

const unsigned char data2[2]={0x41, 0xFB};
const unsigned char vect2[64]={0x55, 0x1D, 0xA6, 0x23,
 0x6F, 0x8B, 0x96, 0xFC, 0xE9, 0xF9, 0x7F, 0x11, 0x90,
 0xE9, 0x01, 0x32, 0x4F, 0x0B, 0x45, 0xE0, 0x6D, 0xBB,
 0xB5, 0xCD, 0xB8, 0x35, 0x5D, 0x6E, 0xD1, 0xDC, 0x34,
 0xB3, 0xF0, 0xEA, 0xE7, 0xDC, 0xB6, 0x86, 0x22, 0xFF,
 0x23, 0x2F, 0xA3, 0xCE, 0xCE, 0x0D, 0x46, 0x16, 0xCD,
 0xEB, 0x39, 0x31, 0xF9, 0x38, 0x03, 0x66, 0x2A, 0x28,
 0xDF, 0x1C, 0xD5, 0x35, 0xB7, 0x31};


int i;
KECCAK512_DATA st;

unsigned char plane1[512]={0};
unsigned char plane2[256]={0};
unsigned char cifer1[512]={0};
unsigned char cifer2[256]={0};
unsigned char decr1[512]={0};
unsigned char decr2[256]={0};
unsigned char pdat[512]={0};
unsigned char key[16]={0};
unsigned char tag[16]={0};
unsigned char tag0[16]={0};
unsigned char tag1[16]={0};
unsigned char tag2[16]={0};
unsigned char tag3[16]={0};
unsigned char tag4[16]={0};
unsigned char hash[64]={0};
unsigned char hash1[64]={0};
unsigned char hash2[64]={0};
unsigned char hash3[64]={0};

ihex2asc(0, 0, "Keccak Universal Sponge portable C release");
ihex2asc(0, 0, "For testing only! Van Gegel, 2014");
ihex2asc(0, 0, "Algo from: http://eprint.iacr.org/2011/499.pdf");
ihex2asc(0, 0, "Source from: http://keccak.noekeon.org/Keccak-reference-3.0-files.zip");
ihex2asc(0, 0, "Based in: Keccak-compact.c Mode: B/R = 1600/576");
ihex2asc(0, 0, "Vectors: http://keccak.noekeon.org/KeccakKAT-3.zip\r\n");

//Integrity test
ihex2asc(0, 0, "Expected vector: Len=8 Msg=CC MD=8630C13C...");
crypto_hash( hash, data1, 1 );
sponge_hash_512(hash1, data1, 1 );
ihex2asc(hash,4,"Ref MD: "); //print ref hash
for(i=0;i<64;i++) if(hash1[i]!=vect1[i]) break;  //compare our hash with vector
if(i==64) ihex2asc(0,0,"Test 1 OK");
else ihex2asc(hash1,4,"Test 1 failure: ");   //print our hash if failure

ihex2asc(0, 0, "\r\nExpected vector: Len=16 Msg=41FB MD=551DA623...");
crypto_hash( hash, data2, 2 );   //reference code
sponge_hash_512(hash1, data2, 2 );  //our code
ihex2asc(hash,4,"Ref MD: "); //print ref hash
for(i=0;i<64;i++) if(hash1[i]!=vect2[i]) break; //compare our hash with vector
if(i==64) ihex2asc(0,0,"Test 2 OK");
else ihex2asc(hash1,4,"Test 2 failure: ");  //print our hash if failure

//Tests settings:

 for(i=0; i<270; i++) plane1[i]=0x30+i%10;
 memcpy(plane2, plane1+135, 135);
 memset(cifer1, 0, 270);
 memset(cifer2, 0, 135);
 memset(decr1, 0, 270);
 memset(decr2, 0, 135);
 memset(tag, 0, 16);
 memset(tag0, 0, 16);
 memset(tag1, 0, 16);
 memset(tag2, 0, 16);
 memset(tag3, 0, 16);
 memset(tag4, 0, 16);
 memset(hash, 0, 64);
 memset(hash1, 0, 64);
 memset(hash2, 0, 64);
 memset(hash3, 0, 64);
 memset(key, 0x35, 16);

 ihex2asc(plane1,32,"\r\nMessg: ");
 //Block boundary tests
 ihex2asc(0,0, "\r\nBlock boundary tests:");
 sponge_hash_512(hash1, plane1, 71 );  //less then one block
 crypto_hash( hash, plane1, 71 );  //ethalon
 ihex2asc(0,0, "71 bytes: less then one block");
 ihex2asc(hash1,32,"Hash: ");
 ihex2asc(hash,32,"Refs: ");

 sponge_hash_512(hash1, plane1, 72 ); //exectly one block
 crypto_hash( hash, plane1, 72 );  //ethalon
 ihex2asc(0,0, "72 bytes: exectly one block");
 ihex2asc(hash1,32,"Hash: ");
 ihex2asc(hash,32,"Refs: ");

 sponge_hash_512(hash1, plane1, 73 ); //more then one block
 crypto_hash( hash, plane1, 73 );  //ethalon
 ihex2asc(0,0, "73 bytes: more then one block");
 ihex2asc(hash1,32,"Hash: ");
 ihex2asc(hash,32,"Refs: ");


 //incremental hashing test:
 ihex2asc(0,0, "\r\nIncremental hashing test:");
 i=135; //Lenth of message part
 Sponge_init(&st, 0, 0, 0, 0); //initializing
 Sponge_data(&st, plane1, i, 0, SP_NORMAL); //absorbing input
 Sponge_data(&st, plane1+i, i, 0, SP_NORMAL); //absorbing input
 Sponge_finalize(&st, hash1, 64); //squeezing hash
 ihex2asc(hash1,32,"135+135 bytes ");
      //Other boundaries
 Sponge_init(&st, 0, 0, 0, 0); //initializing
 Sponge_data(&st, plane1, i+1, 0, SP_NORMAL); //absorbing input
 Sponge_data(&st, plane1+i+1, i-1, 0, SP_NORMAL); //absorbing input
 Sponge_finalize(&st, hash2, 64); //squeezing hash
 ihex2asc(hash2,32,"136+134 bytes ");
      //One-pass
 sponge_hash_512(hash3, plane1, i*2 );
 ihex2asc(hash3,32,"270 bytes msg ");
      //Refference
 crypto_hash( hash, plane1, i*2 );
 ihex2asc(hash1,32,"Ref 270 bytes ");


 //incremental hmac test:
 ihex2asc(0,0, "\r\nIncremental hmac test:");
 i=135; //Length of message part
 Sponge_init(&st, key, 16, 0, 0); //absorbing autentification key
 ihex2asc(key,16, "Key: ");
 Sponge_data(&st, plane1, i, 0, SP_NORMAL); //absorbing input
 Sponge_data(&st, plane1+i, i, 0, SP_NORMAL); //absorbing input
 Sponge_finalize(&st, tag1, 16); //squeezing autentication tag
 ihex2asc(tag1,16,"135+135 bytes ");
      //Other boundaries
 Sponge_init(&st, key, 16, 0, 0); //absorbing autentification key
 Sponge_data(&st, plane1, i+1, 0, SP_NORMAL); //absorbing input
 Sponge_data(&st, plane1+i+1, i-1, 0, SP_NORMAL); //absorbing input
 Sponge_finalize(&st, tag2, 16); //squeezing autentication tag
 ihex2asc(tag2,16,"136+134 bytes ");
      //One-pass
 sponge_hmac_128(tag3, key, 16, plane1, i*2 );
 ihex2asc(tag3,16,"270 bytes msg ");

 //Stream encryption test
 ihex2asc(0,0, "\r\nStream encryption test:");
 memcpy(pdat, plane1+i-16, 32);
 pdat[32]=0;
 printf("Messg: '...%s...'\r\n", pdat);

 ihex2asc(key,16, "\r\nMsgLen=270 bytes IV=3700 Key=");

 sponge_ctr(cifer1, key, 16, "7", 2, plane1, i*2 );
 sponge_ctr(decr1, key, 16, "7", 2, cifer1, i*2 );

 memcpy(pdat, decr1+i-16, 32);
 pdat[32]=0;
 printf("Plane: '...%s...'\r\n", pdat);

 //Incremental stream encryption test :
 ihex2asc(key,16, "\r\nMsgLen=135+135 bytes, same Msg, IV and Key");
      //encrypt
 Sponge_init(&st, key, 16, 0, 0); //absorb key and initialise state
 Sponge_data(&st, "7", 2, 0, SP_NORMAL); //absorb iv, force permute
 Sponge_data(&st, 0, 0, 0, SP_NORMAL); //process full block
 Sponge_data(&st, plane1, i, cifer1, SP_NOABS); //squeezing gamma, out=in^gamma
 Sponge_data(&st, plane1+i, i, cifer2, SP_NOABS);//squeezing gamma, out=in^gamma
 Sponge_finalize(&st, 0, 0); //destroy state
      //decrypt
 Sponge_init(&st, key, 16, 0, 0); //absorb key and initialise state
 Sponge_data(&st, "7", 2, 0, SP_NORMAL); //absorb iv, permute
 Sponge_data(&st, 0, 0, 0, SP_NORMAL); //process full block
 Sponge_data(&st, cifer1, i, decr1, SP_NOABS); //squeezing gamma, out=in^gamma
 Sponge_data(&st, cifer2, i, decr2, SP_NOABS); //squeezing gamma, out=in^gamma
 Sponge_finalize(&st, 0, 0); //destroy state

 memcpy(pdat, decr1+i-16, 16);
 memcpy(pdat+16, decr2, 16);
 pdat[32]=0;
 printf("Plane: '...%s...'\r\n", pdat);

 //Othe boundaries:
 ihex2asc(key,16, "\r\nMsgLen=136+134 bytes, same Msg, IV and Key");
        //encrypt
 Sponge_init(&st, key, 16, 0, 0); //absorb key and initialise state
 Sponge_data(&st, "7", 2, 0, SP_NORMAL); //absorb iv, permute
 Sponge_data(&st, 0, 0, 0, SP_NORMAL); //process full block
 Sponge_data(&st, plane1, i+1, cifer1, SP_NOABS); //squeezing gamma, out=in^gamma
 Sponge_data(&st, plane1+i+1, i-1, cifer2, SP_NOABS); //squeezing gamma, out=in^gamma
 Sponge_finalize(&st, 0, 0); //destroy state
        //decrypt
 Sponge_init(&st, key, 16, 0, 0); //absorb key and initialise state
 Sponge_data(&st, "7", 2, 0, SP_NORMAL); //absorb iv, permute
 Sponge_data(&st, 0, 0, 0, SP_NORMAL); //process full block
 Sponge_data(&st, cifer1, i+1, decr1, SP_NOABS); //squeezing gamma, out=in^gamma
 Sponge_data(&st, cifer2, i-1, decr2, SP_NOABS); //squeezing gamma, out=in^gamma
 Sponge_finalize(&st, 0, 0); //destroy state

 memcpy(decr1+i+1, decr2, i-1);
 memcpy(pdat, decr1+i-16, 32);
 pdat[32]=0;
 printf("Plane: '...%s...'\r\n", pdat);

 //Autenticated encryption test (WrapMode):
 ihex2asc(0,0, "\r\nAutenticated encryption test (WrapMode):");
 ihex2asc(key,16, "\r\nMsgLen=270 bytes IV=3700 Key=");
 sponge_enc(cifer1, tag, 16, key, 16, "7", 2, plane1, i*2 );
 ihex2asc(cifer1,32,"Cifer: ");
 sponge_dec(decr1, tag0, 16, key, 16, "7", 2, cifer1, i*2 );
 ihex2asc(plane1,32,"Plane: ");
 ihex2asc(tag,16,"Tag_E: ");
 ihex2asc(tag0,16,"Tag_D: ");

 //Incremental Autenticated encryption test (WrapMode):
 ihex2asc(key,16, "\r\nMsgLen=135+135 bytes, same Msg, IV and Key");
 Sponge_init(&st, key, 16, "7", 2); //absorbing key||nonce (frame bit=1)  and header (frame bit=0)
 Sponge_data(&st, plane1, i, cifer1, SP_WRAP1|SP_ENCRYPT); //duplex wrap encryption mode (frame bit=1)
 Sponge_data(&st, plane1+i, i, cifer2, SP_WRAP1|SP_ENCRYPT); //duplex wrap encryption mode (frame bit=1)
 Sponge_finalize(&st, tag1, 16); //squeezing autentication tag

 Sponge_init(&st, key, 16, "7", 2); //absorbing key||nonce (frame bit=1)  and header (frame bit=0)
 Sponge_data(&st, cifer1, i, decr1, SP_WRAP1|SP_DECRYPT); //duplex wrap decryption mode (frame bit=1)
 Sponge_data(&st, cifer2, i, decr2, SP_WRAP1|SP_DECRYPT); //duplex wrap decryption mode (frame bit=1)
 Sponge_finalize(&st, tag2, 16); //squeezing autentication tag

 ihex2asc(tag1,16,"Tag_E: ");
 ihex2asc(tag2,16,"Tag_D: ");

 //Other boundaries:
 ihex2asc(key,16, "\r\nMsgLen=136+134 bytes, same Msg, IV and Key");
 Sponge_init(&st, key, 16, "7", 2); //absorbing key||nonce (frame bit=1)  and header (frame bit=0)
 Sponge_data(&st, plane1, i+1, cifer1, SP_WRAP1|SP_ENCRYPT); //duplex wrap encryption mode (frame bit=1)
 Sponge_data(&st, plane1+i+1, i-1, cifer2, SP_WRAP1|SP_ENCRYPT); //duplex wrap encryption mode (frame bit=1)
 Sponge_finalize(&st, tag3, 16); //squeezing autentication tag


 Sponge_init(&st, key, 16, "7", 2); //absorbing key||nonce (frame bit=1)  and header (frame bit=0)
 Sponge_data(&st, cifer1, i+1, decr1, SP_WRAP1|SP_DECRYPT); //duplex wrap decryption mode (frame bit=1)
 Sponge_data(&st, cifer2, i-1, decr2, SP_WRAP1|SP_DECRYPT); //duplex wrap decryption mode (frame bit=1)
 Sponge_finalize(&st, tag4, 16); //squeezing autentication tag

 ihex2asc(tag3,16,"Tag_E: ");
 ihex2asc(tag4,16,"Tag_D: ");


 //SpongePRG test
ihex2asc(0,0, "\r\nSpongePRG test:");

memset(pdat, 0x33, 75);  //this is a seed
i=randInit(pdat, 75); //Init PRG (see sprng.c for use system entropy)

randFetch(plane1, 60); //feed: absorb remaining seed, permute and squeeze block of random
ihex2asc(plane1,32,"");
randFetch(plane2, 75);
ihex2asc(plane2,32,"");

memset(pdat, 0x01, 1); //adds very small entropy
randFeed(pdat, 1);     //absorb seed

randFetch(cifer1, 61);
ihex2asc(cifer1,32,"");
randFetch(cifer2, 77);
ihex2asc(cifer2,32,"");

randForget(); //forgets state: zeroes part of state, permute and squeeze block of random

randFetch(decr1, 62);
ihex2asc(decr1,32,"");
randFetch(decr2, 79);
ihex2asc(decr2,32,"");

randDestroy(); //secure destroy data

//KDF test:
 printf("\r\nkdf test:");
 printf("Salt: 'salt', Pass: 'password', Keylen=100 bytes\r\n");
 sponge_kdf(pdat, 100, "salt", 4, "password", 8, 0 );
 ihex2asc(pdat, 16, "No itterations(kdf): ");
 printf("Pleas wait, pkdf test running...\r\n");
 sponge_kdf(pdat, 100, "salt", 4, "password", 8, 20000 );
 ihex2asc(pdat, 16, "20000   itterations: ");

 return 0;
}
