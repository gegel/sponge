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

 //SpongePRG implementation
 //This code based on: http://eprint.iacr.org/2011/499.pdf
 //Self-thread

// #define USE_SYSTEM_SEED

#ifdef USE_SYSTEM_SEED
 #ifdef _WIN32
  #include <Windows.h>
  #include <Wincrypt.h>
 #else
  #include <stdio.h>
 #endif
#endif


#include "sponge.h"
#include "sprng.h"
#define RATE (cKeccakR/8-1)

static KECCAK512_DATA sponge;
static unsigned avaliable = 0;
static char mutex=1;

//Sponge state protection
void waitMutex(void)
{
 do
 {
  while(mutex)
  {
   ;
  }
  mutex++;
 }while(mutex!=1);
}

//PRG initialization using external and system seeds
int randInit(uchar const *seed, int len)
{
 int ret=0;
 uchar sysrand[64];
 memset(sysrand, 0, sizeof(sysrand));
 //once use system PRG for initialization
 #ifdef USE_SYSTEM_SEED
  do {
  #ifdef _WIN32
    HCRYPTPROV prov;

    if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))  {
        break;
    }

    if (!CryptGenRandom(prov, sizeof(sysrand), sysrand))  {
        CryptReleaseContext(prov, 0);
        break;
    }
    CryptReleaseContext(prov, 0);
    ret=1;
  #else
    FILE *f = fopen("/dev/urandom", "rb");

    if (f == NULL) {
        break;
    }

    fread(sysrand, 1, sizeof(sysrand), f);
    fclose(f);
    ret=1;
  #endif
  } while(0);
 #endif
 //Initialization (duplex mode)
 Sponge_init(&sponge, sysrand, sizeof(sysrand), 0, 0); //Inites Sponge by system rands
 avaliable=RATE;  //sysrand comletely processed, block of random avaliable now
 if((seed)&&(len))
 {
  Sponge_data(&sponge, seed, len, 0, SP_DUPLEX); //Absorbing seed
  if(sponge.bytesInQueue) avaliable=0; //no randoms avaliable now: seed not comletely processed yet
 }
 memset(sysrand, 0, sizeof(sysrand)); //Clears sysrand
 mutex=0;   //release mutex: PRG is ready now
 return ret;
}


//PRG feed request (reseeding)
void randFeed(uchar const *seed, int len)
{
 waitMutex();
 Sponge_data(&sponge, seed, len, 0, SP_DUPLEX); //absorbing entropy
 //some bytes of seed can remained in sponge state - not all seed processed
 if(sponge.bytesInQueue>0) avaliable=0; //in this case no random bytes avaliable yet
 else avaliable=RATE; //otherwise a full block of random is avaliable
 mutex=0;
}

//PRG feed request (generates random)
void randFetch(uchar *randout, int len)
{
 waitMutex();
 if((sponge.bytesInQueue)||(!avaliable)) //first process remaining seed bytes
 {
  Sponge_data(&sponge, 0, 0, 0, SP_DUPLEX|SP_FORCE); //process seed bytes in queue
  avaliable=RATE; //now avaliable full block of random data
 }

 for ( /* empty */; len>0; len-- ) //outputs avaliable random data first
 {
  (*randout++)=sponge.state[RATE-avaliable]; //squeezing avaliable random bytes
  if(avaliable--) continue;
  Sponge_data(&sponge, 0, 0, 0, SP_DUPLEX|SP_FORCE); //permute state for get new block of avaliable random data
  avaliable=RATE;
 }
 mutex=0;
}

//PRG forgen request
void randForget(void)
{
 waitMutex();
 Sponge_data(&sponge, 0, 0, 0, SP_FORGET); //forgets state
 avaliable=RATE;
 mutex=0;
}

//PRG securety destroy
void randDestroy(void)
{
 waitMutex();
 Sponge_finalize(&sponge, 0, 0); //no F calls, cleares state only
}


#if 0

#include <stdio.h>

void
dumprand(unsigned count)
{
	uchar c;

	printf("%u random bytes:\n", count);

	while (count--) {
		randFetch(&c, 1);
		printf("%02x ", (unsigned)c);
	}
	putchar('\n');
}

int
main(int argc, char **argv)
{
	int len;

	while (--argc) {
		len = strlen(*++argv);
		printf("Adding \"%.*s\\0\" to pool.\n", len, *argv);
		randFeed((uchar *)*argv, len+1);
	}
	dumprand(100);
	return 0;
}

#endif
