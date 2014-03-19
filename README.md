sponge
======

Portable C implementation of universal Sponge construction based on compact Keccak source code

********************************************************************
Sponge based compact portable C cryptographic library.
Author: "Van Gegel" <torfone@ukr.net>.
Date: 12-03-2014.
THIS IS A FREE SOFTWARE  AND FOR TEST ONLY!!!
Please do not use it in the case of life and death.
This software is released under GNU LGPL:

* LGPL 3.0 <http://www.gnu.org/licenses/lgpl.html>.
You're free to copy, distribute and make commercial use
of this software under the following conditions:
* You have to cite the author (and copyright owner): Van Gegel
* You have to provide a link to the author's Homepage: <http://torfone.org>
********************************************************************

Portable C implementation of universal Sponge construction based on compact Keccak source from:
http://keccak.noekeon.org/Keccak-reference-3.0-files.zip   // Keccak-compact.c and use mode B/R = 1600/576
Implemented modes: normal Sponge, duplex Sponge, Wrap mode based on document http://eprint.iacr.org/2011/499.pdf

Some test vectors for checking code integrity: http://keccak.noekeon.org/KeccakKAT-3.zip //ShortMsgKAT_512.txt

********************************************************************

Only three procedures provide functionality to set parameters:

--------------------------------------------------------------------
void Sponge_init(KECCAK512_DATA *keccak, 
const BYTE *key, int klen, const BYTE *header, int hlen);
--------------------------------------------------------------------
During initialization Sponge absorb key (universal key, key-material, seed, nonce, vector, key-info, prefix etc.) and then header (only for SpongeWrap mode).  Both key length and header length can be up to 71 bytes otherwise be truncated to this length.
If the key  is not specified  or keylen is 0  the Sponge object is only initialized otherwise performed  F-permutation after absorbing the key.
If the both key and header  are  specified  will be performed two F-permutation separately for each parameter. In this case  the frame bit  (0 for key and 1 for header)  will be added before padding as defined in SpongeWrap mode.

--------------------------------------------------------------------
int Sponge_data(KECCAK512_DATA *keccak, const BYTE *buffer, 
int len, BYTE *output, char mode);
--------------------------------------------------------------------
This is the Sponge Object request type defined by the specified parameters.
Parameter  len  determines the length of data stream processed by Sponge object in current request.
Can be processed any number of bytes. Sponge Object splits stream  into blocks and performs the necessary F-permutations in accordance with   request's parameters.
If len set as 0 will be used value needed for one F-permutation (complete iteration).
Parameters buffer and output defines source for data to / from Sponge object respectively.
If buffer not specified this is "blank" request. 
If output not specified this is "mute" request. 
If both  buffer and output not specified this is iteration only ("blank-mute" request). If buffer specified but output not specified this is "absorbing" request. 
If output specified but buffer is not specified this is "squeezing" request. 
If both buffer and output specified this is a "duplex" request: resulting data will be given to the output are the result of xor  of the input buffer and the previous state of the Sponge object.
After this absorption and F-permutation to be performed. 
Absorption to be performed at the manner will depending  of the mode parameter:

SP_NORMAL - standard mode (as defined for hashing, only last block of absorbing data is padded)
SP_DUPLEX - duplex mode (every block padded before absorbing)
SP_WRAP0, SP_WRAP1 - wrap duplex mode (frame bit 0 or 1 is added to every block before padding)  

SP_ENCRYPT, SP_DECRYPT - specifies the data source for absorption (it should be plain text)
SP_NOABS - input data are not absorbed, despite the presence of the input buffer

SP_FORCE - forces the absorption of the some zero bytes to achieve full block 
SP_FORGET - replaces much of the state to zero bytes then permute making it impossible to restore the previous state.

The parameters can be combined to provide required request of Sponge object.

--------------------------------------------------------------------
void Sponge_finalize(KECCAK512_DATA *keccak, BYTE *tag, int taglen);
--------------------------------------------------------------------
During finalization Sponge provide final padding and F-permutation for squeezing of data up to full block length 72 bytes (hash, tag etc.) follows clears internal state.    
If tag is not specified or taglen is 0 the final F-permutation is not performed  but clears internal state only.

Based on the above primitives as examples were designed ready to use cryptographic functions:
- hashing ( arbitrary data length and fixed output length ) , 
counting mac ( arbitrary data length , fixed key and tag length ) , 
- key derivation ( a small data and salt input, arbitrary length output and specified number of iterations ) ,
streaming encryption (fixed key and vector length, arbitrary data length ) 
- single-pass authenticated encryption ( (fixed key  and vector length, arbitrary data length , fixed tag length) . 
To view the proposed implementation see interface see the files 'sponge.c' and 'sponge.h'. 

Also shown are examples of incremental processing of data stream to broken its into blocks of arbitrary length (see 'main.c')
And finally presents an interface of a cryptographic random number generator SpongePRG (see 'sprng.c' and 'sprng.h').

