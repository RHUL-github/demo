
//
//  PQCgenKAT_sign.c
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
/* Renamed rng.h to sphincsplus-rng.h */
#include "sphincsplus-rng.h"
/* Renamed api.h to sphincspus-api.h */
#include "sphincsplus-api.h"

#define	MAX_MARKER_LEN		50

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

int		FindMarker(FILE *infile, const char *marker);
int		ReadHex(FILE *infile, unsigned char *A, int Length, char *str);
void	fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L);

char    AlgName[] = "My Alg Name";

int
main()
{
    char                fn_req[32], fn_rsp[32];
    FILE                *fp_req, *fp_rsp;
    unsigned char       seed[48];
    unsigned char       msg[3300];
    unsigned char       entropy_input[48];
    unsigned char       *m, *sm, *m1;
    unsigned long long  mlen, smlen, mlen1;
    int                 count;
    int                 done;
    unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    int                 ret_val;
    
    // Create the REQUEST file
	/* Renamed PQCsignKAT_%d.req to sphincsplus-PQCsignKAT_%d.req */
    sprintf(fn_req, "sphincsplus-PQCsignKAT_%d.req", CRYPTO_SECRETKEYBYTES);
    if ( (fp_req = fopen(fn_req, "w")) == NULL ) {
        printf("Couldn't open <%s> for write\n", fn_req);
        return KAT_FILE_OPEN_ERROR;
    }
	/* Renamed PQCsignKAT_%d.rsp to sphincsplus-PQCsignKAT_%d.rsp */
    sprintf(fn_rsp, "sphincsplus-PQCsignKAT_%d.rsp", CRYPTO_SECRETKEYBYTES);
    if ( (fp_rsp = fopen(fn_rsp, "w")) == NULL ) {
        printf("Couldn't open <%s> for write\n", fn_rsp);
        return KAT_FILE_OPEN_ERROR;
    }
    
    for (int i=0; i<48; i++)
        entropy_input[i] = i;

    randombytes_init(entropy_input, NULL, 256);
    for (int i=0; i<100; i++) {
        fprintf(fp_req, "count = %d\n", i);
        randombytes(seed, 48);
        fprintBstr(fp_req, "seed = ", seed, 48);
        mlen = 33*(i+1);
		/* Renamed "mlen" to "message length" */
        fprintf(fp_req, "message length = %llu\n", mlen);
        randombytes(msg, mlen);
		/* Renamed "msg" to "message" */
        fprintBstr(fp_req, "message = ", msg, mlen);
		/* Renamed "pk" to "public key" */
        fprintf(fp_req, "public key =\n");
		/* Renamed "sk" to "secret key" */
        fprintf(fp_req, "secret key =\n");
		/* Renamed "smlen" to "signed message length" */
        fprintf(fp_req, "signed message length =\n");
		/* Renamed "sm" to "signed message" */
        fprintf(fp_req, "signed message =\n\n");
    }
    fclose(fp_req);
    
    //Create the RESPONSE file based on what's in the REQUEST file
    if ( (fp_req = fopen(fn_req, "r")) == NULL ) {
        printf("Couldn't open <%s> for read\n", fn_req);
        return KAT_FILE_OPEN_ERROR;
    }
    
    fprintf(fp_rsp, "# %s\n\n", CRYPTO_ALGNAME);
    done = 0;
    do {
        if ( FindMarker(fp_req, "count = ") )
            fscanf(fp_req, "%d", &count);
        else {
            done = 1;
            break;
        }
        fprintf(fp_rsp, "count = %d\n", count);
        
        if ( !ReadHex(fp_req, seed, 48, "seed = ") ) {
            printf("ERROR: unable to read 'seed' from <%s>\n", fn_req);
            return KAT_DATA_ERROR;
        }
        fprintBstr(fp_rsp, "seed = ", seed, 48);
        
        randombytes_init(seed, NULL, 256);
        
		/* Renamed "mlen" to "message length" */
        if ( FindMarker(fp_req, "message length = ") )
            fscanf(fp_req, "%llu", &mlen);
        else {
			/* Renamed 'mlen' to 'message length' */
            printf("ERROR: unable to read 'message length' from <%s>\n", fn_req);
            return KAT_DATA_ERROR;
        }
		/* Renamed "mlen" to "message length" */
        fprintf(fp_rsp, "message length = %llu\n", mlen);
        
        m = (unsigned char *)calloc(mlen, sizeof(unsigned char));
        m1 = (unsigned char *)calloc(mlen+CRYPTO_BYTES, sizeof(unsigned char));
        sm = (unsigned char *)calloc(mlen+CRYPTO_BYTES, sizeof(unsigned char));
        
		/* Renamed "msg" to "message" */
        if ( !ReadHex(fp_req, m, (int)mlen, "message = ") ) {
			/* Renamed 'msg' to 'message' */
            printf("ERROR: unable to read 'message' from <%s>\n", fn_req);
            return KAT_DATA_ERROR;
        }
		/* Renamed "msg" to "message" */
        fprintBstr(fp_rsp, "message = ", m, mlen);
        
        // Generate the public/private keypair
        if ( (ret_val = crypto_sign_keypair(pk, sk)) != 0) {
            printf("crypto_sign_keypair returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
		/* Renamed "pk" to "public key" */
        fprintBstr(fp_rsp, "public key = ", pk, CRYPTO_PUBLICKEYBYTES);
		/* Renamed "sk" to "secret key" */
        fprintBstr(fp_rsp, "secret key = ", sk, CRYPTO_SECRETKEYBYTES);
        
        if ( (ret_val = crypto_sign(sm, &smlen, m, mlen, sk)) != 0) {
            printf("crypto_sign returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
		/* Renamed "smlen" to "signed message length" */
        fprintf(fp_rsp, "signed message length = %llu\n", smlen);
		/* Renamed "sm" to "signed message" */
        fprintBstr(fp_rsp, "signed message = ", sm, smlen);
        fprintf(fp_rsp, "\n");
        
        if ( (ret_val = crypto_sign_open(m1, &mlen1, sm, smlen, pk)) != 0) {
            printf("crypto_sign_open returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        
        if ( mlen != mlen1 ) {
			/* Renamed 'mlen' to 'message length' */
            printf("crypto_sign_open returned bad 'message length': Got <%llu>, expected <%llu>\n", mlen1, mlen);
            return KAT_CRYPTO_FAILURE;
        }
        
        if ( memcmp(m, m1, mlen) ) {
			/* Renamed 'm' to 'message' */
            printf("crypto_sign_open returned bad 'message' value\n");
            return KAT_CRYPTO_FAILURE;
        }
        
        free(m);
        free(m1);
        free(sm);

    } while ( !done );
    
    fclose(fp_req);
    fclose(fp_rsp);

    return KAT_SUCCESS;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int
FindMarker(FILE *infile, const char *marker)
{
	char	line[MAX_MARKER_LEN];
	int		i, len;
	int curr_line;

	len = (int)strlen(marker);
	if ( len > MAX_MARKER_LEN-1 )
		len = MAX_MARKER_LEN-1;

	for ( i=0; i<len; i++ )
	  {
	    curr_line = fgetc(infile);
	    line[i] = curr_line;
	    if (curr_line == EOF )
	      return 0;
	  }
	line[len] = '\0';

	while ( 1 ) {
		if ( !strncmp(line, marker, len) )
			return 1;

		for ( i=0; i<len-1; i++ )
			line[i] = line[i+1];
		curr_line = fgetc(infile);
		line[len-1] = curr_line;
		if (curr_line == EOF )
		    return 0;
		line[len] = '\0';
	}

	// shouldn't get here
	return 0;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int
ReadHex(FILE *infile, unsigned char *A, int Length, char *str)
{
	int			i, ch, started;
	unsigned char	ich;

	if ( Length == 0 ) {
		A[0] = 0x00;
		return 1;
	}
	memset(A, 0x00, Length);
	started = 0;
	if ( FindMarker(infile, str) )
		while ( (ch = fgetc(infile)) != EOF ) {
			if ( !isxdigit(ch) ) {
				if ( !started ) {
					if ( ch == '\n' )
						break;
					else
						continue;
				}
				else
					break;
			}
			started = 1;
			if ( (ch >= '0') && (ch <= '9') )
				ich = ch - '0';
			else if ( (ch >= 'A') && (ch <= 'F') )
				ich = ch - 'A' + 10;
			else if ( (ch >= 'a') && (ch <= 'f') )
				ich = ch - 'a' + 10;
            else // shouldn't ever get here
                ich = 0;
			
			for ( i=0; i<Length-1; i++ )
				A[i] = (A[i] << 4) | (A[i+1] >> 4);
			A[Length-1] = (A[Length-1] << 4) | ich;
		}
	else
		return 0;

	return 1;
}

void
fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L)
{
	unsigned long long  i;

	fprintf(fp, "%s", S);

	for ( i=0; i<L; i++ )
		fprintf(fp, "%02X", A[i]);

	if ( L == 0 )
		fprintf(fp, "00");

	fprintf(fp, "\n");
}

