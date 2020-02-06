/ *
* MIT License
*
* Copyright(c) 2019 Christine Wright (Royal Holloway, University of London)
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this softwareand associated documentation files(the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and /or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions :
*
*The above copyright noticeand this permission notice shall be included in all
* copies or substantial portions of the Software.
*
*THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
* /
#include <string.h>
#include <stdint.h>

#include "Tpm.h"
#include "sphincsplus-api.h"
#include "sphincsplus-params.h"
#include "sphincsplus-wots.h"
#include "sphincsplus-fors.h"
#include "sphincsplus-hash.h"
#include "sphincsplus-hash_address.h"
#include "sphincsplus-rng.h"
#include "sphincsplus-utils.h"


BOOL CryptSphincsPlusInit(void) {
	return TRUE;
}

BOOL CryptSphincsPlusStartup(void) {
	return TRUE;
}

/**
 * Computes the leaf at a given address. First generates the WOTS key pair,
 * then computes leaf by hashing horizontally.
 */
static void wots_gen_leaf(unsigned char *leaf, const unsigned char *sk_seed,
                          const unsigned char *pub_seed,
                          uint32_t addr_idx, const uint32_t tree_addr[8])
{
    unsigned char pk[SPX_WOTS_BYTES];
    uint32_t wots_addr[8] = {0};
    uint32_t wots_pk_addr[8] = {0};

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    copy_subtree_addr(wots_addr, tree_addr);
    set_keypair_addr(wots_addr, addr_idx);
    wots_gen_pk(pk, sk_seed, pub_seed, wots_addr);

    copy_keypair_addr(wots_pk_addr, wots_addr);
    thash(leaf, pk, SPX_WOTS_LEN, pub_seed, wots_pk_addr);
}
/* FUTURETPM MODS FOR KEY GENERATION - START */
/*
 * Generates an SPX key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
/* int crypto_sign_keypair(unsigned char *pk, unsigned char *sk) */
/* pk is publicArea->unique.sphincsplus.t.buffer */
/* sk is sensitive->sensitive.sphincsplus.t.buffer */
LIB_EXPORT TPM_RC
CryptSphincsPlusGenerateKey(
		// IN/OUT: The object structure in which the key is created.
		OBJECT* sphincsplusKey,
		// IN: if not NULL, the deterministic RNG state
		RAND_STATE* rand
	)
{
    /* We do not need the auth path in key generation, but it simplifies the
       code to have just one treehash routine that computes both root and path
       in one function. */
	TPMT_PUBLIC		*publicArea = &sphincsplusKey->publicArea;
	TPMT_SENSITIVE	*sensitive = &sphincsplusKey->sensitive;
	TPM_RC			retVal = TPM_RC_NO_RESULT;
	unsigned char auth_path[SPX_TREE_HEIGHT * SPX_N];
    uint32_t top_tree_addr[8] = {0};

    set_layer_addr(top_tree_addr, SPX_D - 1);
    set_type(top_tree_addr, SPX_ADDR_TYPE_HASHTREE);

    /* Initialize SK_SEED, SK_PRF and PUB_SEED. */
	/* randombytes(sk, 3 * SPX_N); */
	randombytes(sensitive->sensitive.sphincsplus.t.buffer, 3 * SPX_N);

	/* memcpy(pk, sk + 2*SPX_N, SPX_N); */
	memcpy(publicArea->unique.sphincsplus.t.buffer, sensitive->sensitive.sphincsplus.t.buffer + 2 * SPX_N, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
	/* initialize_hash_function(pk, sk); */
	initialize_hash_function(publicArea->unique.sphincsplus.t.buffer, sensitive->sensitive.sphincsplus.t.buffer);

    /* Compute root node of the top-most subtree. */
	/* treehash(sk + 3*SPX_N, auth_path, sk, sk + 2*SPX_N, 0, 0, SPX_TREE_HEIGHT,
             wots_gen_leaf, top_tree_addr); */
	treehash(sensitive->sensitive.sphincsplus.t.buffer + 3*SPX_N, auth_path, sensitive->sensitive.sphincsplus.t.buffer, sensitive->sensitive.sphincsplus.t.buffer + 2*SPX_N, 0, 0, SPX_TREE_HEIGHT,
		wots_gen_leaf, top_tree_addr);

	/* memcpy(pk + SPX_N, sk + 3*SPX_N, SPX_N); */
	memcpy(publicArea->unique.sphincsplus.t.buffer + SPX_N, sensitive->sensitive.sphincsplus.t.buffer + 3*SPX_N, SPX_N);

/*    return 0; */
/* Write public key size */
	publicArea->unique.sphincsplus.t.size = CRYPTO_PUBLICKEYBYTES;
/* Write secret key size */
	sensitive->sensitive.sphincsplus.t.size = CRYPTO_SECRETKEYBYTES;

	retVal = TPM_RC_SUCCESS;

Exit:
	return retVal;
}
/* FUTURETPM MODS FOR KEY GENERATION - END */

/* FUTURETPM MODS FOR SIGNATURE GENERATION - START */
/**
 * Returns an array containing the signature followed by the message.
 */
/* int crypto_sign(unsigned char* sm, unsigned long long* smlen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* sk) */
/* pk is key->publicArea.unique.sphincsplus.t.buffer */
/* sk is key->sensitive.sensitive.sphincsplus.t.buffer */
/* sm is sigOut->signature.sphincsplus.sig.t.buffer */
/* smlen is sigOut->signature.sphincsplus.sig.b.size */
/* m is hIn->b.buffer */
/* mlen is hIn->b.size */
LIB_EXPORT TPM_RC
CryptSphincsPlusSign(
	     TPMT_SIGNATURE      *sigOut,
	     OBJECT              *key,           // IN: key to use
	     TPM2B_DIGEST        *hIn            // IN: the digest to sign
	     ) */
{
	TPM_RC   retVal = TPM_RC_SUCCESS;
	/* const unsigned char *sk_seed = sk; */
	const unsigned char *sk_seed = key->sensitive.sensitive.sphincsplus.t.buffer;
    /* const unsigned char *sk_prf = sk + SPX_N; */
	const unsigned char *sk_prf = key->sensitive.sensitive.sphincsplus.t.buffer + SPX_N;
    /* const unsigned char *pk = sk + 2*SPX_N; */
	const unsigned char *key->publicArea.unique.sphincsplus.t.buffer = key->sensitive.sensitive.sphincsplus.t.buffer + 2*SPX_N;
    /* const unsigned char *pub_seed = pk; */
	const unsigned char *pub_seed = key->publicArea.unique.sphincsplus.t.buffer;

    unsigned char optrand[SPX_N];
    unsigned char mhash[SPX_FORS_MSG_BYTES];
    unsigned char root[SPX_N];
    unsigned long long i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};

	pAssert(sigOut != NULL && key != NULL && hIn != NULL);

	TEST(sigOut->sigAlg);
	switch (sigOut->sigAlg)
	{
	case ALG_NULL_VALUE:
		sigOut->signature.sphincsplus.sig.t.size = 0;
		return TPM_RC_SUCCESS;
	case ALG_SPHINCS_PLUS_VALUE:
		break;
	default:
		retVal = TPM_RC_SCHEME;
		return retVal;
	}

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(pub_seed, sk_seed);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    /* Already put the message in the right place, to make it easier to prepend
     * things when computing the hash over the message. */
    /* We need to do this from back to front, so that it works when sm = m */
    /* for (i = mlen; i > 0; i--) { */
	for (i = hIn->b.size; i > 0; i--) {
        /* sm[SPX_BYTES + i - 1] = m[i - 1]; */
		sigOut->signature.sphincsplus.sig.t.buffer[SPX_BYTES + i - 1] = hIn->b.buffer[i - 1];
    }
	/* *smlen = SPX_BYTES + mlen; */
    *sigOut->signature.sphincsplus.sig.b.size = SPX_BYTES + hIn->b.size;

    /* Optionally, signing can be made non-deterministic using optrand.
       This can help counter side-channel attacks that would benefit from
       getting a large number of traces when the signer uses the same nodes. */
    randombytes(optrand, SPX_N);
    /* Compute the digest randomization value. */
    /* gen_message_random(sm, sk_prf, optrand, sm + SPX_BYTES, mlen); */
	gen_message_random(sigOut->signature.sphincsplus.sig.t.buffer, sk_prf, optrand, sigOut->signature.sphincsplus.sig.t.buffer + SPX_BYTES, hIn->b.size);

    /* Derive the message digest and leaf index from R, PK and M. */
    /* hash_message(mhash, &tree, &idx_leaf, sm, pk, sm + SPX_BYTES, mlen); */
	hash_message(mhash, &tree, &idx_leaf, sigOut->signature.sphincsplus.sig.t.buffer, key->publicArea.unique.sphincsplus.t.buffer, sigOut->signature.sphincsplus.sig.t.buffer + SPX_BYTES, hIn->b.size);
    /* sm += SPX_N; */
	sigOut->signature.sphincsplus.sig.t.buffer += SPX_N;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    /* Sign the message hash using FORS. */
    /* fors_sign(sm, root, mhash, sk_seed, pub_seed, wots_addr); */
	fors_sign(sigOut->signature.sphincsplus.sig.t.buffer, root, mhash, sk_seed, pub_seed, wots_addr);
    /* sm += SPX_FORS_BYTES; */
	sigOut->signature.sphincsplus.sig.t.buffer += SPX_FORS_BYTES;

    for (i = 0; i < SPX_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        /* Compute a WOTS signature. */
        /* wots_sign(sm, root, sk_seed, pub_seed, wots_addr); */
		wots_sign(sigOut->signature.sphincsplus.sig.t.buffer, root, sk_seed, pub_seed, wots_addr);
        /* sm += SPX_WOTS_BYTES; */
		sigOut->signature.sphincsplus.sig.t.buffer += SPX_WOTS_BYTES;

        /* Compute the authentication path for the used WOTS leaf. */
        /* treehash(root, sm, sk_seed, pub_seed, idx_leaf, 0,
                 SPX_TREE_HEIGHT, wots_gen_leaf, tree_addr); */
		treehash(root, sigOut->signature.sphincsplus.sig.t.buffer, sk_seed, pub_seed, idx_leaf, 0,
			SPX_TREE_HEIGHT, wots_gen_leaf, tree_addr);
        /* sm += SPX_TREE_HEIGHT * SPX_N; */
		sigOut->signature.sphincsplus.sig.t.buffer += SPX_TREE_HEIGHT * SPX_N;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    /* return 0; */
	return retVal;
}
/* FUTURETPM MODS FOR SIGNATURE GENERATION - END */

/* FUTURETPM MODS FOR SIGNATURE VERIFICATION - START */
/**
 * Verifies a given signature-message pair under a given public key.
 */
/* int crypto_sign_open(unsigned char* m, unsigned long long* mlen,
	const unsigned char* sm, unsigned long long smlen,
	const unsigned char* pk) */
/* pk is key->publicArea.unique.sphincsplus.b.buffer */
/* sm is sig->signature.sphincsplus.sig.b.buffer */
/* smlen is sig->signature.sphincsplus.sig.b.size */
/* m is message_tmp.t.buffer */
/* mlen is message_tmp.b.size */
LIB_EXPORT TPM_RC
CryptSphincsPlusValidateSignature(
	TPMT_SIGNATURE* sig,           // IN: signature
	OBJECT* key,           // IN: public sphincsplus key
	TPM2B_DIGEST* digest         // IN: The digest being validated
	)
{
	TPM_RC   retVal = TPM_RC_SUCCESS;
	/* const unsigned char *pub_seed = pk; */
	const unsigned char* pub_seed = key->publicArea.unique.sphincsplus.b.buffer;
    /* const unsigned char *pub_root = pk + SPX_N; */
	const unsigned char* pub_root = key->publicArea.unique.sphincsplus.b.buffer + SPX_N;
    unsigned char mhash[SPX_FORS_MSG_BYTES];
    unsigned char wots_pk[SPX_WOTS_BYTES];
    unsigned char root[SPX_N];
    unsigned char leaf[SPX_N];
    unsigned char sig[SPX_BYTES];
    unsigned char *sigptr = sig;
    unsigned int i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    uint32_t wots_pk_addr[8] = {0};
	TPM2B_SPHINCS_PLUS_MESSAGE message_tmp;

	pAssert(sig != NULL && key != NULL && digest != NULL);

	switch (sig->sigAlg) {
	case ALG_SPHINCS_PLUS_VALUE:
		break;
	default:
		return TPM_RC_SCHEME;
	}

	TEST(sig->sigAlg);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(pub_seed, NULL);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    /* *mlen = smlen - SPX_BYTES; */
	message_tmp.b.size = sig->signature.sphincsplus.sig.b.size - SPX_BYTES;

    /* Put the message all the way at the end of the m buffer, so that we can
     * prepend the required other inputs for the hash function. */
    /* memcpy(m + SPX_BYTES, sm + SPX_BYTES, *mlen); */
	memcpy(message_tmp.t.buffer + SPX_BYTES, sig->signature.sphincsplus.sig.b.buffer + SPX_BYTES, message_tmp.b.size);

    /* Create a copy of the signature so that m = sm is not an issue */
    /* memcpy(sig, sm, SPX_BYTES); */
	memcpy(sig, sig->signature.sphincsplus.sig.b.buffer, SPX_BYTES);

    /* Derive the message digest and leaf index from R || PK || M. */
    /* The additional SPX_N is a result of the hash domain separator. */
    /* hash_message(mhash, &tree, &idx_leaf, sigptr, pk, m + SPX_BYTES, *mlen); */
	hash_message(mhash, &tree, &idx_leaf, sigptr, key->publicArea.unique.sphincsplus.b.buffer, message_tmp.t.buffer + SPX_BYTES, message_tmp.b.size);
    sigptr += SPX_N;

    /* Layer correctly defaults to 0, so no need to set_layer_addr */
    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    fors_pk_from_sig(root, sigptr, mhash, pub_seed, wots_addr);
    sigptr += SPX_FORS_BYTES;

    /* For each subtree.. */
    for (i = 0; i < SPX_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        copy_keypair_addr(wots_pk_addr, wots_addr);

        /* The WOTS public key is only correct if the signature was correct. */
        /* Initially, root is the FORS pk, but on subsequent iterations it is
           the root of the subtree below the currently processed subtree. */
        wots_pk_from_sig(wots_pk, sigptr, root, pub_seed, wots_addr);
        sigptr += SPX_WOTS_BYTES;

        /* Compute the leaf node using the WOTS public key. */
        thash(leaf, wots_pk, SPX_WOTS_LEN, pub_seed, wots_pk_addr);

        /* Compute the root node of this subtree. */
        compute_root(root, leaf, idx_leaf, 0, sigptr, SPX_TREE_HEIGHT,
                     pub_seed, tree_addr);
        sigptr += SPX_TREE_HEIGHT * SPX_N;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    /* Check if the root node equals the root node in the public key. */
    if (memcmp(root, pub_root, SPX_N)) {
        /* If not, zero the message */
        /* memset(m, 0, *mlen); */
		memset(message_tmp.t.buffer, 0, message_tmp.b.size);
        /* *mlen = 0; */
		message_tmp.b.size = 0;
        /* return -1; */
		return TPM_RC_SIGNATURE;
    }

    /* If verification was successful, move the message to the right place. */
    /* memmove(m, m + SPX_BYTES, *mlen); */
	memmove(message_tmp.t.buffer, message_tmp.t.buffer + SPX_BYTES, message_tmp.b.size);

    /* return 0; */
	return retVal;
}
/* FUTURETPM MODS FOR SIGNATURE VERIFICATION - END */
