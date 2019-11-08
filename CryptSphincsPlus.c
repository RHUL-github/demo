/*
 * MIT License
 *
 * Copyright (c) 2019 Luís Fiolhais, Paulo Martins, Leonel Sousa (INESC-ID)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "Tpm.h"
#include "sphincsplus-params.h"
#include "sphincsplus-sign.h"
#include "fips202.h"
#include "sphincsplus-polyvec.h"
#include "sphincsplus-sign.h"
#include "sphincsplus-packing.h"

BOOL CryptSphincsPlusInit(void) {
    return TRUE;
}

BOOL CryptSphincsPlusStartup(void) {
    return TRUE;
}

typedef struct {
    uint64_t k;
    uint64_t l;
    uint64_t eta;
    uint64_t setabits;
    uint64_t beta;
    uint64_t omega;
    uint64_t polt0_size_packed;
    uint64_t polt1_size_packed;
    uint64_t poleta_size_packed;
    uint64_t polz_size_packed;
    uint64_t crypto_publickeybytes;
    uint64_t crypto_secretkeybytes;
    uint64_t crypto_bytes;
    uint64_t pol_size_packed;
    uint64_t polw1_size_packed;
    uint64_t polveck_size_packed;
    uint64_t polvecl_size_packed;
} SphincsPlusParams;

static SphincsPlusParams generate_sphincsplus_params(BYTE mode) {
    SphincsPlusParams params;

    switch(mode) {
        case TPM_SPHINCS_PLUS_MODE_1:
            params.k = 3;
            params.l = 2;
            params.eta = 7;
            params.setabits = 4;
            params.beta = 375;
            params.omega = 64;
            break;
        case TPM_SPHINCS_PLUS_MODE_2:
            params.k = 4;
            params.l = 3;
            params.eta = 6;
            params.setabits = 4;
            params.beta = 325;
            params.omega = 80;
            break;
        case TPM_SPHINCS_PLUS_MODE_3:
            params.k = 5;
            params.l = 4;
            params.eta = 5;
            params.setabits = 4;
            params.beta = 275;
            params.omega = 96;
            break;
        case TPM_SPHINCS_PLUS_MODE_4:
            params.k = 6;
            params.l = 5;
            params.eta = 3;
            params.setabits = 3;
            params.beta = 175;
            params.omega = 120;
            break;
        default:
            // A call to this function should be protected against invalid
            // sphincsplus modes, i.e.,
            // TPM_SPHINCS_PLUS_MODE_0 <= mode <= TPM_SPHINCS_PLUS_MODE_3
            break;
    }

    params.pol_size_packed     = ((SPHINCS_PLUS_N * SPHINCS_PLUS_QBITS) / 8);
    params.polt1_size_packed   = ((SPHINCS_PLUS_N * (SPHINCS_PLUS_QBITS - SPHINCS_PLUS_D)) / 8);
    params.polt0_size_packed   = ((SPHINCS_PLUS_N * SPHINCS_PLUS_D) / 8);
    params.poleta_size_packed  = ((SPHINCS_PLUS_N * params.setabits) / 8);
    params.polz_size_packed    = ((SPHINCS_PLUS_N * (SPHINCS_PLUS_QBITS - 3)) / 8);
    params.polw1_size_packed   = ((SPHINCS_PLUS_N * 4) / 8);
    params.polveck_size_packed = (params.k * params.pol_size_packed);
    params.polvecl_size_packed = (params.l * params.pol_size_packed);

    params.crypto_publickeybytes = (SPHINCS_PLUS_SEEDBYTES + params.k*params.polt1_size_packed);
    params.crypto_secretkeybytes = (2* SPHINCS_PLUS_SEEDBYTES + (params.l + params.k)*params.poleta_size_packed + SPHINCS_PLUS_CRHBYTES + params.k*params.polt0_size_packed);
    params.crypto_bytes = (params.l * params.polz_size_packed + (params.omega + params.k) + (SPHINCS_PLUS_N/8 + 8));

    return params;
}

LIB_EXPORT TPM_RC
CryptSphincsPlusSign(
	     TPMT_SIGNATURE      *sigOut,
	     OBJECT              *key,           // IN: key to use
	     TPM2B_DIGEST        *hIn            // IN: the digest to sign
	     )
{
    TPM_RC   retVal = TPM_RC_SUCCESS;
    SphincsPlusParams params;
    unsigned long long i;
    unsigned int n;
    unsigned char seedbuf[2*SPHINCS_PLUS_SEEDBYTES + 3*SPHINCS_PLUS_CRHBYTES];
    unsigned char *rho, *key_, *mu, *tr, *rhoprime;
    uint16_t nonce = 0;
    sphincsplus_poly c, chat;
	sphincsplus_polyvecl mat[6], s1, y, yhat, z; // Max K in SphincsPlus
	sphincsplus_polyveck t0, s2, w0, w, w1;
	sphincsplus_polyveck h, ct0, cs2;

    pAssert(sigOut != NULL && key != NULL && hIn != NULL);

    // Set mode used in signature
    sigOut->signature.sphincsplus.mode = key->publicArea.parameters.sphincsplusDetail.mode;

    TEST(sigOut->sigAlg);
    switch(sigOut->sigAlg)
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

    if (sigOut->signature.sphincsplus.mode >= TPM_SPHINCS_PLUS_MODE_1 &&
            sigOut->signature.sphincsplus.mode <= TPM_SPHINCS_PLUS_MODE_4) {
        params = generate_sphincsplus_params(sigOut->signature.sphincsplus.mode);
    } else {
        return TPM_RC_VALUE;
    }

    rho = seedbuf;
    tr = rho + SPHINCS_PLUS_SEEDBYTES;
    key_ = tr + SPHINCS_PLUS_CRHBYTES;
    mu = key_ + SPHINCS_PLUS_SEEDBYTES;
    rhoprime = mu + SPHINCS_PLUS_CRHBYTES;
    sphincsplus_unpack_sk(rho, key_, tr, &s1, &s2, &t0,
            key->sensitive.sensitive.sphincsplus.b.buffer, params.k,
            params.l, params.poleta_size_packed, params.polt0_size_packed,
            params.eta);

    /* Copy tr and message into the sm buffer,
     * backwards since m and sm can be equal in SUPERCOP API */
    for(i = 1; i <= hIn->b.size; ++i)
      sigOut->signature.sphincsplus.sig.t.buffer[params.crypto_bytes + hIn->b.size - i] = hIn->b.buffer[hIn->b.size - i];
    for(i = 0; i < SPHINCS_PLUS_CRHBYTES; ++i)
      sigOut->signature.sphincsplus.sig.t.buffer[params.crypto_bytes - SPHINCS_PLUS_CRHBYTES + i] = tr[i];

    /* Compute CRH(tr, msg) */
    CryptHashBlock(TPM_ALG_SHAKE256,
			SPHINCS_PLUS_CRHBYTES + hIn->b.size, sigOut->signature.sphincsplus.sig.b.buffer + params.crypto_bytes - SPHINCS_PLUS_CRHBYTES,
			SPHINCS_PLUS_CRHBYTES, mu);

    CryptHashBlock(TPM_ALG_SHAKE256,
			SPHINCS_PLUS_SEEDBYTES + SPHINCS_PLUS_CRHBYTES, key_,
			SPHINCS_PLUS_CRHBYTES, rhoprime);

    /* Expand matrix and transform vectors */
	sphincsplus_expand_mat(mat, rho, params.k, params.l);
	sphincsplus_polyvecl_ntt(&s1, params.l);
	sphincsplus_polyveck_ntt(&s2, params.k);
	sphincsplus_polyveck_ntt(&t0, params.k);

    rej:
    if(_plat__IsCanceled()) ERROR_RETURN(TPM_RC_CANCELED);

    /* Sample intermediate vector y */
    for(i = 0; i < params.l; ++i)
		sphincsplus_poly_uniform_gamma1m1(&y.vec[i], rhoprime, nonce++);

    /* Matrix-vector multiplication */
    yhat = y;
    sphincsplus_polyvecl_ntt(&yhat, params.l);
    for(i = 0; i < params.k; ++i) {
      sphincsplus_polyvecl_pointwise_acc_invmontgomery(&w.vec[i], &mat[i], &yhat,
              params.l);
	  sphincsplus_poly_reduce(&w.vec[i]);
	  sphincsplus_poly_invntt_montgomery(&w.vec[i]);
    }

    /* Decompose w and call the random oracle */
    sphincsplus_polyveck_csubq(&w, params.k);
    sphincsplus_polyveck_decompose(&w1, &w0, &w, params.k);
    sphincsplus_challenge(&c, mu, &w1, params.k, params.polw1_size_packed);
    chat = c;
    sphincsplus_poly_ntt(&chat);

    /* Check that subtracting cs2 does not change high bits of w and low bits
    * do not reveal secret information */
    for(i = 0; i < params.k; ++i) {
        sphincsplus_poly_pointwise_invmontgomery(&cs2.vec[i], &chat, &s2.vec[i]);
        sphincsplus_poly_invntt_montgomery(&cs2.vec[i]);
    }
    sphincsplus_polyveck_sub(&w0, &w0, &cs2, params.k);
    sphincsplus_polyveck_freeze(&w0, params.k);
    if(sphincsplus_polyveck_chknorm(&w0, SPHINCS_PLUS_GAMMA2 - params.beta, params.l))
        goto rej;

    /* Compute z, reject if it reveals secret */
    for(i = 0; i < params.l; ++i) {
      sphincsplus_poly_pointwise_invmontgomery(&z.vec[i], &chat, &s1.vec[i]);
      sphincsplus_poly_invntt_montgomery(&z.vec[i]);
    }
    sphincsplus_polyvecl_add(&z, &z, &y, params.l);
    sphincsplus_polyvecl_freeze(&z, params.l);
    if(sphincsplus_polyvecl_chknorm(&z, SPHINCS_PLUS_GAMMA1 - params.beta, params.l))
      goto rej;

    /* Compute hints for w1 */
    for(i = 0; i < params.k; ++i) {
      sphincsplus_poly_pointwise_invmontgomery(&ct0.vec[i], &chat, &t0.vec[i]);
      sphincsplus_poly_invntt_montgomery(&ct0.vec[i]);
    }

    sphincsplus_polyveck_csubq(&ct0, params.k);
    if(sphincsplus_polyveck_chknorm(&ct0, SPHINCS_PLUS_GAMMA2, params.k))
      goto rej;

    sphincsplus_polyveck_add(&w0, &w0, &ct0, params.k);
    sphincsplus_polyveck_csubq(&w0, params.k);
    n = sphincsplus_polyveck_make_hint(&h, &w0, &w1, params.k);
    if(n > params.omega)
      goto rej;

    /* Write signature */
    sphincsplus_pack_sig((unsigned char *)&sigOut->signature.sphincsplus.sig.b.buffer, &z, &h,
            &c, params.k, params.l, params.polz_size_packed, params.omega);

    sigOut->signature.sphincsplus.sig.b.size = hIn->b.size + params.crypto_bytes;
Exit:
    return retVal;
}

LIB_EXPORT TPM_RC
CryptSphincsPlusValidateSignature(
			  TPMT_SIGNATURE  *sig,           // IN: signature
			  OBJECT          *key,           // IN: public sphincsplus key
			  TPM2B_DIGEST    *digest         // IN: The digest being validated
			  )
{
    TPM_RC   retVal = TPM_RC_SUCCESS;
    SphincsPlusParams params;
    unsigned long long i;
    unsigned char rho[SPHINCS_PLUS_SEEDBYTES];
    unsigned char mu[SPHINCS_PLUS_CRHBYTES];
    sphincsplus_poly c, chat, cp;
    sphincsplus_polyvecl mat[6], z; // Max K for sphincsplus
    sphincsplus_polyveck t1, w1, h, tmp1, tmp2;
    TPM2B_SPHINCS_PLUS_MESSAGE message_tmp;

    pAssert(sig != NULL && key != NULL && digest != NULL);

    // Can't verify signatures with a key of different mode
    if (sig->signature.sphincsplus.mode != key->publicArea.parameters.sphincsplusDetail.mode)
        ERROR_RETURN(TPM_RC_SIGNATURE);

    switch(sig->sigAlg) {
	  case ALG_SPHINCS_PLUS_VALUE:
	    break;
	  default:
	    return TPM_RC_SCHEME;
	}

    TEST(sig->sigAlg);
    if (sig->signature.sphincsplus.mode >= TPM_SPHINCS_PLUS_MODE_1 &&
            sig->signature.sphincsplus.mode <= TPM_SPHINCS_PLUS_MODE_4) {
        params = generate_sphincsplus_params(sig->signature.sphincsplus.mode);
    } else {
        return TPM_RC_SUCCESS + 2;
    }

    if(sig->signature.sphincsplus.sig.b.size < params.crypto_bytes)
      goto badsig;

    message_tmp.b.size = sig->signature.sphincsplus.sig.b.size - params.crypto_bytes;

    sphincsplus_unpack_pk(rho, &t1, key->publicArea.unique.sphincsplus.b.buffer, params.k, params.polt1_size_packed);
    if(sphincsplus_unpack_sig(&z, &h, &c, sig->signature.sphincsplus.sig.b.buffer, params.k, params.l, params.polz_size_packed, params.omega)) {
      goto badsig;
    }
    if(sphincsplus_polyvecl_chknorm(&z, SPHINCS_PLUS_GAMMA1 - params.beta, params.l)) {
      goto badsig;
    }

    /* Compute CRH(CRH(rho, t1), msg) using m as "playground" buffer */
    if(sig->signature.sphincsplus.sig.b.buffer != message_tmp.b.buffer)
      for(i = 0; i < message_tmp.b.size; ++i)
        message_tmp.b.buffer[params.crypto_bytes + i] = sig->signature.sphincsplus.sig.b.buffer[params.crypto_bytes + i];

    CryptHashBlock(TPM_ALG_SHAKE256,
            params.crypto_publickeybytes, key->publicArea.unique.sphincsplus.b.buffer,
            SPHINCS_PLUS_CRHBYTES, message_tmp.t.buffer + params.crypto_bytes - SPHINCS_PLUS_CRHBYTES);
    CryptHashBlock(TPM_ALG_SHAKE256,
            SPHINCS_PLUS_CRHBYTES + message_tmp.b.size, message_tmp.b.buffer + params.crypto_bytes - sphincsplus_CRHBYTES,
            SPHINCS_PLUS_CRHBYTES, mu);

    /* Matrix-vector multiplication; compute Az - c2^dt1 */
    sphincsplus_expand_mat(mat, rho, params.k, params.l);
    sphincsplus_polyvecl_ntt(&z, params.l);
    for(i = 0; i < params.k; ++i)
      sphincsplus_polyvecl_pointwise_acc_invmontgomery(&tmp1.vec[i], &mat[i], &z, params.l);

    chat = c;
    sphincsplus_poly_ntt(&chat);
    sphincsplus_polyveck_shiftl(&t1, params.k);
    sphincsplus_polyveck_ntt(&t1, params.k);
    for(i = 0; i < params.k; ++i)
      sphincsplus_poly_pointwise_invmontgomery(&tmp2.vec[i], &chat, &t1.vec[i]);

    sphincsplus_polyveck_sub(&tmp1, &tmp1, &tmp2, params.k);
    sphincsplus_polyveck_reduce(&tmp1, params.k);
    sphincsplus_polyveck_invntt_montgomery(&tmp1, params.k);

    /* Reconstruct w1 */
    sphincsplus_polyveck_csubq(&tmp1, params.k);
    sphincsplus_polyveck_use_hint(&w1, &tmp1, &h, params.k);

    /* Call random oracle and verify challenge */
    sphincsplus_challenge(&cp, mu, &w1, params.k, params.polw1_size_packed);

    for(i = 0; i < SPHINCS_PLUS_N; ++i)
      if(c.coeffs[i] != cp.coeffs[i]) {
        goto badsig;
      }

    /* All good, copy msg, return 0 */
    for(i = 0; i < message_tmp.b.size; ++i)
      message_tmp.b.buffer[i] = sig->signature.sphincsplus.sig.b.buffer[params.crypto_bytes + i];

    if (!MemoryEqual2B(&digest->b, &message_tmp.b)) {
        goto badsig;
    }

Exit:
    return retVal;

    /* Signature verification failed */
    badsig:
    return TPM_RC_SIGNATURE;
}

LIB_EXPORT TPM_RC
CryptSphincsPlusGenerateKey(
            // IN/OUT: The object structure in which the key is created.
		    OBJECT              *spincsplusKey,
            // IN: if not NULL, the deterministic RNG state
		    RAND_STATE          *rand
		    )
{
    TPMT_PUBLIC         *publicArea = &sphincsplusKey->publicArea;
    TPMT_SENSITIVE      *sensitive = &sphincsplusKey->sensitive;
    TPM_RC               retVal = TPM_RC_NO_RESULT;
    unsigned int i;
    unsigned char seedbuf[3*SPHINCS_PLUS_SEEDBYTES];
    unsigned char tr[SPHINCS_PLUS_CRHBYTES];
    const unsigned char *rho, *rhoprime, *key;
    uint16_t nonce = 0;
    sphincsplus_polyvecl mat[6]; // MAX K in SphincsPlus
    sphincsplus_polyvecl s1, s1hat;
    sphincsplus_polyveck s2, t, t1, t0;
    SphincsPlusParams params;

    pAssert(sphincsplusKey != NULL);

    // SphincsPlus is only used for signing
    if (!IS_ATTRIBUTE(publicArea->objectAttributes, TPMA_OBJECT, sign))
        ERROR_RETURN(TPM_RC_NO_RESULT);

    if (publicArea->parameters.sphincsplusDetails.mode >= TPM_SPHINCS_PLUS_MODE_1 &&
            publicArea->parameters.sphincsplusDetails.mode <= TPM_SPHINCS_PLUS_MODE_4) {
        params = generate_sphincsplus_params(publicArea->parameters.sphincsplusDetail.mode);
    } else {
        return TPM_RC_VALUE;
    }

    /* Expand 32 bytes of randomness into rho, rhoprime and key */
    CryptRandomGenerate(3*SPHINCS_PLUS_SEEDBYTES, seedbuf);
    rho = seedbuf;
    rhoprime = seedbuf + SPHINCS_PLUS_SEEDBYTES;
    key = seedbuf + 2*SPHINCS_PLUS_SEEDBYTES;

    /* Expand matrix */
    sphincsplus_expand_mat(mat, rho, params.k, params.l);

    /* Sample short vector s1 and s2 */
    for(i = 0; i < params.l; ++i)
      sphincsplus_poly_uniform_eta(&s1.vec[i], rhoprime, nonce++, params.eta,
              params.setabits);
    for(i = 0; i < params.k; ++i)
      sphincsplus_poly_uniform_eta(&s2.vec[i], rhoprime, nonce++, params.eta,
              params.setabits);

    /* Matrix-vector multiplication */
    s1hat = s1;
    sphincsplus_polyvecl_ntt(&s1hat, params.l);
    for(i = 0; i < params.k; ++i) {
      sphincsplus_polyvecl_pointwise_acc_invmontgomery(&t.vec[i], &mat[i], &s1hat,
              params.l);
      sphincsplus_poly_reduce(&t.vec[i]);
      sphincsplus_poly_invntt_montgomery(&t.vec[i]);
    }

    /* Add error vector s2 */
    sphincsplus_polyveck_add(&t, &t, &s2, params.k);

    /* Extract t1 and write public key */
    sphincsplus_polyveck_freeze(&t, params.k);
    sphincsplus_polyveck_power2round(&t1, &t0, &t, params.k);
    sphincsplus_pack_pk(publicArea->unique.sphincsplus.t.buffer,
            rho, &t1, params.k, params.polt1_size_packed);

    /* Compute CRH(rho, t1) and write secret key */
    CryptHashBlock(TPM_ALG_SHAKE256,
            params.crypto_publickeybytes, publicArea->unique.sphincsplus.t.buffer,
            SPHINCS_PLUS_CRHBYTES, tr);
    sphincsplus_pack_sk(sensitive->sensitive.sphincsplus.t.buffer,
            rho, key, tr, &s1, &s2, &t0,
            params.k, params.l, params.poleta_size_packed,
            params.polt0_size_packed, params.eta);

    publicArea->unique.sphincsplus.t.size = params.crypto_publickeybytes;
    sensitive->sensitive.sphincsplus.t.size = params.crypto_secretkeybytes;

    retVal = TPM_RC_SUCCESS;

 Exit:
    return retVal;
}
