#ifndef SPHINCS_PLUS_KEYGEN_FP_H
#define SPHINCS_PLUS_KEYGEN_FP_H

typedef struct {
    BYTE	mode;
} SPHINCS_PLUS_KeyGen_In;

#define RC_SPHINCS_PLUS_KeyGen_mode		(TPM_RC_P + TPM_RC_1)

typedef struct {
    TPM2B_SPHINCS_PLUS_PUBLIC_KEY	public_key;
    TPM2B_SPHINCS_PLUS_SECRET_KEY	secret_key;
} SPHINCS_PLUS_KeyGen_Out;

TPM_RC
TPM2_SPHINCS_PLUS_KeyGen(
         SPHINCS_PLUS_KeyGen_In      *in,            // IN: input parameter list
		 SPHINCS_PLUS_KeyGen_Out     *out            // OUT: output parameter list
		 );


#endif
