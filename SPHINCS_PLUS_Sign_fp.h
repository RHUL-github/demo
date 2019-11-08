#ifndef SPHINCS_PLUS_SIGN_FP_H
#define SPHINCS_PLUS_SIGN_FP_H

typedef struct {
    BYTE	                    mode;
    TPM2B_SPHINCS_PLUS_MESSAGE	    message;
    TPM2B_SPHINCS_PLUS_SECRET_KEY	secret_key;
} SPHINCS_PLUS_Sign_In;

#define RC_SPHINCS_PLUS_Sign_mode		    (TPM_RC_P + TPM_RC_1)
#define RC_SPHINCS_PLUS_Sign_message		(TPM_RC_P + TPM_RC_2)
#define RC_SPHINCS_PLUS_Sign_secret_key	(TPM_RC_P + TPM_RC_3)

typedef struct {
    TPM2B_SPHINCS_PLUS_SIGNED_MESSAGE	signed_message;
} SPHINCS_PLUS_Sign_Out;

TPM_RC
TPM2_SPHINCS_PLUS_Sign(
         SPHINCS_PLUS_Sign_In      *in,            // IN: input parameter list
		 SPHINCS_PLUS_Sign_Out     *out            // OUT: output parameter list
		 );


#endif
