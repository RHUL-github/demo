#ifndef SPHINCS_PLUS_VERIFY_FP_H
#define SPHINCS_PLUS_VERIFY_FP_H

typedef struct {
    BYTE	                        mode;
    TPM2B_SPHINCS_PLUS_PUBLIC_KEY	    public_key;
    TPM2B_SPHINCS_PLUS_SIGNED_MESSAGE	signed_message;
} SPHINCS_PLUS_Verify_In;

#define RC_SPHINCS_PLUS_Verify_mode		    (TPM_RC_P + TPM_RC_1)
#define RC_SPHINCS_PLUS_Verify_public_key	    (TPM_RC_P + TPM_RC_2)
#define RC_SPHINCS_PLUS_Verify_signed_message	(TPM_RC_P + TPM_RC_3)

typedef struct {
    TPM2B_SPHINCS_PLUS_MESSAGE	    message;
} SPHINCS_PLUS_Verify_Out;

TPM_RC
TPM2_SPHINCS_PLUS_Verify(
         SPHINCS_PLUS_Verify_In      *in,            // IN: input parameter list
		 SPHINCS_PLUS_Verify_Out     *out            // OUT: output parameter list
		 );


#endif
