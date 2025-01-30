#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>


// Include the test vectors (these should define dsa_test_cases[] and dsa_p1363_test_cases[])
#include "../../parsing/parsed_vectors/tv_DsaTest.h"
#include "../../parsing/parsed_vectors/tv_DsaP1363Test.h"


// Helper function to map hash names to EVP_MD
static const EVP_MD *get_md_by_name(const char *md_name) {
    if (strcasecmp(md_name, "SHA-1") == 0) {
        return EVP_sha1();
    } else if (strcasecmp(md_name, "SHA-224") == 0) {
        return EVP_sha224();
    } else if (strcasecmp(md_name, "SHA-256") == 0) {
        return EVP_sha256();
    } else if (strcasecmp(md_name, "SHA-384") == 0) {
        return EVP_sha384();
    } else if (strcasecmp(md_name, "SHA-512") == 0) {
        return EVP_sha512();
    } else if (strcasecmp(md_name, "SHA3-256") == 0) {
        return EVP_sha3_256();
    } else if (strcasecmp(md_name, "SHA3-384") == 0) {
        return EVP_sha3_384();
    } else if (strcasecmp(md_name, "SHA3-512") == 0) {
        return EVP_sha3_512();
    } else if (strcasecmp(md_name, "SHAKE128") == 0) {
        return EVP_shake128();
    } else if (strcasecmp(md_name, "SHAKE256") == 0) {
        return EVP_shake256();
    } else {
        fprintf(stderr, "Unsupported hash function %s\n", md_name);
        return NULL;
    }
}

// Convert a P1363 signature (r||s) into DER format for DSA
// P1363 for DSA: signature is just r||s, each of length equal to the size of q in bytes
static int p1363_sig_to_der(const unsigned char *p1363_sig, size_t p1363_sig_len,
                            unsigned char **der_sig, size_t *der_sig_len,
                            const BIGNUM *q) {
    int ret = 0;
    DSA_SIG *dsa_sig = NULL;
    BIGNUM *r = NULL;
    BIGNUM *s = NULL;

    if (!q) return 0;

    size_t q_size = (size_t)BN_num_bytes(q);

    // P1363 requires r and s each be exactly q_size bytes
    if (p1363_sig_len != 2 * q_size) {
        return 0;
    }

    r = BN_bin2bn(p1363_sig, q_size, NULL);
    s = BN_bin2bn(p1363_sig + q_size, q_size, NULL);
    if (!r || !s) goto end;

    dsa_sig = DSA_SIG_new();
    if (!dsa_sig) goto end;

    if (DSA_SIG_set0(dsa_sig, r, s) != 1) goto end;
    // r and s now owned by dsa_sig
    r = NULL;
    s = NULL;

    {
        int len = i2d_DSA_SIG(dsa_sig, NULL);
        if (len <= 0) goto end;

        *der_sig = (unsigned char *)OPENSSL_malloc(len);
        if (!*der_sig) goto end;

        unsigned char *p = *der_sig;
        len = i2d_DSA_SIG(dsa_sig, &p);
        if (len <= 0) {
            OPENSSL_free(*der_sig);
            *der_sig = NULL;
            goto end;
        }

        *der_sig_len = len;
        ret = 1;
    }

end:
    if (!ret) {
        OPENSSL_free(*der_sig);
        *der_sig = NULL;
        *der_sig_len = 0;
    }
    DSA_SIG_free(dsa_sig);
    BN_free(r);
    BN_free(s);
    return ret;
}


static int verify_dsa_signature(const DsaTestCase *test_case) {
    int ret = 0;
    EVP_PKEY *pub_key = NULL;
    const EVP_MD *md = NULL;
    int expected_valid = (strcmp(test_case->result, "valid") == 0);

    // Load public key from PEM
    BIO *bio = BIO_new_mem_buf(test_case->public_key_pem, -1);
    if (!bio) {
        fprintf(stderr, "Failed to create BIO for public key\n");
        return expected_valid ? 0 : 1;
    }

    pub_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pub_key) {
        fprintf(stderr, "Failed to read public key from PEM\n");
        return expected_valid ? 0 : 1;
    }

    md = get_md_by_name(test_case->sha);
    if (!md) {
        EVP_PKEY_free(pub_key);
        return expected_valid ? 0 : 1;
    }

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pub_key);
        return expected_valid ? 0 : 1;
    }

    if (EVP_DigestVerifyInit(md_ctx, NULL, md, NULL, pub_key) != 1) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pub_key);
        return expected_valid ? 0 : 1;
    }

    if (EVP_DigestVerifyUpdate(md_ctx, test_case->msg, test_case->msg_len) != 1) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pub_key);
        return expected_valid ? 0 : 1;
    }

    int verify_result = EVP_DigestVerifyFinal(md_ctx, test_case->sig, test_case->sig_len);
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pub_key);

    if (verify_result == 1) {
        return expected_valid ? 1 : 0;
    } else {
        return expected_valid ? 0 : 1;
    }
}



static int verify_dsa_p1363_signature(const DsaP1363TestCase *test_case) {
    int ret = 0;
    EVP_PKEY *pub_key = NULL;
    const EVP_MD *md = NULL;
    int expected_valid = (strcmp(test_case->result, "valid") == 0);

    // Load public key from PEM
    BIO *bio = BIO_new_mem_buf(test_case->public_key_pem, -1);
    if (!bio) {
        fprintf(stderr, "Failed to create BIO for public key\n");
        return expected_valid ? 0 : 1;
    }

    pub_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pub_key) {
        fprintf(stderr, "Failed to read public key from PEM\n");
        return expected_valid ? 0 : 1;
    }

    md = get_md_by_name(test_case->sha);
    if (!md) {
        EVP_PKEY_free(pub_key);
        return expected_valid ? 0 : 1;
    }

    // Convert P1363 signature to DER
    unsigned char *der_sig = NULL;
    size_t der_sig_len = 0;
    if (!p1363_sig_to_der(test_case->sig, test_case->sig_len, &der_sig, &der_sig_len, NULL)) {
        EVP_PKEY_free(pub_key);
        return expected_valid ? 0 : 1;
    }

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pub_key);
        OPENSSL_free(der_sig);
        return expected_valid ? 0 : 1;
    }

    if (EVP_DigestVerifyInit(md_ctx, NULL, md, NULL, pub_key) != 1) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pub_key);
        OPENSSL_free(der_sig);
        return expected_valid ? 0 : 1;
    }

    if (EVP_DigestVerifyUpdate(md_ctx, test_case->msg, test_case->msg_len) != 1) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pub_key);
        OPENSSL_free(der_sig);
        return expected_valid ? 0 : 1;
    }

    int verify_result = EVP_DigestVerifyFinal(md_ctx, der_sig, der_sig_len);
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pub_key);
    OPENSSL_free(der_sig);

    if (verify_result == 1) {
        return expected_valid ? 1 : 0;
    } else {
        return expected_valid ? 0 : 1;
    }
}


int main() {
    size_t passed = 0;
    size_t failed = 0;

    // Count actual number of DER-encoded test cases
    size_t total_dsa = 0;
    for (size_t i = 0; ; i++) {
        if (dsa_test_cases[i].tc_id == 0) {
            total_dsa = i;
            break;
        }
    }

    // Run DER-encoded DSA tests
    for (size_t i = 0; i < total_dsa; i++) {
        const DsaTestCase *test_case = &dsa_test_cases[i];
        if (verify_dsa_signature(test_case)) {
            passed++;
        } else {
            printf("DSA Test case %d failed\n", test_case->tc_id);
            failed++;
        }
    }

    // Count actual number of P1363-encoded test cases
    size_t total_p1363 = 0;
    for (size_t i = 0; ; i++) {
        if (dsa_p1363_test_cases[i].tc_id == 0) {
            total_p1363 = i;
            break;
        }
    }

    // Run P1363-encoded DSA tests
    for (size_t i = 0; i < total_p1363; i++) {
        const DsaP1363TestCase *test_case = &dsa_p1363_test_cases[i];
        if (verify_dsa_p1363_signature(test_case)) {
            passed++;
        } else {
            printf("DSA P1363 Test case %d failed\n", test_case->tc_id);
            failed++;
        }
    }

    printf("Total tests: %zu, Passed: %zu, Failed: %zu\n", total_dsa + total_p1363, passed, failed);
    return failed == 0 ? 0 : 1;
}
