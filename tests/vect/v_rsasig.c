#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/rsa.h>

// Include your test vectors
#include "../../parsing/parsed_vectors/tv_RsassaPkcs1Verify.h"  // rsassa_pkcs1_verify_test_cases[]
#include "../../parsing/parsed_vectors/tv_RsassaPssVerify.h"    // rsassa_pss_verify_test_cases[]

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

// A function to decode a hex string into a binary buffer
static unsigned char *hex_to_bin(const char *hex, size_t hex_len, size_t *out_len) {
    // If hex_len is the length of the hex string, the output length in bytes is hex_len/2
    if (hex_len % 2 != 0) {
        fprintf(stderr, "Hex string length must be even\n");
        return NULL;
    }

    size_t bin_len = hex_len / 2;
    unsigned char *bin = malloc(bin_len);
    if (!bin) return NULL;

    for (size_t i = 0; i < bin_len; i++) {
        unsigned char c1 = hex[i*2];
        unsigned char c2 = hex[i*2+1];
        unsigned char v1 = 0, v2 = 0;

        if (c1 >= '0' && c1 <= '9') v1 = c1 - '0';
        else if (c1 >= 'a' && c1 <= 'f') v1 = c1 - 'a' + 10;
        else if (c1 >= 'A' && c1 <= 'F') v1 = c1 - 'A' + 10;
        else {
            fprintf(stderr, "Invalid hex char: %c\n", c1);
            free(bin);
            return NULL;
        }

        if (c2 >= '0' && c2 <= '9') v2 = c2 - '0';
        else if (c2 >= 'a' && c2 <= 'f') v2 = c2 - 'a' + 10;
        else if (c2 >= 'A' && c2 <= 'F') v2 = c2 - 'A' + 10;
        else {
            fprintf(stderr, "Invalid hex char: %c\n", c2);
            free(bin);
            return NULL;
        }

        bin[i] = (unsigned char)((v1 << 4) | v2);
    }

    if (out_len) *out_len = bin_len;
    return bin;
}

// Parse a PEM public key into EVP_PKEY
static EVP_PKEY *load_public_key_from_pem(const char *pem_str) {
    EVP_PKEY *pkey = NULL;
    BIO *bio = BIO_new_mem_buf(pem_str, -1);
    if (!bio) return NULL;

    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return pkey;
}

// Choose a default hash algorithm if none is specified
static const EVP_MD *choose_default_md(const char *flags[], size_t flags_len) {
    // For demonstration: if "WeakHash" is present, use SHA-1; else use SHA-256
    // Adjust this logic based on your test vector conventions
    for (size_t i = 0; i < flags_len; i++) {
        if (strcasecmp(flags[i], "WeakHash") == 0) {
            return EVP_sha1();
        }
    }
    return EVP_sha256();
}

static int verify_rsa_pkcs1_signature(const RsassaPkcs1VerifyTestCase *test_case) {
    int ret = 0;
    EVP_PKEY *pub_key = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    size_t msg_bin_len = 0, sig_bin_len = 0;
    unsigned char *msg_bin = NULL, *sig_bin = NULL;

    int expected_valid = (strcmp(test_case->result, "valid") == 0);

    // Decode msg and sig from hex
    msg_bin = hex_to_bin(test_case->msg_hex, test_case->msg_len*2, &msg_bin_len);
    sig_bin = hex_to_bin(test_case->sig_hex, test_case->sig_len*2, &sig_bin_len);
    if (!msg_bin || !sig_bin) {
        free(msg_bin);
        free(sig_bin);
        return expected_valid ? 0 : 1;
    }

    pub_key = load_public_key_from_pem(test_case->public_key_pem);
    if (!pub_key) {
        fprintf(stderr, "Failed to load public key PEM for test case %d\n", test_case->tc_id);
        free(msg_bin);
        free(sig_bin);
        return expected_valid ? 0 : 1;
    }

    // Choose a default hash from flags
    const EVP_MD *md = choose_default_md(NULL, 0); // If no flags in pkcs1 test, adjust as needed.

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pub_key);
        free(msg_bin);
        free(sig_bin);
        return expected_valid ? 0 : 1;
    }

    if (EVP_DigestVerifyInit(md_ctx, NULL, md, NULL, pub_key) != 1) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pub_key);
        free(msg_bin);
        free(sig_bin);
        return expected_valid ? 0 : 1;
    }

    if (EVP_DigestVerifyUpdate(md_ctx, msg_bin, msg_bin_len) != 1) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pub_key);
        free(msg_bin);
        free(sig_bin);
        return expected_valid ? 0 : 1;
    }

    int verify_result = EVP_DigestVerifyFinal(md_ctx, sig_bin, sig_bin_len);
    if (verify_result == 1) {
        // Valid signature
        ret = expected_valid ? 1 : 0;
        if (!expected_valid) {
            fprintf(stderr, "Test case %d: Expected invalid but signature verified\n", test_case->tc_id);
        }
    } else if (verify_result == 0) {
        // Invalid signature
        ret = !expected_valid ? 1 : 0;
        if (expected_valid) {
            fprintf(stderr, "Test case %d: Expected valid but signature did not verify\n", test_case->tc_id);
        }
    } else {
        // Error occurred
        unsigned long err = ERR_get_error();
        fprintf(stderr, "EVP_DigestVerifyFinal error: %s\n", ERR_error_string(err, NULL));
        ret = expected_valid ? 0 : 1;
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pub_key);
    free(msg_bin);
    free(sig_bin);
    return ret;
}

// For RSASSA-PSS, set PSS parameters if needed
static int set_pss_parameters(EVP_MD_CTX *md_ctx, EVP_PKEY *pub_key,
                              const EVP_MD *md, const char *flags[], size_t flags_len) {
    // Deduce mgf1_md and saltlen from flags, if any
    const EVP_MD *mgf1_md = md;
    int saltlen = 32; // default
    for (size_t i = 0; i < flags_len; i++) {
        if (strncasecmp(flags[i], "Mgf1Sha1", 8) == 0) {
            mgf1_md = EVP_sha1();
        } else if (strncasecmp(flags[i], "Mgf1Sha256", 10) == 0) {
            mgf1_md = EVP_sha256();
        } else if (strncasecmp(flags[i], "SaltLen=", 8) == 0) {
            saltlen = atoi(flags[i] + 8);
        }
    }

    EVP_PKEY_CTX *pctx = NULL;
    if (EVP_DigestVerifyInit(md_ctx, &pctx, md, NULL, pub_key) != 1) {
        return 0;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0) {
        return 0;
    }

    if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, mgf1_md) <= 0) {
        return 0;
    }

    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, saltlen) <= 0) {
        return 0;
    }

    return 1;
}

static int verify_rsa_pss_signature(const RsassaPssVerifyTestCase *test_case) {
    int ret = 0;
    EVP_PKEY *pub_key = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    int expected_valid = (strcmp(test_case->result, "valid") == 0);

    size_t msg_bin_len = 0, sig_bin_len = 0;
    unsigned char *msg_bin = NULL, *sig_bin = NULL;

    // Decode hex to binary
    msg_bin = hex_to_bin(test_case->msg_hex, test_case->msg_len*2, &msg_bin_len);
    sig_bin = hex_to_bin(test_case->sig_hex, test_case->sig_len*2, &sig_bin_len);
    if (!msg_bin || !sig_bin) {
        free(msg_bin);
        free(sig_bin);
        return expected_valid ? 0 : 1;
    }

    pub_key = load_public_key_from_pem(test_case->public_key_pem);
    if (!pub_key) {
        fprintf(stderr, "Failed to load public key PEM for test case %d\n", test_case->tc_id);
        free(msg_bin);
        free(sig_bin);
        return expected_valid ? 0 : 1;
    }

    // Choose default md from flags
    const EVP_MD *md = choose_default_md(test_case->flags, test_case->flags_len);

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pub_key);
        free(msg_bin);
        free(sig_bin);
        return expected_valid ? 0 : 1;
    }

    // Set PSS parameters
    if (!set_pss_parameters(md_ctx, pub_key, md, (const char **)test_case->flags, test_case->flags_len)) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pub_key);
        free(msg_bin);
        free(sig_bin);
        return expected_valid ? 0 : 1;
    }

    if (EVP_DigestVerifyUpdate(md_ctx, msg_bin, msg_bin_len) != 1) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pub_key);
        free(msg_bin);
        free(sig_bin);
        return expected_valid ? 0 : 1;
    }

    int verify_result = EVP_DigestVerifyFinal(md_ctx, sig_bin, sig_bin_len);
    if (verify_result == 1) {
        ret = expected_valid ? 1 : 0;
        if (!expected_valid) {
            fprintf(stderr, "Test case %d: Expected invalid but signature verified\n", test_case->tc_id);
        }
    } else if (verify_result == 0) {
        ret = !expected_valid ? 1 : 0;
        if (expected_valid) {
            fprintf(stderr, "Test case %d: Expected valid but signature did not verify\n", test_case->tc_id);
        }
    } else {
        unsigned long err = ERR_get_error();
        fprintf(stderr, "EVP_DigestVerifyFinal error: %s\n", ERR_error_string(err, NULL));
        ret = expected_valid ? 0 : 1;
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pub_key);
    free(msg_bin);
    free(sig_bin);
    return ret;
}

int main() {
    size_t passed = 0;
    size_t failed = 0;

    // Test RSASSA-PKCS1
    size_t total_pkcs1 = sizeof(rsassa_pkcs1_verify_test_cases)/sizeof(rsassa_pkcs1_verify_test_cases[0]);
    for (size_t i = 0; i < total_pkcs1; i++) {
        if (rsassa_pkcs1_verify_test_cases[i].tc_id == 0) {
            total_pkcs1 = i;
            break;
        }
    }

    for (size_t i = 0; i < total_pkcs1; i++) {
        const RsassaPkcs1VerifyTestCase *test_case = &rsassa_pkcs1_verify_test_cases[i];
        if (verify_rsa_pkcs1_signature(test_case)) {
            passed++;
        } else {
            printf("RSASSA-PKCS1 Test case %d failed\n", test_case->tc_id);
            failed++;
        }
    }

    // Test RSASSA-PSS
    size_t total_pss = sizeof(rsassa_pss_verify_test_cases)/sizeof(rsassa_pss_verify_test_cases[0]);
    for (size_t i = 0; i < total_pss; i++) {
        if (rsassa_pss_verify_test_cases[i].tc_id == 0) {
            total_pss = i;
            break;
        }
    }

    for (size_t i = 0; i < total_pss; i++) {
        const RsassaPssVerifyTestCase *test_case = &rsassa_pss_verify_test_cases[i];
        if (verify_rsa_pss_signature(test_case)) {
            passed++;
        } else {
            printf("RSASSA-PSS Test case %d failed\n", test_case->tc_id);
            failed++;
        }
    }

    printf("Total tests: %zu, Passed: %zu, Failed: %zu\n", total_pkcs1 + total_pss, passed, failed);
    return failed == 0 ? 0 : 1;
}
