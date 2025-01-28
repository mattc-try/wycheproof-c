#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

// Include the test vectors (make sure these files define ecdsa_p1363_test_cases[] and EcdsaP1363TestCase)
#include "../../parsing/parsed_vectors/tv_EcdsaP1363.h"
#include "../../parsing/parsed_vectors/tv_Ecdsa.h"




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




// Function to convert P1363 signature to DER
static int p1363_sig_to_der(const unsigned char *p1363_sig, size_t p1363_sig_len,
                     unsigned char **der_sig, size_t *der_sig_len, int curve_nid) {
    int ret = 0;
    ECDSA_SIG *ecdsa_sig = NULL;
    BIGNUM *r = NULL;
    BIGNUM *s = NULL;
    const EC_GROUP *group = NULL;

    EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(curve_nid);
    if (!ec_group) {
        fprintf(stderr, "Unsupported curve NID %d\n", curve_nid);
        goto end;
    }
    group = ec_group;

    BIGNUM *order = BN_new();
    if (!order) goto end;

    if (EC_GROUP_get_order(group, order, NULL) != 1) goto end;

    size_t order_size = (size_t)BN_num_bytes(order);

    // Strictly require the signature to be exactly 2 * order_size.
    if (p1363_sig_len != 2 * order_size) {
        // Just fail without printing an error message.
        // The caller will handle "invalid" results accordingly.
        goto end;
    }

    r = BN_bin2bn(p1363_sig, order_size, NULL);
    s = BN_bin2bn(p1363_sig + order_size, order_size, NULL);
    if (!r || !s) goto end;

    ecdsa_sig = ECDSA_SIG_new();
    if (!ecdsa_sig) goto end;

    if (ECDSA_SIG_set0(ecdsa_sig, r, s) != 1) goto end;
    // r and s are now owned by ecdsa_sig
    r = NULL;
    s = NULL;

    {
        int len = i2d_ECDSA_SIG(ecdsa_sig, NULL);
        if (len <= 0) goto end;

        *der_sig = (unsigned char *)OPENSSL_malloc(len);
        if (!*der_sig) goto end;

        unsigned char *p = *der_sig;
        len = i2d_ECDSA_SIG(ecdsa_sig, &p);
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
    ECDSA_SIG_free(ecdsa_sig);
    BN_free(r);
    BN_free(s);
    EC_GROUP_free((EC_GROUP *)group);
    BN_free(order);
    return ret;
}



// Verification for P1363 test vectors
static int verify_ecdsa_p1363_signature(const EcdsaP1363TestCase *test_case) {
    int ret = 0;
    EVP_PKEY *pub_key = NULL;
    EC_KEY *ec_key = NULL;
    BIGNUM *wx = NULL;
    BIGNUM *wy = NULL;
    unsigned char *der_sig = NULL;
    size_t der_sig_len = 0;
    const EVP_MD *md = NULL;
    int expected_valid = (strcmp(test_case->result, "valid") == 0);

    int curve_nid = OBJ_txt2nid(test_case->curve);
    if (curve_nid == NID_undef) {
        fprintf(stderr, "Unsupported curve %s\n", test_case->curve);
        // If we can't handle curve, consider test failed. If it's invalid, maybe pass?
        // Usually inability to handle curve means we can't properly verify.
        if (!expected_valid) {
            // If expected invalid, consider it a pass since we fail to verify.
            return 1;
        }
        return 0;
    }

    ec_key = EC_KEY_new_by_curve_name(curve_nid);
    if (!ec_key) {
        fprintf(stderr, "Failed to create EC_KEY for curve %s\n", test_case->curve);
        if (!expected_valid) return 1; // invalid expected, so this fail = pass
        return 0;
    }

    if (!BN_hex2bn(&wx, test_case->wx) || !BN_hex2bn(&wy, test_case->wy)) {
        fprintf(stderr, "Failed to convert wx or wy to BIGNUM\n");
        if (!expected_valid) { 
            // If expected invalid and keys can't be loaded, it's effectively failing to verify
            // so test passes.
            ret = 1;
        }
        goto end;
    }

    if (EC_KEY_set_public_key_affine_coordinates(ec_key, wx, wy) != 1) {
        fprintf(stderr, "Failed to set public key coordinates\n");
        if (!expected_valid) ret = 1; // invalid expected => pass
        goto end;
    }

    pub_key = EVP_PKEY_new();
    if (!pub_key || EVP_PKEY_assign_EC_KEY(pub_key, ec_key) != 1) {
        fprintf(stderr, "Failed to create EVP_PKEY from EC_KEY\n");
        if (!expected_valid) ret = 1; // invalid expected => pass
        goto end;
    }
    ec_key = NULL; // now owned by pub_key

    md = get_md_by_name(test_case->sha);
    if (!md) {
        fprintf(stderr, "Unsupported hash function %s\n", test_case->sha);
        if (!expected_valid) ret = 1; // invalid expected => pass
        goto end;
    }

    // Convert from P1363 to DER
    if (!p1363_sig_to_der(test_case->sig, test_case->sig_len, &der_sig, &der_sig_len, curve_nid)) {
        // Failed to convert. This should result in a verification failure.
        // If expected invalid, that's good (test passed). If expected valid, test failed.
        if (!expected_valid) {
            // We expected invalid, and we got a failure to parse signature
            // -> verification fails as expected
            ret = 1;
        } else {
            // Expected valid but can't parse the signature
            ret = 0;
        }
        goto end;
    }

    {
        EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) {
            if (!expected_valid) ret = 1; // invalid expected => pass
            goto end;
        }

        if (EVP_DigestVerifyInit(md_ctx, NULL, md, NULL, pub_key) != 1) {
            EVP_MD_CTX_free(md_ctx);
            if (!expected_valid) ret = 1; // invalid expected => pass
            goto end;
        }

        if (EVP_DigestVerifyUpdate(md_ctx, test_case->msg, test_case->msg_len) != 1) {
            EVP_MD_CTX_free(md_ctx);
            if (!expected_valid) ret = 1; // invalid expected => pass
            goto end;
        }

        int verify_result = EVP_DigestVerifyFinal(md_ctx, der_sig, der_sig_len);
        EVP_MD_CTX_free(md_ctx);

        if (verify_result == 1) {
            // Signature is valid
            if (expected_valid) {
                ret = 1; // Test passed as expected
            } else {
                fprintf(stderr, "Test case %d: Expected invalid but signature verified\n", test_case->tc_id);
                ret = 0; // Test failed
            }
        } else if (verify_result == 0) {
            // Signature is invalid
            if (!expected_valid) {
                ret = 1; // Test passed as expected
            } else {
                fprintf(stderr, "Test case %d: Expected valid but signature did not verify\n", test_case->tc_id);
                ret = 0; // Test failed
            }
        } else {
            // Error occurred
            unsigned long err = ERR_get_error();
            if (!expected_valid) {
                // If expected invalid, consider this as invalid => pass
                
                ret = 1;
            } else {
                // If expected valid, it's a fail
                fprintf(stderr, "EVP_DigestVerifyFinal error: %s\n", ERR_error_string(err, NULL));
                ret = 0;
            }
        }
    }

end:
    EVP_PKEY_free(pub_key);
    EC_KEY_free(ec_key);
    BN_free(wx);
    BN_free(wy);
    OPENSSL_free(der_sig);
    return ret;
}



// Verification for standard ECDSA DER-encoded test vectors
static int verify_ecdsa_signature(const EcdsaTestCase *test_case) {
    int ret = 0;
    EVP_PKEY *pub_key = NULL;
    EC_KEY *ec_key = NULL;
    BIGNUM *wx = NULL;
    BIGNUM *wy = NULL;
    const EVP_MD *md = NULL;
    int expected_valid = (strcmp(test_case->result, "valid") == 0);

    int curve_nid = OBJ_txt2nid(test_case->curve);
    if (curve_nid == NID_undef) {
        fprintf(stderr, "Unsupported curve %s\n", test_case->curve);
        if (!expected_valid) return 1;
        return 0;
    }

    ec_key = EC_KEY_new_by_curve_name(curve_nid);
    if (!ec_key) {
        fprintf(stderr, "Failed to create EC_KEY for curve %s\n", test_case->curve);
        if (!expected_valid) ret = 1;
        goto end;
    }

    if (!BN_hex2bn(&wx, test_case->wx) || !BN_hex2bn(&wy, test_case->wy)) {
        fprintf(stderr, "Failed to convert wx or wy to BIGNUM\n");
        if (!expected_valid) ret = 1;
        goto end;
    }

    if (EC_KEY_set_public_key_affine_coordinates(ec_key, wx, wy) != 1) {
        fprintf(stderr, "Failed to set public key coordinates\n");
        if (!expected_valid) ret = 1;
        goto end;
    }

    pub_key = EVP_PKEY_new();
    if (!pub_key || EVP_PKEY_assign_EC_KEY(pub_key, ec_key) != 1) {
        fprintf(stderr, "Failed to create EVP_PKEY from EC_KEY\n");
        if (!expected_valid) ret = 1;
        goto end;
    }
    ec_key = NULL; // now owned by pub_key

    md = get_md_by_name(test_case->sha);
    if (!md) {
        fprintf(stderr, "Unsupported hash function %s\n", test_case->sha);
        if (!expected_valid) ret = 1;
        goto end;
    }

    {
        EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) {
            if (!expected_valid) ret = 1;
            goto end;
        }

        if (EVP_DigestVerifyInit(md_ctx, NULL, md, NULL, pub_key) != 1) {
            EVP_MD_CTX_free(md_ctx);
            if (!expected_valid) ret = 1;
            goto end;
        }

        if (EVP_DigestVerifyUpdate(md_ctx, test_case->msg, test_case->msg_len) != 1) {
            EVP_MD_CTX_free(md_ctx);
            if (!expected_valid) ret = 1;
            goto end;
        }

        int verify_result = EVP_DigestVerifyFinal(md_ctx, test_case->sig, test_case->sig_len);
        EVP_MD_CTX_free(md_ctx);

        if (verify_result == 1) {
            if (expected_valid) {
                ret = 1;
            } else {
                fprintf(stderr, "Test case %d: Expected invalid but signature verified\n", test_case->tc_id);
                ret = 0;
            }
        } else if (verify_result == 0) {
            if (!expected_valid) {
                ret = 1;
            } else {
                fprintf(stderr, "Test case %d: Expected valid but signature did not verify\n", test_case->tc_id);
                ret = 0;
            }
        } else {
            unsigned long err = ERR_get_error();
            fprintf(stderr, "EVP_DigestVerifyFinal error: %s\n", ERR_error_string(err, NULL));
            ret = expected_valid ? 0 : 1;
        }
    }

end:
    EVP_PKEY_free(pub_key);
    EC_KEY_free(ec_key);
    BN_free(wx);
    BN_free(wy);
    return ret;
}

int main() {
    size_t passed = 0;
    size_t failed = 0;

    // Test DER-encoded ECDSA vectors
    size_t total_ecdsa = sizeof(ecdsa_test_cases) / sizeof(ecdsa_test_cases[0]);
    for (size_t i = 0; i < total_ecdsa; i++) {
        if (ecdsa_test_cases[i].tc_id == 0) {
            total_ecdsa = i;
            break;
        }
    }

    for (size_t i = 0; i < total_ecdsa; i++) {
        const EcdsaTestCase *test_case = &ecdsa_test_cases[i];
        if (verify_ecdsa_signature(test_case)) {
            passed++;
        } else {
            printf("ECDSA Test case %d failed\n", test_case->tc_id);
            failed++;
        }
    }

    // Test P1363-encoded ECDSA vectors
    size_t total_p1363 = sizeof(ecdsa_p1363_test_cases) / sizeof(ecdsa_p1363_test_cases[0]);
    for (size_t i = 0; i < total_p1363; i++) {
        if (ecdsa_p1363_test_cases[i].tc_id == 0) {
            total_p1363 = i;
            break;
        }
    }

    for (size_t i = 0; i < total_p1363; i++) {
        const EcdsaP1363TestCase *test_case = &ecdsa_p1363_test_cases[i];
        if (verify_ecdsa_p1363_signature(test_case)) {
            passed++;
        } else {
            printf("ECDSA P1363 Test case %d failed\n", test_case->tc_id);
            failed++;
        }
    }

    printf("Total tests: %zu, Passed: %zu, Failed: %zu\n", total_ecdsa + total_p1363, passed, failed);
    return failed == 0 ? 0 : 1;
}
