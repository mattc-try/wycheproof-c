#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "../../parsing/parsed_vectors/tv_RsaesOaepDecrypt.h"
#include "../../parsing/parsed_vectors/tv_RsaPkcs1Decrypt.h"

/**
 * @brief Handles OpenSSL errors by printing them and aborting the program.
 */
static void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}


/**
 * @brief Decodes a hex string into a byte array.
 *
 * @param hex The hex string (e.g., "54657374" for "Test").
 * @param out_len Output: the length of the decoded data in bytes.
 * @return A newly allocated buffer containing the decoded bytes, or NULL on failure.
 *         Caller must free the returned buffer.
 */
static unsigned char* hex_decode(const char *hex, size_t *out_len) {
    if (hex == NULL || strlen(hex) == 0) {
        *out_len = 0;
        return NULL;
    }
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) {
        fprintf(stderr, "Invalid hex string length: %zu\n", hex_len);
        return NULL;
    }
    size_t bytes_len = hex_len / 2;
    unsigned char *out = malloc(bytes_len);
    if (!out) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
    for (size_t i = 0; i < bytes_len; i++) {
        unsigned int val;
        if (sscanf(&hex[i*2], "%2x", &val) != 1) {
            fprintf(stderr, "Invalid hex string format\n");
            free(out);
            return NULL;
        }
        out[i] = (unsigned char)val;
    }
    *out_len = bytes_len;
    return out;
}

/**
 * @brief Loads an RSA private key from a PKCS#8 PEM string.
 *
 * @param key_data The PEM-encoded private key data in PKCS#8 format.
 * @return RSA* Pointer to the loaded RSA key, or NULL on failure.
 */
static RSA *load_private_key_from_pem(const char *key_pem) {
    BIO *bio = BIO_new_mem_buf((void *)key_pem, -1); // -1 to let OpenSSL determine the length
    if (!bio) {
        fprintf(stderr, "Failed to create BIO for private key.\n");
        return NULL;
    }

    // Read the private key into an EVP_PKEY structure
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!pkey) {
        fprintf(stderr, "PEM_read_bio_PrivateKey failed. Ensure the key is in PKCS#8 format.\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Extract the RSA key from EVP_PKEY
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    EVP_PKEY_free(pkey);

    if (!rsa) {
        fprintf(stderr, "EVP_PKEY_get1_RSA failed. The key may not be an RSA key.\n");
        ERR_print_errors_fp(stderr);
    }

    return rsa; // rsa is NULL if not an RSA key
}

/**
 * @brief Records outcomes for invalid tests to check indistinguishability.
 *
 * @param outcome The outcome code (1 or 2).
 * @param outcomes_array Pointer to the outcomes array.
 * @param count Pointer to the current count of outcomes.
 * @param capacity Pointer to the current capacity of the outcomes array.
 */
static void record_invalid_outcome(int outcome, int **outcomes_array, int *count, int *capacity) {
    if (*count >= *capacity) {
        *capacity = (*capacity == 0) ? 16 : (*capacity * 2);
        *outcomes_array = realloc(*outcomes_array, (*capacity) * sizeof(int));
        if (!*outcomes_array) {
            fprintf(stderr, "Out of memory while recording invalid outcome.\n");
            exit(1);
        }
    }
    (*outcomes_array)[(*count)++] = outcome;
}



/**
 * @brief Checks the indistinguishability of invalid test outcomes.
 *
 * @param schema_name Name of the schema (e.g., "InvalidPkcs1Padding").
 * @param invalid_outcomes Array of invalid outcomes.
 * @param invalid_count Number of invalid outcomes recorded.
 * @param tests_failed Pointer to the count of failed tests.
 */
static void check_indistinguishability(const char *schema_name,
                                       int *invalid_outcomes, int invalid_count,
                                       int *tests_failed) {
    if (invalid_count == 0) {
        // No invalid tests to check
        return;
    }
    int first = invalid_outcomes[0];
    for (int i = 1; i < invalid_count; i++) {
        if (invalid_outcomes[i] != first) {
            fprintf(stderr, "Schema %s: Invalid ciphertext results are not indistinguishable.\n", schema_name);
            (*tests_failed)++;
            return;
        }
    }
}

/**
 * @brief Executes a single RSA decryption test and compares results.
 *
 * @param test_id Identifier for the test case.
 * @param ciphertext The ciphertext to decrypt.
 * @param ct_len Length of the ciphertext.
 * @param expected_msg The expected plaintext message.
 * @param msg_len Length of the expected message.
 * @param private_key_pem The PEM-encoded private key.
 * @param result_str Expected result ("valid" or other).
 * @param sha Hash algorithm for OAEP (e.g., "SHA-256").
 * @param mgf_sha MGF hash algorithm for OAEP (e.g., "SHA-256").
 * @param label Optional label for OAEP.
 * @param label_len Length of the label.
 * @param tests_passed Pointer to the count of passed tests.
 * @param tests_failed Pointer to the count of failed tests.
 * @param invalid_outcomes_array Pointer to the array of invalid outcomes.
 * @param invalid_count Pointer to the current count of invalid outcomes.
 * @param invalid_cap Pointer to the current capacity of the invalid outcomes array.
 */
static void test_rsa_decryption(int test_id,
                                const unsigned char *ciphertext, size_t ct_len,
                                const unsigned char *expected_msg, size_t msg_len,
                                const char *private_key_pem,
                                const char *result_str,
                                const char *sha, const char *mgf_sha,
                                const unsigned char *label, size_t label_len,
                                int *tests_passed, int *tests_failed,
                                int **invalid_outcomes_array, int *invalid_count, int *invalid_cap) {
    // Load the private key
    RSA *rsa = load_private_key_from_pem(private_key_pem);
    if (!rsa) {
        fprintf(stderr, "Test case %d: Failed to load private key.\n", test_id);
        (*tests_failed)++;
        return;
    }

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        fprintf(stderr, "Test case %d: Failed to create EVP_PKEY structure.\n", test_id);
        RSA_free(rsa);
        (*tests_failed)++;
        return;
    }

    if (EVP_PKEY_assign_RSA(pkey, rsa) <= 0) {
        fprintf(stderr, "Test case %d: Failed to assign RSA key to EVP_PKEY.\n", test_id);
        EVP_PKEY_free(pkey);
        RSA_free(rsa); // In case of failure, free rsa
        (*tests_failed)++;
        return;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        fprintf(stderr, "Test case %d: Failed to create EVP_PKEY_CTX.\n", test_id);
        EVP_PKEY_free(pkey);
        (*tests_failed)++;
        return;
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        fprintf(stderr, "Test case %d: EVP_PKEY_decrypt_init failed.\n", test_id);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        (*tests_failed)++;
        return;
    }

    const EVP_MD *md = NULL;
    const EVP_MD *mgf_md_obj = NULL;

    if (sha && mgf_sha) {
        // OAEP parameters
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            fprintf(stderr, "Test case %d: Failed to set OAEP padding.\n", test_id);
            goto decrypt_fail;
        }
        md = EVP_get_digestbyname(sha);
        mgf_md_obj = EVP_get_digestbyname(mgf_sha);
        if (!md || !mgf_md_obj) {
            fprintf(stderr, "Test case %d: Unsupported digest algorithms (%s, %s).\n", test_id, sha, mgf_sha);
            goto decrypt_fail;
        }
        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0) {
            fprintf(stderr, "Test case %d: Failed to set OAEP MD.\n", test_id);
            goto decrypt_fail;
        }
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, mgf_md_obj) <= 0) {
            fprintf(stderr, "Test case %d: Failed to set MGF1 MD.\n", test_id);
            goto decrypt_fail;
        }
        if (label && label_len > 0) {
            unsigned char *oaep_label = OPENSSL_malloc(label_len);
            if (!oaep_label) {
                fprintf(stderr, "Test case %d: Failed to allocate memory for OAEP label.\n", test_id);
                goto decrypt_fail;
            }
            memcpy(oaep_label, label, label_len);
            if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, oaep_label, label_len) <= 0) {
                fprintf(stderr, "Test case %d: Failed to set OAEP label.\n", test_id);
                OPENSSL_free(oaep_label);
                goto decrypt_fail;
            }
            // EVP_PKEY_CTX_set0_rsa_oaep_label takes ownership of oaep_label on success
        }
    } else {
        // PKCS#1 v1.5 padding
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
            fprintf(stderr, "Test case %d: Failed to set PKCS#1 padding.\n", test_id);
            goto decrypt_fail;
        }
    }

    unsigned char decrypted[4096];
    size_t decrypted_len = sizeof(decrypted);

    int ret = EVP_PKEY_decrypt(ctx, decrypted, &decrypted_len, ciphertext, ct_len);
    if (ret <= 0) {
        // Decryption failed
        if (strcmp(result_str, "valid") == 0) {
            fprintf(stderr, "Test case %d: Expected valid, but decryption failed.\n", test_id);
            (*tests_failed)++;
        } else {
            // Invalid test: failure is acceptable
            record_invalid_outcome(1, invalid_outcomes_array, invalid_count, invalid_cap);
            (*tests_passed)++;
        }
    } else {
        // Decryption succeeded
        int matches = (decrypted_len == msg_len && memcmp(decrypted, expected_msg, msg_len) == 0);
        if (strcmp(result_str, "valid") == 0) {
            if (matches) {
                (*tests_passed)++;
            } else {
                fprintf(stderr, "Test case %d: Expected valid, but decrypted plaintext does not match.\n", test_id);
                (*tests_failed)++;
            }
        } else {
            // Invalid test
            if (matches) {
                fprintf(stderr, "Test case %d: Invalid ciphertext produced correct plaintext!\n", test_id);
                (*tests_failed)++;
            } else {
                // Produced incorrect plaintext, which is acceptable for invalid tests
                record_invalid_outcome(2, invalid_outcomes_array, invalid_count, invalid_cap);
                (*tests_passed)++;
            }
        }
    }

    // Clean up
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return;

decrypt_fail:
    fprintf(stderr, "Test case %d: Failed to initialize decryption parameters.\n", test_id);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    (*tests_failed)++;
}



/**
 * @brief Test all PKCS#1 test vectors and check indistinguishability.
 *
 * @param tests_passed Pointer to the count of passed tests.
 * @param tests_failed Pointer to the count of failed tests.
 */
static void test_pkcs1_vectors(int *tests_passed, int *tests_failed) {
    int *invalid_outcomes = NULL;
    int invalid_count = 0;
    int invalid_cap = 0;

    printf("Testing RSA PKCS1 decryption test cases...\n");
    for (int i = 0; i < (int)(sizeof(rsa_pkcs1_decrypt_test_cases)/sizeof(rsa_pkcs1_decrypt_test_cases[0])); i++) {
        const RsaPkcs1DecryptTestCase *vec = &rsa_pkcs1_decrypt_test_cases[i];

        // Decode hex strings
        size_t msg_dec_len = 0;
        unsigned char *msg_dec = NULL;
        if (vec->msg_len > 0 && vec->msg_hex && strlen(vec->msg_hex) > 0) {
            msg_dec = hex_decode(vec->msg_hex, &msg_dec_len);
            if (!msg_dec) {
                fprintf(stderr, "Test case %d: Failed to decode msg_hex.\n", vec->tc_id);
                (*tests_failed)++;
                continue;
            }
        }

        size_t ct_dec_len = 0;
        unsigned char *ct_dec = NULL;
        if (vec->ct_len > 0 && vec->ct_hex && strlen(vec->ct_hex) > 0) {
            ct_dec = hex_decode(vec->ct_hex, &ct_dec_len);
            if (!ct_dec) {
                fprintf(stderr, "Test case %d: Failed to decode ct_hex.\n", vec->tc_id);
                free(msg_dec);
                (*tests_failed)++;
                continue;
            }
        }

        // Check length matches
        if ((vec->msg_len > 0 && msg_dec_len != vec->msg_len) ||
            (vec->ct_len > 0 && ct_dec_len != vec->ct_len)) {
            fprintf(stderr, "Test case %d: Length mismatch after hex decode.\n", vec->tc_id);
            free(msg_dec);
            free(ct_dec);
            (*tests_failed)++;
            continue;
        }

        test_rsa_decryption(
            vec->tc_id,
            ct_dec, vec->ct_len,
            msg_dec, vec->msg_len,
            vec->private_key_pem,
            vec->result,
            NULL, NULL, // No OAEP parameters for PKCS#1
            NULL, 0,
            tests_passed, tests_failed,
            &invalid_outcomes, &invalid_count, &invalid_cap
        );

        free(msg_dec);
        free(ct_dec);
    }

    // Check indistinguishability for PKCS#1 invalid ciphertexts
    check_indistinguishability("InvalidPkcs1Padding", invalid_outcomes, invalid_count, tests_failed);
    free(invalid_outcomes);
}

/**
 * @brief Test all OAEP test vectors and check indistinguishability.
 *
 * @param tests_passed Pointer to the count of passed tests.
 * @param tests_failed Pointer to the count of failed tests.
 */
static void test_oaep_vectors(int *tests_passed, int *tests_failed) {
    int *invalid_outcomes = NULL;
    int invalid_count = 0;
    int invalid_cap = 0;

    printf("Testing RSA OAEP decryption test cases...\n");
    for (int i = 0; i < (int)(sizeof(rsa_oaep_decrypt_test_cases)/sizeof(rsa_oaep_decrypt_test_cases[0])); i++) {
        const RsaOaepDecryptTestCase *vec = &rsa_oaep_decrypt_test_cases[i];

        // Decode hex strings
        size_t msg_dec_len = 0;
        unsigned char *msg_dec = NULL;
        if (vec->msg_len > 0 && vec->msg_hex && strlen(vec->msg_hex) > 0) {
            msg_dec = hex_decode(vec->msg_hex, &msg_dec_len);
            if (!msg_dec) {
                fprintf(stderr, "Test case %d: Failed to decode msg_hex.\n", vec->tc_id);
                (*tests_failed)++;
                continue;
            }
        }

        size_t ct_dec_len = 0;
        unsigned char *ct_dec = NULL;
        if (vec->ct_len > 0 && vec->ct_hex && strlen(vec->ct_hex) > 0) {
            ct_dec = hex_decode(vec->ct_hex, &ct_dec_len);
            if (!ct_dec) {
                fprintf(stderr, "Test case %d: Failed to decode ct_hex.\n", vec->tc_id);
                free(msg_dec);
                (*tests_failed)++;
                continue;
            }
        }

        size_t label_dec_len = 0;
        unsigned char *label_dec = NULL;
        if (vec->label_len > 0 && vec->label_hex && strlen(vec->label_hex) > 0) {
            label_dec = hex_decode(vec->label_hex, &label_dec_len);
            if (!label_dec) {
                fprintf(stderr, "Test case %d: Failed to decode label_hex.\n", vec->tc_id);
                free(msg_dec);
                free(ct_dec);
                (*tests_failed)++;
                continue;
            }
        }

        // Check length matches
        if ((vec->msg_len > 0 && msg_dec_len != vec->msg_len) ||
            (vec->ct_len > 0 && ct_dec_len != vec->ct_len) ||
            (vec->label_len > 0 && label_dec_len != vec->label_len)) {
            fprintf(stderr, "Test case %d: Length mismatch after hex decode.\n", vec->tc_id);
            free(msg_dec);
            free(ct_dec);
            free(label_dec);
            (*tests_failed)++;
            continue;
        }

        test_rsa_decryption(
            vec->tc_id,
            ct_dec, vec->ct_len,
            msg_dec, vec->msg_len,
            vec->private_key_pem,
            vec->result,
            vec->sha, vec->mgf_sha,
            label_dec, vec->label_len,
            tests_passed, tests_failed,
            &invalid_outcomes, &invalid_count, &invalid_cap
        );

        free(msg_dec);
        free(ct_dec);
        free(label_dec);
    }

    // Check indistinguishability for OAEP invalid ciphertexts
    check_indistinguishability("InvalidOaepPadding", invalid_outcomes, invalid_count, tests_failed);
    free(invalid_outcomes);
}



/**
 * @brief Main test runner.
 *
 * @return int Exit status code.
 */
int main() {
    int tests_passed = 0;
    int tests_failed = 0;

    // Initialize OpenSSL error strings
    ERR_load_crypto_strings();

    printf("Testing RSA decryption with test vectors...\n\n");

    // Run PKCS#1 tests
    test_pkcs1_vectors(&tests_passed, &tests_failed);

    // Run OAEP tests
    test_oaep_vectors(&tests_passed, &tests_failed);

    // Summary
    printf("\n--- Test Summary ---\n");
    printf("Total tests passed: %d\n", tests_passed);
    printf("Total tests failed: %d\n", tests_failed);

    // Clean up OpenSSL error strings
    ERR_free_strings();

    return (tests_failed == 0) ? 0 : 1;
}