#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>

// Include all generated header files containing test vectors
#include "../../parsing/parsed_vectors/tv_XdhComp.h"
#include "../../parsing/parsed_vectors/tv_XdhAsnComp.h"
#include "../../parsing/parsed_vectors/tv_XdhJwkComp.h"
#include "../../parsing/parsed_vectors/tv_XdhPemComp.h"

// Define maximum shared secret length (for X448)
#define MAX_SHARED_SECRET_LEN 56

/**
 * @enum ExpectedResult
 * @brief Enumeration for expected test results.
 */
typedef enum {
    RESULT_VALID,       /**< The test case is expected to be valid. */
    RESULT_INVALID,     /**< The test case is expected to be invalid. */
    RESULT_ACCEPTABLE   /**< The test case has acceptable variations. */
} ExpectedResult;

/**
 * @brief Parses the expected result string from test vectors.
 *
 * @param result_str The result string from the test vector ("valid", "invalid", "acceptable").
 * @return The corresponding ExpectedResult enum value.
 */
ExpectedResult parse_expected_result(const char *result_str) {
    if (strcmp(result_str, "valid") == 0) {
        return RESULT_VALID;
    } else if (strcmp(result_str, "invalid") == 0) {
        return RESULT_INVALID;
    } else if (strcmp(result_str, "acceptable") == 0) {
        return RESULT_ACCEPTABLE;
    } else {
        return RESULT_INVALID; // Default to invalid for unrecognized strings
    }
}

/**
 * @brief Decodes a base64url-encoded string.
 *
 * This function converts base64url encoding to standard base64, adds necessary padding,
 * and decodes the string into binary data.
 *
 * @param input The base64url-encoded input string.
 * @param output_len Pointer to a size_t variable where the output length will be stored.
 * @return Pointer to the decoded binary data, or NULL on failure.
 *         The caller is responsible for freeing the returned buffer.
 */
unsigned char *base64url_decode(const char *input, size_t *output_len) {
    size_t input_len = strlen(input);
    // Calculate padding required for base64
    size_t padding = (4 - (input_len % 4)) % 4;
    char *b64_input = malloc(input_len + padding + 1);
    if (b64_input == NULL) {
        return NULL;
    }
    strcpy(b64_input, input);
    // Replace URL-specific characters
    for (size_t i = 0; i < input_len; i++) {
        if (b64_input[i] == '-') {
            b64_input[i] = '+';
        } else if (b64_input[i] == '_') {
            b64_input[i] = '/';
        }
    }
    // Add padding
    for (size_t i = 0; i < padding; i++) {
        b64_input[input_len + i] = '=';
    }
    b64_input[input_len + padding] = '\0';

    BIO *bio, *b64;
    size_t max_decoded_len = ((input_len + padding) * 3) / 4;
    unsigned char *buffer = malloc(max_decoded_len);
    if (buffer == NULL) {
        free(b64_input);
        return NULL;
    }

    // Initialize BIO for base64 decoding
    bio = BIO_new_mem_buf(b64_input, -1);
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // Disable newlines
    bio = BIO_push(b64, bio);

    // Perform decoding
    *output_len = BIO_read(bio, buffer, max_decoded_len);

    // Clean up
    BIO_free_all(bio);
    free(b64_input);

    return buffer;
}

/**
 * @brief Executes XDH key agreement tests based on provided test vectors.
 *
 * This function iterates through each test case, performs key agreement using OpenSSL,
 * and verifies the derived shared secret against expected values.
 *
 * @param tests_passed Pointer to an integer tracking the number of passed tests.
 * @param tests_failed Pointer to an integer tracking the number of failed tests.
 */
void test_xdh_comp_cases(int *tests_passed, int *tests_failed) {
    size_t NUM_TEST_CASES = sizeof(xdh_test_cases) / sizeof(xdh_test_cases[0]);

    for (size_t i = 0; i < NUM_TEST_CASES; i++) {
        const XdhTestCase *test = &xdh_test_cases[i];
        ExpectedResult expected = parse_expected_result(test->result);

        // Determine the curve type based on the test case
        int curve_nid = 0;
        if (strcmp(test->curve, "curve25519") == 0) {
            curve_nid = EVP_PKEY_X25519;
        } else if (strcmp(test->curve, "curve448") == 0) {
            curve_nid = EVP_PKEY_X448;
        } else {
            printf("Test case %d: Unsupported curve %s\n", test->tc_id, test->curve);
            (*tests_failed)++;
            continue;
        }

        // Load the private key from raw bytes
        EVP_PKEY *privkey = EVP_PKEY_new_raw_private_key(
            curve_nid, NULL, test->private_key, test->private_key_len);
        if (privkey == NULL) {
            if (expected == RESULT_INVALID) {
                // printf("Test case %d: Expected invalid (private key load failed)\n", test->tc_id);
                (*tests_passed)++;
            } else {
                printf("Test case %d: Failed to load private key\n", test->tc_id);
                (*tests_failed)++;
            }
            continue;
        }

        // Load the peer's public key from raw bytes
        EVP_PKEY *pubkey = EVP_PKEY_new_raw_public_key(
            curve_nid, NULL, test->public_key, test->public_key_len);
        if (pubkey == NULL) {
            if (expected == RESULT_INVALID) {
                // printf("Test case %d: Expected invalid (public key load failed)\n", test->tc_id);
                (*tests_passed)++;
            } else {
                printf("Test case %d: Failed to load public key\n", test->tc_id);
                (*tests_failed)++;
            }
            EVP_PKEY_free(privkey);
            continue;
        }

        // Initialize key agreement context
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
        if (ctx == NULL || EVP_PKEY_derive_init(ctx) <= 0) {
            printf("Test case %d: Derive init failed\n", test->tc_id);
            (*tests_failed)++;
            EVP_PKEY_free(privkey);
            EVP_PKEY_free(pubkey);
            continue;
        }

        // Set the peer public key
        if (EVP_PKEY_derive_set_peer(ctx, pubkey) <= 0) {
            if (expected == RESULT_INVALID || expected == RESULT_ACCEPTABLE) {
                // printf("Test case %d: Expected invalid (derive set peer failed)\n", test->tc_id);
                (*tests_passed)++;
            } else {
                printf("Test case %d: Derive set peer failed\n", test->tc_id);
                (*tests_failed)++;
            }
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(privkey);
            EVP_PKEY_free(pubkey);
            continue;
        }

        // Derive the shared secret
        unsigned char shared_secret[MAX_SHARED_SECRET_LEN];
        size_t shared_secret_len = sizeof(shared_secret);
        int derive_result = EVP_PKEY_derive(ctx, shared_secret, &shared_secret_len);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privkey);
        EVP_PKEY_free(pubkey);

        if (derive_result <= 0) {
            if (expected == RESULT_INVALID || expected == RESULT_ACCEPTABLE) {
                // printf("Test case %d: Expected invalid (derive failed)\n", test->tc_id);
                (*tests_passed)++;
            } else {
                printf("Test case %d: Derive failed\n", test->tc_id);
                (*tests_failed)++;
            }
            continue;
        }

        // Compare the derived shared secret with the expected value
        if (shared_secret_len != test->shared_len ||
            memcmp(shared_secret, test->shared, shared_secret_len) != 0) {
            if (expected == RESULT_INVALID || expected == RESULT_ACCEPTABLE) {
                printf("Test case %d: Expected invalid but derived value\n", test->tc_id);
                (*tests_failed)++;
            } else {
                printf("Test case %d: Shared secret mismatch\n", test->tc_id);
                (*tests_failed)++;
            }
        } else {
            if (expected == RESULT_INVALID) {
                printf("Test case %d: Expected invalid but test passed\n", test->tc_id);
                (*tests_failed)++;
            } else {
                (*tests_passed)++;
            }
        }
    }
}

/**
 * @brief Executes XDH key agreement tests using ASN.1 encoded keys.
 *
 * This function processes test cases where keys are encoded using ASN.1 DER format.
 *
 * @param tests_passed Pointer to an integer tracking the number of passed tests.
 * @param tests_failed Pointer to an integer tracking the number of failed tests.
 */
void test_xdh_asn_cases(int *tests_passed, int *tests_failed) {
    size_t NUM_TEST_CASES = sizeof(xdh_asn_test_cases) / sizeof(xdh_asn_test_cases[0]);

    for (size_t i = 0; i < NUM_TEST_CASES; i++) {
        const XdhAsnTestCase *test = &xdh_asn_test_cases[i];
        ExpectedResult expected = parse_expected_result(test->result);

        // Determine the curve type based on the test case
        int curve_nid = 0;
        if (strcmp(test->curve, "curve25519") == 0) {
            curve_nid = EVP_PKEY_X25519;
        } else if (strcmp(test->curve, "curve448") == 0) {
            curve_nid = EVP_PKEY_X448;
        } else {
            printf("Test case %d: Unsupported curve %s\n", test->tc_id, test->curve);
            (*tests_failed)++;
            continue;
        }

        // Load the private key from ASN.1 DER encoding
        const unsigned char *p = test->private_key_asn;
        EVP_PKEY *privkey = d2i_PrivateKey(curve_nid, NULL, &p, test->private_key_asn_len);
        if (privkey == NULL) {
            if (expected == RESULT_INVALID || expected == RESULT_ACCEPTABLE) {
                // printf("Test case %d: Expected invalid (private key load failed)\n", test->tc_id);
                (*tests_passed)++;
            } else {
                printf("Test case %d: Failed to load private key\n", test->tc_id);
                (*tests_failed)++;
            }
            continue;
        }

        // Load the public key from ASN.1 DER encoding
        p = test->public_key_asn;
        EVP_PKEY *pubkey = d2i_PUBKEY(NULL, &p, test->public_key_asn_len);
        if (pubkey == NULL) {
            if (expected == RESULT_INVALID || expected == RESULT_ACCEPTABLE) {
                // printf("Test case %d: Expected invalid (public key load failed)\n", test->tc_id);
                (*tests_passed)++;
            } else {
                printf("Test case %d: Failed to load public key\n", test->tc_id);
                (*tests_failed)++;
            }
            EVP_PKEY_free(privkey);
            continue;
        }

        // Initialize key agreement context
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
        if (ctx == NULL || EVP_PKEY_derive_init(ctx) <= 0) {
            printf("Test case %d: Derive init failed\n", test->tc_id);
            (*tests_failed)++;
            EVP_PKEY_free(privkey);
            EVP_PKEY_free(pubkey);
            continue;
        }

        // Set the peer public key
        if (EVP_PKEY_derive_set_peer(ctx, pubkey) <= 0) {
            if (expected == RESULT_INVALID || expected == RESULT_ACCEPTABLE) {
                // printf("Test case %d: Expected invalid (derive set peer failed)\n", test->tc_id);
                (*tests_passed)++;
            } else {
                printf("Test case %d: Derive set peer failed\n", test->tc_id);
                (*tests_failed)++;
            }
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(privkey);
            EVP_PKEY_free(pubkey);
            continue;
        }

        // Derive the shared secret
        unsigned char shared_secret[MAX_SHARED_SECRET_LEN];
        size_t shared_secret_len = sizeof(shared_secret);
        int derive_result = EVP_PKEY_derive(ctx, shared_secret, &shared_secret_len);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privkey);
        EVP_PKEY_free(pubkey);

        if (derive_result <= 0) {
            if (expected == RESULT_INVALID || expected == RESULT_ACCEPTABLE) {
                // printf("Test case %d: Expected invalid (derive failed)\n", test->tc_id);
                (*tests_passed)++;
            } else {
                printf("Test case %d: Derive failed\n", test->tc_id);
                (*tests_failed)++;
            }
            continue;
        }

        // Compare the derived shared secret with the expected value
        if (shared_secret_len != test->shared_len ||
            memcmp(shared_secret, test->shared, shared_secret_len) != 0) {
            if (expected == RESULT_INVALID || expected == RESULT_ACCEPTABLE) {
                printf("Test case %d: Expected invalid but derived value\n", test->tc_id);
                (*tests_failed)++;
            } else {
                printf("Test case %d: Shared secret mismatch\n", test->tc_id);
                (*tests_failed)++;
            }
        } else {
            if (expected == RESULT_INVALID) {
                printf("Test case %d: Expected invalid but test passed\n", test->tc_id);
                (*tests_failed)++;
            } else {
                (*tests_passed)++;
            }
        }
    }
}

/**
 * @brief Executes XDH key agreement tests using JWK encoded keys.
 *
 * This function processes test cases where keys are encoded using JWK (JSON Web Key) format.
 *
 * @param tests_passed Pointer to an integer tracking the number of passed tests.
 * @param tests_failed Pointer to an integer tracking the number of failed tests.
 */
void test_xdh_jwk_cases(int *tests_passed, int *tests_failed) {
    size_t NUM_TEST_CASES = sizeof(xdh_jwk_test_cases) / sizeof(xdh_jwk_test_cases[0]);

    for (size_t i = 0; i < NUM_TEST_CASES; i++) {
        const XdhJwkTestCase *test = &xdh_jwk_test_cases[i];
        ExpectedResult expected = parse_expected_result(test->result);

        // Determine the curve type based on the test case
        int curve_nid = 0;
        if (strcmp(test->curve, "curve25519") == 0) {
            curve_nid = EVP_PKEY_X25519;
        } else if (strcmp(test->curve, "curve448") == 0) {
            curve_nid = EVP_PKEY_X448;
        } else {
            printf("Test case %d: Unsupported curve %s\n", test->tc_id, test->curve);
            (*tests_failed)++;
            continue;
        }

        // Decode the private key from base64url
        size_t private_key_len = 0;
        unsigned char *private_key_bytes = base64url_decode(test->private_d, &private_key_len);
        if (private_key_bytes == NULL) {
            printf("Test case %d: Failed to decode private key\n", test->tc_id);
            (*tests_failed)++;
            continue;
        }
        EVP_PKEY *privkey = EVP_PKEY_new_raw_private_key(
            curve_nid, NULL, private_key_bytes, private_key_len);
        free(private_key_bytes);
        if (privkey == NULL) {
            if (expected == RESULT_INVALID || expected == RESULT_ACCEPTABLE) {
                // printf("Test case %d: Expected invalid (private key load failed)\n", test->tc_id);
                (*tests_passed)++;
            } else {
                printf("Test case %d: Failed to load private key\n", test->tc_id);
                (*tests_failed)++;
            }
            continue;
        }

        // Decode the public key from base64url
        size_t public_key_len = 0;
        unsigned char *public_key_bytes = base64url_decode(test->public_x, &public_key_len);
        if (public_key_bytes == NULL) {
            printf("Test case %d: Failed to decode public key\n", test->tc_id);
            EVP_PKEY_free(privkey);
            (*tests_failed)++;
            continue;
        }
        EVP_PKEY *pubkey = EVP_PKEY_new_raw_public_key(
            curve_nid, NULL, public_key_bytes, public_key_len);
        free(public_key_bytes);
        if (pubkey == NULL) {
            if (expected == RESULT_INVALID || expected == RESULT_ACCEPTABLE) {
                // printf("Test case %d: Expected invalid (public key load failed)\n", test->tc_id);
                (*tests_passed)++;
            } else {
                printf("Test case %d: Failed to load public key\n", test->tc_id);
                (*tests_failed)++;
            }
            EVP_PKEY_free(privkey);
            continue;
        }

        // Initialize key agreement context
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
        if (ctx == NULL || EVP_PKEY_derive_init(ctx) <= 0) {
            printf("Test case %d: Derive init failed\n", test->tc_id);
            (*tests_failed)++;
            EVP_PKEY_free(privkey);
            EVP_PKEY_free(pubkey);
            continue;
        }

        // Set the peer public key
        if (EVP_PKEY_derive_set_peer(ctx, pubkey) <= 0) {
            if (expected == RESULT_INVALID || expected == RESULT_ACCEPTABLE) {
                // printf("Test case %d: Expected invalid (derive set peer failed)\n", test->tc_id);
                (*tests_passed)++;
            } else {
                printf("Test case %d: Derive set peer failed\n", test->tc_id);
                (*tests_failed)++;
            }
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(privkey);
            EVP_PKEY_free(pubkey);
            continue;
        }

        // Derive the shared secret
        unsigned char shared_secret[MAX_SHARED_SECRET_LEN];
        size_t shared_secret_len = sizeof(shared_secret);
        int derive_result = EVP_PKEY_derive(ctx, shared_secret, &shared_secret_len);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privkey);
        EVP_PKEY_free(pubkey);

        if (derive_result <= 0) {
            if (expected == RESULT_INVALID || expected == RESULT_ACCEPTABLE) {
                // printf("Test case %d: Expected invalid (derive failed)\n", test->tc_id);
                (*tests_passed)++;
            } else {
                printf("Test case %d: Derive failed\n", test->tc_id);
                (*tests_failed)++;
            }
            continue;
        }

        // Compare the derived shared secret with the expected value
        if (shared_secret_len != test->shared_len ||
            memcmp(shared_secret, test->shared, shared_secret_len) != 0) {
            if (expected == RESULT_INVALID || expected == RESULT_ACCEPTABLE) {
                printf("Test case %d: Expected invalid but derived value\n", test->tc_id);
                (*tests_failed)++;
            } else {
                printf("Test case %d: Shared secret mismatch\n", test->tc_id);
                (*tests_failed)++;
            }
        } else {
            if (expected == RESULT_INVALID) {
                printf("Test case %d: Expected invalid but test passed\n", test->tc_id);
                (*tests_failed)++;
            } else {
                (*tests_passed)++;
            }
        }
    }
}

/**
 * @brief Executes XDH key agreement tests using PEM encoded keys.
 *
 * This function processes test cases where keys are encoded using PEM format.
 *
 * @param tests_passed Pointer to an integer tracking the number of passed tests.
 * @param tests_failed Pointer to an integer tracking the number of failed tests.
 */
void test_xdh_pem_cases(int *tests_passed, int *tests_failed) {
    size_t NUM_TEST_CASES = sizeof(xdh_pem_test_cases) / sizeof(xdh_pem_test_cases[0]);

    for (size_t i = 0; i < NUM_TEST_CASES; i++) {
        const XdhPemTestCase *test = &xdh_pem_test_cases[i];
        ExpectedResult expected = parse_expected_result(test->result);

        // Determine the curve type based on the test case
        int curve_nid = 0;
        if (strcmp(test->curve, "curve25519") == 0) {
            curve_nid = EVP_PKEY_X25519;
        } else if (strcmp(test->curve, "curve448") == 0) {
            curve_nid = EVP_PKEY_X448;
        } else {
            printf("Test case %d: Unsupported curve %s\n", test->tc_id, test->curve);
            (*tests_failed)++;
            continue;
        }

        // Load the private key from PEM format
        BIO *bio = BIO_new_mem_buf(test->private_key_pem, -1);
        if (bio == NULL) {
            printf("Test case %d: Failed to create BIO for private key\n", test->tc_id);
            (*tests_failed)++;
            continue;
        }
        EVP_PKEY *privkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (privkey == NULL) {
            if (expected == RESULT_INVALID || expected == RESULT_ACCEPTABLE) {
                // printf("Test case %d: Expected invalid (private key load failed)\n", test->tc_id);
                (*tests_passed)++;
            } else {
                printf("Test case %d: Failed to load private key\n", test->tc_id);
                (*tests_failed)++;
            }
            continue;
        }

        // Load the public key from PEM format
        bio = BIO_new_mem_buf(test->public_key_pem, -1);
        if (bio == NULL) {
            printf("Test case %d: Failed to create BIO for public key\n", test->tc_id);
            EVP_PKEY_free(privkey);
            (*tests_failed)++;
            continue;
        }
        EVP_PKEY *pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (pubkey == NULL) {
            if (expected == RESULT_INVALID || expected == RESULT_ACCEPTABLE) {
                // printf("Test case %d: Expected invalid (public key load failed)\n", test->tc_id);
                (*tests_passed)++;
            } else {
                printf("Test case %d: Failed to load public key\n", test->tc_id);
                (*tests_failed)++;
            }
            EVP_PKEY_free(privkey);
            continue;
        }

        // Initialize key agreement context
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
        if (ctx == NULL || EVP_PKEY_derive_init(ctx) <= 0) {
            printf("Test case %d: Derive init failed\n", test->tc_id);
            (*tests_failed)++;
            EVP_PKEY_free(privkey);
            EVP_PKEY_free(pubkey);
            continue;
        }

        // Set the peer public key
        if (EVP_PKEY_derive_set_peer(ctx, pubkey) <= 0) {
            if (expected == RESULT_INVALID || expected == RESULT_ACCEPTABLE) {
                // printf("Test case %d: Expected invalid (derive set peer failed)\n", test->tc_id);
                (*tests_passed)++;
            } else {
                printf("Test case %d: Derive set peer failed\n", test->tc_id);
                (*tests_failed)++;
            }
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(privkey);
            EVP_PKEY_free(pubkey);
            continue;
        }

        // Derive the shared secret
        unsigned char shared_secret[MAX_SHARED_SECRET_LEN];
        size_t shared_secret_len = sizeof(shared_secret);
        int derive_result = EVP_PKEY_derive(ctx, shared_secret, &shared_secret_len);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privkey);
        EVP_PKEY_free(pubkey);

        if (derive_result <= 0) {
            if (expected == RESULT_INVALID || expected == RESULT_ACCEPTABLE) {
                // printf("Test case %d: Expected invalid (derive failed)\n", test->tc_id);
                (*tests_passed)++;
            } else {
                printf("Test case %d: Derive failed\n", test->tc_id);
                (*tests_failed)++;
            }
            continue;
        }

        // Compare the derived shared secret with the expected value
        if (shared_secret_len != test->shared_len ||
            memcmp(shared_secret, test->shared, shared_secret_len) != 0) {
            if (expected == RESULT_INVALID || expected == RESULT_ACCEPTABLE) {
                printf("Test case %d: Expected invalid but derived value\n", test->tc_id);
                (*tests_failed)++;
            } else {
                printf("Test case %d: Shared secret mismatch\n", test->tc_id);
                (*tests_failed)++;
            }
        } else {
            if (expected == RESULT_INVALID) {
                printf("Test case %d: Expected invalid but test passed\n", test->tc_id);
                (*tests_failed)++;
            } else {
                (*tests_passed)++;
            }
        }
    }
}

/**
 * @brief Generates an XDH key pair and prints the key formats and encodings.
 *
 * This function mimics the Java `testKeyGeneration` and `testKeyGenerationWithName` tests.
 *
 * @param curve The curve type ("X25519" or "X448").
 */
void generate_and_print_xdh_keys(const char *curve) {
    int curve_nid = 0;
    if (strcmp(curve, "X25519") == 0) {
        curve_nid = EVP_PKEY_X25519;
    } else if (strcmp(curve, "X448") == 0) {
        curve_nid = EVP_PKEY_X448;
    } else {
        printf("Unsupported curve for key generation: %s\n", curve);
        return;
    }

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(curve_nid, NULL);
    if (!pctx) {
        fprintf(stderr, "Error creating PKEY_CTX for %s\n", curve);
        ERR_print_errors_fp(stderr);
        return;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        fprintf(stderr, "Error initializing keygen for %s\n", curve);
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pctx);
        return;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        fprintf(stderr, "Error generating key pair for %s\n", curve);
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pctx);
        return;
    }

    EVP_PKEY_CTX_free(pctx);

    // Extract private key encoding
    unsigned char *priv_der = NULL;
    int priv_len = i2d_PrivateKey(pkey, &priv_der);
    if (priv_len < 0) {
        fprintf(stderr, "Error encoding private key for %s\n", curve);
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        return;
    }

    // Extract public key encoding
    unsigned char *pub_der = NULL;
    int pub_len = i2d_PUBKEY(pkey, &pub_der);
    if (pub_len < 0) {
        fprintf(stderr, "Error encoding public key for %s\n", curve);
        ERR_print_errors_fp(stderr);
        OPENSSL_free(priv_der);
        EVP_PKEY_free(pkey);
        return;
    }

    // Print key formats and encodings
    printf("\n%s Key Pair Generated:\n", curve);
    printf("Private Key Format: PKCS#8\nEncoded: ");
    for (int i = 0; i < priv_len; i++) {
        printf("%02x", priv_der[i]);
    }
    printf("\n");

    printf("Public Key Format: SubjectPublicKeyInfo\nEncoded: ");
    for (int i = 0; i < pub_len; i++) {
        printf("%02x", pub_der[i]);
    }
    printf("\n");

    // Clean up
    OPENSSL_free(priv_der);
    OPENSSL_free(pub_der);
    EVP_PKEY_free(pkey);
}

/**
 * @brief Executes key generation tests for X25519 and X448.
 *
 * This function generates key pairs for both curves and prints their encodings.
 */
void test_key_generation() {
    printf("\n--- Key Generation Tests ---\n");
    generate_and_print_xdh_keys("X25519");
    generate_and_print_xdh_keys("X448");
}

/**
 * @brief Executes all test cases and key generation tests.
 *
 * This function initializes OpenSSL, runs all test case functions, performs key generation tests,
 * and summarizes the results.
 *
 * @return Exit status code (0 for success, 1 for failure).
 */
int main() {
    int tests_passed = 0;
    int tests_failed = 0;


    printf("Running Key generation test cases...\n");
    // Run key generation tests
    test_key_generation();

    // Run key agreement tests for different key formats
    printf("Testing XdhComp test cases...\n");
    test_xdh_comp_cases(&tests_passed, &tests_failed);

    printf("\nTesting XdhAsnComp test cases...\n");
    test_xdh_asn_cases(&tests_passed, &tests_failed);

    printf("\nTesting XdhJwkComp test cases...\n");
    test_xdh_jwk_cases(&tests_passed, &tests_failed);

    printf("\nTesting XdhPemComp test cases...\n");
    test_xdh_pem_cases(&tests_passed, &tests_failed);

    // Summarize test results
    printf("\n--- Test Summary ---\n");
    printf("Total tests passed: %d\n", tests_passed);
    printf("Total tests failed: %d\n", tests_failed);


    return (tests_failed == 0) ? 0 : 1;
}
