// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
// either express or implied. See the License for the specific
// language governing permissions and limitations under the License.

/**
 * @file RsaKeyTest_C.c
 * @brief A C program rewriting key aspects of the Java RsaKeyTest using OpenSSL 3.0+ APIs.
 *
 * Build example:
 * @code
 *   gcc -o RsaKeyTest_C RsaKeyTest_C.c -lcrypto -lssl
 * @endcode
 *
 * Run:
 * @code
 *   ./RsaKeyTest_C
 * @endcode
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

// -----------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------

/**
 * @brief Converts a hexadecimal string to a byte array.
 *
 * Allocates memory for and fills a buffer with binary data represented by
 * the hexadecimal string.
 *
 * @param hex_string The input hexadecimal string.
 * @param out_len Pointer to store the length of the resulting byte array.
 * @return unsigned char* Returns a pointer to the allocated byte array, or NULL on failure.
 */
static unsigned char* hex_to_bytes(const char* hex_string, size_t* out_len) {
    size_t len = strlen(hex_string);
    // If the length of the string is not even, it's invalid hex
    if ((len % 2) != 0) {
        return NULL;
    }
    *out_len = len / 2;
    unsigned char* buf = (unsigned char*)malloc(*out_len);
    if (!buf) {
        return NULL;
    }
    for (size_t i = 0; i < *out_len; i++) {
        sscanf(&hex_string[2*i], "%2hhx", &buf[i]);
    }
    return buf;
}

/**
 * @brief Prints the OpenSSL error stack and terminates the program.
 *
 * This function is used to assist with debugging OpenSSL-related errors
 * by printing out the error stack and then exiting the application.
 *
 * @param msg A message to display before printing the error stack.
 */
static void print_openssl_error_and_exit(const char* msg) {
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

/**
 * @brief Checks whether a BIGNUM is negative or zero.
 *
 * This utility function returns 1 (true) if the number is
 * negative or zero, otherwise returns 0 (false).
 *
 * @param bn A pointer to the BIGNUM object.
 * @return int 1 if `bn` is negative or zero, 0 otherwise.
 */
static int BN_is_negative_or_zero(const BIGNUM* bn) {
    if (BN_is_negative(bn)) return 1;
    if (BN_is_zero(bn))     return 1;
    return 0;
}

// -----------------------------------------------------------------------
// Test 1: Parsing modified X.509-encoded RSA public keys
// -----------------------------------------------------------------------

// A small subset of "modified" hex-encoded RSA public keys for illustration.
// In the original Java test, many more are included.
static const char* MODIFIED_PUBLIC_KEYS[] = {
    // A known-good encoding from the Java file (ENCODED_PUBLIC_KEY).
    "30819f300d06092a864886f70d010101050003818d0030818902818100ab9014"
    "dc47d44b6d260fc1fef9ab022042fd9566e9d7b60c54100cb6e1d4edc9859046"
    "7d0502c17fce69d00ac5efb40b2cb167d8a44ab93d73c4d0f109fb5a26c2f882"
    "3236ff517cf84412e173679cfae42e043b6fec81f9d984b562517e6febe1f722"
    "95dbc3fdfc19d3240aa75515563f31dad83563f3a315acf9a0b351a23f020301"
    "0001",

    // A deliberately truncated or corrupted encoding.
    "30819e300d06092a864886f70d010101050003818c0030818902818100ab9014"
    "dc47d44b6d260fc1fef9ab022042fd9566e9d7b60c54100", // truncated

    // Example negative exponent scenario.
    "30819f300d06092a864886f70d010101050003818d0030818902818100ab9014"
    "dc47d44b6d260fc1fef9ab022042fd9566e9d7b60c54100cb6e1d4edc9859046"
    "7d0502c17fce69d00ac5efb40b2cb167d8a44ab93d73c4d0f109fb5a26c2f882"
    "3236ff517cf84412e173679cfae42e043b6fec81f9d984b562517e6febe1f722"
    "95dbc3fdfc19d3240aa75515563f31dad83563f3a315acf9a0b351a23f0203fe"
    "ffff",
};

// Number of items in MODIFIED_PUBLIC_KEYS
static const int NUM_MODIFIED_PUB_KEYS =
    (int)(sizeof(MODIFIED_PUBLIC_KEYS)/sizeof(MODIFIED_PUBLIC_KEYS[0]));

/**
 * @brief Parses and tests a series of modified X.509-encoded RSA public keys.
 *
 * This function attempts to parse each entry in MODIFIED_PUBLIC_KEYS
 * as a DER-encoded SubjectPublicKeyInfo. On success, it does some
 * basic checks of the resulting RSA key. Many entries are expected
 * to fail parsing (similar to InvalidKeySpecException in Java).
 */
static void test_modified_public_key_decoding(void) {
    printf("=== Test: Modified Public Key Decoding ===\n");
    for (int i = 0; i < NUM_MODIFIED_PUB_KEYS; i++) {
        const char* hexstr = MODIFIED_PUBLIC_KEYS[i];
        size_t der_len = 0;
        unsigned char* der = hex_to_bytes(hexstr, &der_len);
        if (!der) {
            printf("    [Key %d] hex_to_bytes error (invalid hex?), skip.\n", i);
            continue;
        }
        const unsigned char* p = der;

        // OpenSSL function to decode a SubjectPublicKeyInfo from DER.
        EVP_PKEY* pubkey = d2i_PUBKEY(NULL, &p, der_len);
        if (!pubkey) {
            // In Java: InvalidKeySpecException => expected or good.
            printf("    [Key %d] Parsing failed as expected or is invalid.\n", i);
        } else {
            // We got a key. Check some properties.
            printf("    [Key %d] Parsing succeeded.\n", i);

            if (EVP_PKEY_id(pubkey) == EVP_PKEY_RSA) {
                RSA* rsa = EVP_PKEY_get0_RSA(pubkey);
                if (rsa) {
                    const BIGNUM* n = NULL;
                    const BIGNUM* e = NULL;
                    RSA_get0_key(rsa, &n, &e, NULL);

                    if (BN_is_negative_or_zero(n)) {
                        printf("        => Modulus is negative or zero!\n");
                    }
                    if (BN_is_negative_or_zero(e)) {
                        printf("        => Exponent is negative or zero!\n");
                    } else {
                        // Quick check exponent > 1?
                        if (BN_cmp(e, BN_value_one()) <= 0) {
                            printf("        => Exponent <= 1 (bad)!\n");
                        } else {
                            printf("        => Looks like a plausible RSA public key.\n");
                        }
                    }
                }
            }
            EVP_PKEY_free(pubkey);
        }
        free(der);
    }
    printf("\n");
}

// -----------------------------------------------------------------------
// Test 2: Generating and verifying RSA keypairs of certain sizes
// -----------------------------------------------------------------------

/**
 * @brief Generates an RSA key of a specified bit length and performs basic checks.
 *
 * Uses OpenSSL 3.0+ to create an RSA key of `bits` length. Verifies
 * that the generated key is indeed RSA, checks the modulus size,
 * and confirms if the exponent is 65537.
 *
 * @param bits The desired RSA key size in bits (e.g., 2048, 3072).
 */
static void test_key_generation_size(int bits) {
    printf("=== Test: RSA Key Generation, bits=%d ===\n", bits);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx) {
        print_openssl_error_and_exit("EVP_PKEY_CTX_new_from_name() failed.");
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        print_openssl_error_and_exit("EVP_PKEY_keygen_init() failed.");
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        print_openssl_error_and_exit("EVP_PKEY_CTX_set_rsa_keygen_bits() failed.");
    }

    // Optionally set exponent = 65537.
    BIGNUM* bn65537 = BN_new();
    BN_set_word(bn65537, 65537UL);
    if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, bn65537) <= 0) {
        BN_free(bn65537);
        print_openssl_error_and_exit("EVP_PKEY_CTX_set1_rsa_keygen_pubexp() failed.");
    }
    BN_free(bn65537);

    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        print_openssl_error_and_exit("EVP_PKEY_generate() failed.");
    }
    EVP_PKEY_CTX_free(ctx);

    if (!pkey) {
        print_openssl_error_and_exit("EVP_PKEY_generate() returned NULL pkey.");
    }
    if (EVP_PKEY_id(pkey) != EVP_PKEY_RSA) {
        fprintf(stderr, "Generated key is not RSA.\n");
        EVP_PKEY_free(pkey);
        return;
    }

    RSA* rsa = EVP_PKEY_get0_RSA(pkey);
    if (!rsa) {
        fprintf(stderr, "EVP_PKEY_get0_RSA returned NULL.\n");
        EVP_PKEY_free(pkey);
        return;
    }

    const BIGNUM* n = NULL;
    const BIGNUM* e = NULL;
    const BIGNUM* d = NULL;
    RSA_get0_key(rsa, &n, &e, &d);

    int actual_bits = BN_num_bits(n);
    printf("    Generated RSA key has modulus size: %d bits\n", actual_bits);
    if (actual_bits < bits) {
        printf("    => Unexpected: Key is smaller than requested!\n");
    }

    // Check exponent is 65537.
    if (BN_cmp(e, BN_value_one()) <= 0) {
        printf("    => Exponent <= 1: invalid!\n");
    } else {
        if (BN_get_word(e) == 65537UL) {
            printf("    => Public exponent is 65537, as expected.\n");
        } else {
            printf("    => Public exponent is not 65537, found something else.\n");
        }
    }

    EVP_PKEY_free(pkey);
    printf("\n");
}

/**
 * @brief Main entry point for the test program.
 *
 * Initializes OpenSSL, performs two major tests:
 *  1. Parsing a series of modified public keys.
 *  2. Generating RSA key pairs of specific sizes.
 *
 * @return int Returns 0 on successful completion, or exits on error.
 */
int main(void) {
    // Initialize OpenSSL error strings, etc.
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // 1) Test decoding a variety of modified public keys.
    test_modified_public_key_decoding();

    // 2) Test generating RSA keys of certain sizes.
    test_key_generation_size(2048);
    test_key_generation_size(3072);

    // Cleanup
    EVP_cleanup();
    ERR_free_strings();

    printf("All tests done.\n");
    return 0;
}
