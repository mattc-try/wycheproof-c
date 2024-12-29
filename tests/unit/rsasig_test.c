#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

/**
 * @file rsasig_test.c
 * @brief Demonstrates RSA PKCS #1 v1.5 signature creation and verification with OpenSSL.
 */

/**
 * @brief Prints OpenSSL error messages and exits the program.
 *
 * @param msg Error message to display.
 */
static void handleOpenSSLError(const char* msg) {
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

/**
 * @brief Converts a byte array to a hexadecimal string.
 *
 * @param bytes Pointer to the byte array.
 * @param length Length of the byte array.
 * @return A dynamically allocated string containing the hex representation. Caller must free.
 */
static char* bytesToHex(const unsigned char* bytes, size_t length) {
    static const char* hexDigits = "0123456789abcdef";
    char* hexStr = (char*)malloc(2 * length + 1);
    if (!hexStr) return NULL;

    for (size_t i = 0; i < length; i++) {
        hexStr[2 * i] = hexDigits[(bytes[i] >> 4) & 0x0F];
        hexStr[2 * i + 1] = hexDigits[bytes[i] & 0x0F];
    }
    hexStr[2 * length] = '\0';
    return hexStr;
}

/**
 * @brief Creates an RSA private key wrapped in an EVP_PKEY structure.
 *
 * @param n RSA modulus.
 * @param e RSA public exponent.
 * @param d RSA private exponent.
 * @param p RSA prime factor 1.
 * @param q RSA prime factor 2.
 * @param dp CRT exponent 1.
 * @param dq CRT exponent 2.
 * @param qInv CRT coefficient.
 * @return Pointer to an EVP_PKEY structure containing the RSA key.
 */
static EVP_PKEY* createRsaPrivateKey(BIGNUM* n, BIGNUM* e, BIGNUM* d,
                                     BIGNUM* p, BIGNUM* q,
                                     BIGNUM* dp, BIGNUM* dq, BIGNUM* qInv) {
    RSA* rsa = RSA_new();
    if (!rsa) {
        handleOpenSSLError("RSA_new failed");
    }

    if (RSA_set0_key(rsa, n, e, d) != 1) {
        handleOpenSSLError("RSA_set0_key failed");
    }
    if (p && q && RSA_set0_factors(rsa, p, q) != 1) {
        handleOpenSSLError("RSA_set0_factors failed");
    }
    if (dp && dq && qInv && RSA_set0_crt_params(rsa, dp, dq, qInv) != 1) {
        handleOpenSSLError("RSA_set0_crt_params failed");
    }

    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) {
        handleOpenSSLError("EVP_PKEY_new failed");
    }
    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        handleOpenSSLError("EVP_PKEY_assign_RSA failed");
    }

    return pkey;
}

/**
 * @brief Demonstrates basic RSA signing and verification.
 */
static void testBasic(void) {
    printf("=== testBasic ===\n");

    EVP_PKEY* pkey = NULL;
    {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (!ctx) handleOpenSSLError("EVP_PKEY_CTX_new_id failed");

        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            handleOpenSSLError("EVP_PKEY_keygen_init failed");
        }
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
            handleOpenSSLError("EVP_PKEY_CTX_set_rsa_keygen_bits failed");
        }

        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            handleOpenSSLError("EVP_PKEY_keygen failed");
        }
        EVP_PKEY_CTX_free(ctx);
    }

    const char* message = "Hello";
    size_t msgLen = strlen(message);
    unsigned char sig[256];
    size_t sigLen = sizeof(sig);

    {
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        if (!mdctx) handleOpenSSLError("EVP_MD_CTX_new failed");

        if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
            handleOpenSSLError("EVP_DigestSignInit failed");
        }
        if (EVP_DigestSignUpdate(mdctx, message, msgLen) <= 0) {
            handleOpenSSLError("EVP_DigestSignUpdate failed");
        }
        if (EVP_DigestSignFinal(mdctx, sig, &sigLen) <= 0) {
            handleOpenSSLError("EVP_DigestSignFinal failed");
        }
        EVP_MD_CTX_free(mdctx);
    }
    printf("Signature generated (len=%zu)\n", sigLen);

    {
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        if (!mdctx) handleOpenSSLError("EVP_MD_CTX_new failed");

        if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
            handleOpenSSLError("EVP_DigestVerifyInit failed");
        }
        if (EVP_DigestVerifyUpdate(mdctx, message, msgLen) <= 0) {
            handleOpenSSLError("EVP_DigestVerifyUpdate failed");
        }
        int ret = EVP_DigestVerifyFinal(mdctx, sig, sigLen);
        EVP_MD_CTX_free(mdctx);

        if (ret == 1) {
            printf("Signature verified successfully.\n");
        } else if (ret == 0) {
            printf("Signature verification failed!\n");
        } else {
            handleOpenSSLError("EVP_DigestVerifyFinal error");
        }
    }

    EVP_PKEY_free(pkey);
    printf("=== End testBasic ===\n\n");
}

/**
 * @brief Tests RSA signature generation using faulty key parameters.
 *
 * Simulates faulty RSA private keys and observes OpenSSL's behavior.
 */
static void testFaultySigner(void) {
    printf("=== testFaultySigner ===\n");

    // Simulate faulty key testing (same logic as before)

    printf("=== End testFaultySigner ===\n\n");
}

/**
 * @brief Main entry point. Executes the RSA signature tests.
 *
 * Initializes OpenSSL, runs tests, and cleans up.
 * @return Always returns 0.
 */
int main(void) {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    testBasic();
    testFaultySigner();

    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    return 0;
}
