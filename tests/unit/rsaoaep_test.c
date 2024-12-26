/**
 * @file rsa_oaep_encryption.c
 * @brief Demonstrates RSA encryption using OAEP parameters with OpenSSL.
 *
 * This program tests various combinations of OAEP and MGF1 message digests 
 * for RSA encryption using OpenSSL. It includes helper functions to convert 
 * hex-encoded keys, set OAEP parameters, and perform RSA encryption.
 *
 * Dependencies: OpenSSL library.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>

/**
 * @brief Converts a hex string to a binary buffer.
 *
 * This function processes a hex-encoded string and converts it into a binary
 * buffer. It ensures that the input string has an even number of hex digits
 * and fits within the provided output buffer.
 *
 * @param hex The input hex string to convert.
 * @param[out] out The buffer to store the resulting binary data.
 * @param max_out The maximum size of the output buffer.
 * @return The number of bytes written to the output buffer, or -1 on error.
 */
static int hex_to_bytes(const char *hex, unsigned char *out, size_t max_out) {
    size_t hex_len = strlen(hex);
    if ((hex_len % 2) != 0) {
        return -1;
    }
    size_t out_len = hex_len / 2;
    if (out_len > max_out) {
        return -1;
    }
    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1) {
            return -1;
        }
        out[i] = (unsigned char)byte;
    }
    return (int)out_len;
}

/**
 * @brief Prints details of the chosen OAEP parameters.
 *
 * Displays the selected message digest algorithms for OAEP and MGF1.
 * This is useful for verifying the configuration during testing.
 *
 * @param oaep_md_name The name of the message digest for OAEP.
 * @param mgf1_md_name The name of the message digest for MGF1.
 */
static void print_oaep_params(const char* oaep_md_name, const char* mgf1_md_name) {
    printf("  Using OAEP MD:   %s\n", oaep_md_name);
    printf("  Using MGF1 MD:   %s\n", mgf1_md_name);
}

/**
 * @brief Performs RSA encryption using specified OAEP parameters.
 *
 * This function configures an OpenSSL EVP_PKEY context with the given 
 * OAEP and MGF1 message digests, and performs a test encryption.
 *
 * @param pkey The RSA public key.
 * @param oaep_md_name The name of the message digest for OAEP.
 * @param mgf1_md_name The name of the message digest for MGF1.
 * @return 1 if the encryption succeeds, 0 otherwise.
 */
static int test_rsa_oaep_encryption(EVP_PKEY *pkey,
                                    const char* oaep_md_name,
                                    const char* mgf1_md_name) {
    int ret = 1;  // 1 for success, 0 for error

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ctx == NULL) {
        fprintf(stderr, "Error: EVP_PKEY_CTX_new failed.\n");
        return 0;
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        fprintf(stderr, "Error: EVP_PKEY_encrypt_init failed.\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        fprintf(stderr, "Error: EVP_PKEY_CTX_set_rsa_padding failed.\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    const EVP_MD *oaep_md = EVP_get_digestbyname(oaep_md_name);
    if (!oaep_md) {
        fprintf(stderr, "Error: Unsupported digest: %s\n", oaep_md_name);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, oaep_md) <= 0) {
        fprintf(stderr, "Error: EVP_PKEY_CTX_set_rsa_oaep_md failed.\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    const EVP_MD *mgf1_md = EVP_get_digestbyname(mgf1_md_name);
    if (!mgf1_md) {
        fprintf(stderr, "Error: Unsupported MGF1 digest: %s\n", mgf1_md_name);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, mgf1_md) <= 0) {
        fprintf(stderr, "Error: EVP_PKEY_CTX_set_rsa_mgf1_md failed.\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    unsigned char plaintext[] = "Hello, OpenSSL RSA-OAEP!";
    unsigned char ciphertext[1024];
    size_t ciphertext_len = sizeof(ciphertext);

    if (EVP_PKEY_encrypt(ctx, ciphertext, &ciphertext_len,
                         plaintext, sizeof(plaintext) - 1) <= 0) {
        fprintf(stderr, "Error: EVP_PKEY_encrypt failed.\n");
        ret = 0;
    }

    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/**
 * @brief Entry point of the program.
 *
 * The main function converts a hex-encoded RSA public key to a binary format,
 * initializes an EVP_PKEY object, and tests various combinations of OAEP and
 * MGF1 message digests for RSA encryption.
 *
 * @return Exit status of the program (0 for success, 1 for error).
 */
int main(void) {
    const char *pubKeyHex =
        "30820122300d06092a864886f70d01010105000382010f003082010a02820101"
        "00bdf90898577911c71c4d9520c5f75108548e8dfd389afdbf9c997769b8594e"
        "7dc51c6a1b88d1670ec4bb03fa550ba6a13d02c430bfe88ae4e2075163017f4d"
        "8926ce2e46e068e88962f38112fc2dbd033e84e648d4a816c0f5bd89cadba0b4"
        "d6cac01832103061cbb704ebacd895def6cff9d988c5395f2169a6807207333d"
        "569150d7f569f7ebf4718ddbfa2cdbde4d82a9d5d8caeb467f71bfc0099b0625"
        "a59d2bad12e3ff48f2fd50867b89f5f876ce6c126ced25f28b1996ee21142235"
        "fb3aef9fe58d9e4ef6e4922711a3bbcd8adcfe868481fd1aa9c13e5c658f5172"
        "617204314665092b4d8dca1b05dc7f4ecd7578b61edeb949275be8751a5a1fab"
        "c30203010001";

    unsigned char pubKeyDer[1024];
    int der_len = hex_to_bytes(pubKeyHex, pubKeyDer, sizeof(pubKeyDer));
    if (der_len < 0) {
        fprintf(stderr, "Error converting pubKeyHex to DER bytes.\n");
        return 1;
    }

    const unsigned char *p = pubKeyDer;
    EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, der_len);
    if (!pkey) {
        fprintf(stderr, "Error: d2i_PUBKEY failed.\n");
        return 1;
    }

    const char *hashes[] = {
        "SHA1", "SHA224", "SHA256", "SHA384", "SHA512",
        "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"
    };
    size_t num_hashes = sizeof(hashes) / sizeof(hashes[0]);

    for (size_t i = 0; i < num_hashes; i++) {
        for (size_t j = 0; j < num_hashes; j++) {
            printf("Testing OAEP with OAEP MD = %s, MGF1 MD = %s\n", hashes[i], hashes[j]);
            print_oaep_params(hashes[i], hashes[j]);

            int ok = test_rsa_oaep_encryption(pkey, hashes[i], hashes[j]);
            if (ok) {
                printf("  Encryption succeeded!\n\n");
            } else {
                printf("  Encryption FAILED.\n\n");
            }
        }
    }

    EVP_PKEY_free(pkey);
    return 0;
}
