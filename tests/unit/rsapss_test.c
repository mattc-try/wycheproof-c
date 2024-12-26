/**
 * @file rsa_pss_tests.c
 * @brief Demonstrates RSA-PSS public key operations, signing, and verification using OpenSSL.
 *
 * This program includes functions for:
 * - Parsing RSA-PSS public keys with custom parameters.
 * - Signing and verifying messages with RSA-PSS using specific hash and padding configurations.
 * - Testing the randomization property of RSA-PSS signatures.
 *
 * Dependencies: OpenSSL library.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>

/**
 * @brief Helper macro to handle test assertions.
 *
 * This macro terminates the program with an error message if the condition fails.
 *
 * @param cond The condition to evaluate.
 * @param msg The error message to display if the condition fails.
 */
#define TEST_ASSERT(cond, msg) \
  do {                         \
    if (!(cond)) {            \
      fprintf(stderr, "Test failed: %s\n", msg); \
      ERR_print_errors_fp(stderr); \
      exit(1);                \
    }                         \
  } while (0)


/**
 * @brief Converts a single hexadecimal character to its integer value.
 *
 * @param c The hexadecimal character.
 * @return The integer value of the hexadecimal character, or -1 on error.
 */
static int hex_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/**
 * @brief Converts a hex string to a dynamically allocated byte array.
 *
 * This function allocates memory for the output array, which must be freed by the caller.
 *
 * @param hex The input hex string.
 * @param[out] out The dynamically allocated output array.
 * @return The length of the output array, or -1 on error.
 */
static int hex_to_bytes(const char* hex, unsigned char** out) {
  size_t len = strlen(hex);
  if ((len & 1) != 0) {
    return -1;  /* Must be even length. */
  }
  size_t out_len = len / 2;
  unsigned char* buf = (unsigned char*)OPENSSL_malloc(out_len);
  if (buf == NULL) {
    return -1;
  }

  for (size_t i = 0; i < out_len; i++) {
    int hi = hex_value(hex[2 * i]);
    int lo = hex_value(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) {
      OPENSSL_free(buf);
      return -1;
    }
    buf[i] = (unsigned char)((hi << 4) | lo);
  }
  *out = buf;
  return (int)out_len;
}

/**
 * @brief Prints a buffer as a hex string for debugging purposes.
 *
 * @param label A label to prefix the output.
 * @param data The buffer to print.
 * @param len The length of the buffer.
 */
static void print_hex(const char* label, const unsigned char* data, size_t len) {
  printf("%s: ", label);
  for (size_t i = 0; i < len; i++) {
    printf("%02X", data[i]);
  }
  printf("\n");
}

/* ============================================================================
 * Test 1: Decode a RSASSA-PSS public key that uses OID id-RSASSA-PSS and custom
 *         MGF1/SHA-256/saltLength=20, then re-encode and compare.
 *
 * The Java code checks that the parameters are recognized. In OpenSSL, we can
 * decode it with d2i_PUBKEY, then re-encode with i2d_PUBKEY, verifying that the
 * raw bytes match.
 * ============================================================================
 */
/**
 * @brief Test decoding and re-encoding an RSA-PSS public key with custom parameters.
 *
 * This test validates that the parsed key can be re-encoded to match the original.
 */
static void testDecodeEncodePublicKeyWithPssParameters(void) {
  /* This is the same hex-encoded public key from RsaPssTest. */
  const char* encodedPubKeyHex =
    "30820151303c06092a864886f70d01010a302fa00f300d060960864801650304"
    "02010500a11c301a06092a864886f70d010108300d0609608648016503040201"
    "05000382010f003082010a0282010100b09191ef91e8b4ab58f7c66430636641"
    "0988d8cba6f2e0f33495d37b355828d04554472e854dff7d8c1dfd1ea50123de"
    "12d34b77280220184b924db82a535978e9bfe7a6111f455028f18cd923c54144"
    "08a247409d7121a99c3594708c0dd9cdebf1c9bb0060ff1c4c0363e25fac0d5b"
    "bf85013945f393b0b9673780c6f579353ae895d7dc891220a92bac0a8deb35b5"
    "20803cf82b19c27232a889d0f04fb2bde6623f357e3e56027298379d10bee8fa"
    "4e0c29029a78fde01694719d2d036fe726aa5633205553565f127a78fec46918"
    "182e41a16c5cc86bd3b77d26c5113082cb1f2d83d9213eca019bbdee99001e11"
    "16bcfec1242ece175558b15c5bbbc4710203010001";

  unsigned char* der = NULL;
  int der_len = hex_to_bytes(encodedPubKeyHex, &der);
  TEST_ASSERT(der_len > 0, "hex_to_bytes failed.");

  /* Decode the public key. */
  const unsigned char* p = der;
  EVP_PKEY* pkey = d2i_PUBKEY(NULL, &p, der_len);
  TEST_ASSERT(pkey != NULL, "d2i_PUBKEY failed to parse RSA-PSS public key.");

  /* Re-encode it. */
  unsigned char* out = NULL;
  int out_len = i2d_PUBKEY(pkey, &out);
  TEST_ASSERT(out_len > 0, "i2d_PUBKEY failed to re-encode RSA-PSS key.");

  /* Compare the original DER with the re-encoded DER. */
  TEST_ASSERT(out_len == der_len, "Re-encoded key length differs from original.");
  TEST_ASSERT(memcmp(der, out, out_len) == 0, "Re-encoded key differs from original.");

  OPENSSL_free(der);
  OPENSSL_free(out);
  EVP_PKEY_free(pkey);

  printf("[OK] testDecodeEncodePublicKeyWithPssParameters\n");
}

/* ============================================================================
 * Test 2: Generate an RSA-PSS key, sign, then verify. We explicitly set:
 *   - Hash = SHA-256
 *   - MGF1 with SHA-256
 *   - Salt length = 32
 *
 * This test uses the EVP_DigestSign* and EVP_DigestVerify* family, so OpenSSL
 * does the hashing of the message internally.
 * ============================================================================
 */
/**
 * @brief Test RSA-PSS signing and verification with custom parameters.
 *
 * This test demonstrates how to configure RSA-PSS parameters for signing 
 * and verifies the generated signature.
 */
static void testSignVerifyWithPssParameters(void) {
    // 1) Generate a plain RSA key (2048 bits).
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    TEST_ASSERT(kctx != NULL, "Failed to create kctx");
    TEST_ASSERT(EVP_PKEY_keygen_init(kctx) == 1, "keygen_init failed");
    TEST_ASSERT(EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) == 1, "set bits failed");
    TEST_ASSERT(EVP_PKEY_keygen(kctx, &pkey) == 1, "EVP_PKEY_keygen failed");
    EVP_PKEY_CTX_free(kctx);

    /* ---------------------------------------------------------
     * 2) SIGN the message with RSA-PSS, letting OpenSSL do the hashing
     * --------------------------------------------------------- */
    EVP_MD_CTX *mdctx_sign = EVP_MD_CTX_new();
    TEST_ASSERT(mdctx_sign != NULL, "mdctx_sign alloc failed");

    EVP_PKEY_CTX *signParams = NULL;  // This will be set by DigestSignInit
    TEST_ASSERT(
        EVP_DigestSignInit(mdctx_sign, &signParams, EVP_sha256(), NULL, pkey) == 1,
        "DigestSignInit failed"
    );
    // Now set RSA-PSS parameters:
    TEST_ASSERT(EVP_PKEY_CTX_set_rsa_padding(signParams, RSA_PKCS1_PSS_PADDING) == 1,
                "set PSS padding fail");
    TEST_ASSERT(EVP_PKEY_CTX_set_rsa_mgf1_md(signParams, EVP_sha256()) == 1,
                "set mgf1=sha256 fail");
    TEST_ASSERT(EVP_PKEY_CTX_set_rsa_pss_saltlen(signParams, 32) == 1,
                "set saltlen=32 fail");

    // Provide plaintext data, e.g. 4 bytes
    unsigned char message[] = {0x01, 0x02, 0x03, 0x04};
    TEST_ASSERT(EVP_DigestSignUpdate(mdctx_sign, message, sizeof(message)) == 1,
                "DigestSignUpdate fail");

    // Determine required size for signature
    size_t sigLen = 0;
    TEST_ASSERT(EVP_DigestSignFinal(mdctx_sign, NULL, &sigLen) == 1,
                "DigestSignFinal (get size) fail");

    // Allocate signature buffer
    unsigned char *signature = OPENSSL_malloc(sigLen);
    TEST_ASSERT(signature != NULL, "OPENSSL_malloc for signature fail");

    // Produce the signature
    TEST_ASSERT(EVP_DigestSignFinal(mdctx_sign, signature, &sigLen) == 1,
                "DigestSignFinal (sign) fail");

    EVP_MD_CTX_free(mdctx_sign);

    /* ---------------------------------------------------------
     * 3) VERIFY the signature with RSA-PSS, letting OpenSSL hash
     * --------------------------------------------------------- */
    EVP_MD_CTX *mdctx_verify = EVP_MD_CTX_new();
    TEST_ASSERT(mdctx_verify != NULL, "mdctx_verify alloc fail");

    EVP_PKEY_CTX *verifyParams = NULL;
    TEST_ASSERT(
        EVP_DigestVerifyInit(mdctx_verify, &verifyParams, EVP_sha256(), NULL, pkey) == 1,
        "DigestVerifyInit fail"
    );

    // Same RSA-PSS params
    TEST_ASSERT(EVP_PKEY_CTX_set_rsa_padding(verifyParams, RSA_PKCS1_PSS_PADDING) == 1,
                "set pss padding fail");
    TEST_ASSERT(EVP_PKEY_CTX_set_rsa_mgf1_md(verifyParams, EVP_sha256()) == 1,
                "set mgf1=sha256 fail");
    TEST_ASSERT(EVP_PKEY_CTX_set_rsa_pss_saltlen(verifyParams, 32) == 1,
                "set saltlen=32 fail");

    // Provide the same message
    TEST_ASSERT(EVP_DigestVerifyUpdate(mdctx_verify, message, sizeof(message)) == 1,
                "DigestVerifyUpdate fail");

    int rc = EVP_DigestVerifyFinal(mdctx_verify, signature, sigLen);
    EVP_MD_CTX_free(mdctx_verify);
    EVP_PKEY_free(pkey);
    OPENSSL_free(signature);

    // rc = 1 means verified OK
    TEST_ASSERT(rc == 1, "Signature did not verify");
    printf("[OK] testSignVerifyWithPssParameters\n");
}

/* ============================================================================
 * Test 3: Test randomization of RSA-PSS signatures.
 *
 * Here we do a "raw sign" approach: we call EVP_PKEY_sign() with a digest
 * buffer. That means we must compute a 32-byte SHA-256 digest ourselves.
 *
 * We'll sign the same digest multiple times, expecting different outputs
 * (due to the salt in RSA-PSS).
 * ============================================================================
 */
/**
 * @brief Test the randomization property of RSA-PSS signatures.
 *
 * Signs the same data multiple times, verifying that the signatures differ.
 */
static void testRandomization(void) {
  int keyBits = 2048;
  EVP_PKEY* pkey = NULL;
  EVP_PKEY_CTX* kctx = NULL;
  TEST_ASSERT((kctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL)) != NULL,
              "Failed to create ctx for RSA generation.");
  TEST_ASSERT(EVP_PKEY_keygen_init(kctx) == 1, "EVP_PKEY_keygen_init failed.");
  TEST_ASSERT(EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, keyBits) == 1,
              "Failed to set RSA key size.");
  TEST_ASSERT(EVP_PKEY_keygen(kctx, &pkey) == 1, "Failed to generate RSA key.");
  EVP_PKEY_CTX_free(kctx);
  kctx = NULL;

  /* Prepare a signing context for "raw sign" with PSS padding and SHA256. */
  EVP_PKEY_CTX* signCtx = EVP_PKEY_CTX_new(pkey, NULL);
  TEST_ASSERT(signCtx != NULL, "Failed to create sign context.");
  TEST_ASSERT(EVP_PKEY_sign_init(signCtx) == 1, "Failed to init sign.");

  TEST_ASSERT(EVP_PKEY_CTX_set_rsa_padding(signCtx, RSA_PKCS1_PSS_PADDING) == 1,
              "Set pss padding fail.");
  // We want to sign a 32-byte digest (SHA-256). The library uses this to verify input length.
  TEST_ASSERT(EVP_PKEY_CTX_set_signature_md(signCtx, EVP_sha256()) == 1,
              "Set signature md fail.");
  TEST_ASSERT(EVP_PKEY_CTX_set_rsa_mgf1_md(signCtx, EVP_sha256()) == 1,
              "Set mgf1 md fail.");
  TEST_ASSERT(EVP_PKEY_CTX_set_rsa_pss_saltlen(signCtx, 32) == 1,
              "Set salt len fail.");

  /* We'll sign the same 8-byte message, but since this is a raw sign approach,
   * we must compute a 32-byte SHA-256 digest ourselves. */
  unsigned char message[8] = {0};
  unsigned char digest[SHA256_DIGEST_LENGTH];

  /* Precompute the digest once. It's the same for each signature attempt. */
  SHA256(message, sizeof(message), digest);

  const int samples = 8;
  size_t sigLen = 0;
  /* First call gets size for the final signature. We pass in the digest (32 bytes). */
  int rc = EVP_PKEY_sign(signCtx, NULL, &sigLen, digest, sizeof(digest));
  TEST_ASSERT(rc == 1 && sigLen > 0, "Failed to get sig size once.");

  /* We'll store them as hex strings to compare. */
  char** sigHex = (char**)calloc(samples, sizeof(char*));
  for (int i = 0; i < samples; i++) {
    size_t tmpLen = sigLen;
    unsigned char* sigBuf = (unsigned char*)OPENSSL_malloc(sigLen);
    TEST_ASSERT(sigBuf != NULL, "Failed to malloc sigBuf.");

    /* Sign the 32-byte digest again; we expect randomization. */
    rc = EVP_PKEY_sign(signCtx, sigBuf, &tmpLen, digest, sizeof(digest));
    TEST_ASSERT(rc == 1, "Sign failed unexpectedly.");

    /* Convert to hex. */
    char* hexOut = (char*)calloc((tmpLen * 2 + 1), sizeof(char));
    for (size_t j = 0; j < tmpLen; j++) {
      sprintf(&hexOut[j * 2], "%02X", sigBuf[j]);
    }
    sigHex[i] = hexOut;

    OPENSSL_free(sigBuf);
  }
  EVP_PKEY_CTX_free(signCtx);
  signCtx = NULL;
  EVP_PKEY_free(pkey);

  /* Compare all signatures; ensure no duplicates. */
  for (int i = 0; i < samples; i++) {
    for (int j = i + 1; j < samples; j++) {
      TEST_ASSERT(strcmp(sigHex[i], sigHex[j]) != 0,
                  "Found two identical RSA-PSS signatures => no randomization?");
    }
  }

  for (int i = 0; i < samples; i++) {
    free(sigHex[i]);
  }
  free(sigHex);

  printf("[OK] testRandomization\n");
}

/**
 * @brief Main entry point for the RSA-PSS test suite.
 *
 * Initializes OpenSSL, runs the tests, and performs cleanup before exiting.
 *
 * @return 0 on successful completion of all tests.
 */
int main(void) {
  /* Initialize OpenSSL error strings (helpful for debugging) */
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();

  testDecodeEncodePublicKeyWithPssParameters();
  testSignVerifyWithPssParameters();
  testRandomization();

  /* Cleanup */
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();

  printf("All tests passed.\n");
  return 0;
}
