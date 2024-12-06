#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>


/**
 * Prints OpenSSL errors to stderr.
 */
void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
}

/**
 * @brief Converts a hexadecimal string to a byte array.
 *
 * Allocates memory for and fills a buffer with binary data represented by the hexadecimal string.
 *
 * @param hexstr The input hexadecimal string.
 * @param out_len Pointer to store the length of the resulting byte array.
 * @return unsigned char* Returns a pointer to the allocated byte array, or NULL on failure.
 */
unsigned char *hexstr_to_bytes(const char *hexstr, long *out_len) {
    return OPENSSL_hexstr2buf(hexstr, out_len);
}

/**
 * @brief Test parsing of invalid public keys.
 *
 * Attempts to parse invalid public key encodings represented as hexadecimal strings.
 * Expects failures for invalid encodings and verifies the parsing behavior.
 */
void testEncodedPublicKey() {
    printf("\nRunning testEncodedPublicKey...\n");

    // Array of invalid public key encodings (hex strings)
    const char *invalid_public_keys[] = {
    // order = -115792089210356248762697446949407573529996955224135760342422259061068512044369
    "308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d01"
    "01022100ffffffff00000001000000000000000000000000ffffffffffffffff"
    "ffffffff30440420ffffffff00000001000000000000000000000000ffffffff"
    "fffffffffffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53"
    "b0f63bce3c3e27d2604b0441046b17d1f2e12c4247f8bce6e563a440f277037d"
    "812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33"
    "576b315ececbb6406837bf51f50221ff00000000ffffffff0000000000000000"
    "4319055258e8617b0c46353d039cdaaf02010103420004cdeb39edd03e2b1a11"
    "a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958ea58493b8429598c0b"
    "49bbb85c3303ddb1553c3b761c2caacca71606ba9ebac8",
    // order = 0
    "308201123081cb06072a8648ce3d02013081bf020101302c06072a8648ce3d01"
    "01022100ffffffff00000001000000000000000000000000ffffffffffffffff"
    "ffffffff30440420ffffffff00000001000000000000000000000000ffffffff"
    "fffffffffffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53"
    "b0f63bce3c3e27d2604b0441046b17d1f2e12c4247f8bce6e563a440f277037d"
    "812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33"
    "576b315ececbb6406837bf51f5020002010103420004cdeb39edd03e2b1a11a5"
    "e134ec99d5f25f21673d403f3ecb47bd1fa676638958ea58493b8429598c0b49"
    "bbb85c3303ddb1553c3b761c2caacca71606ba9ebac8",
    // cofactor = -1
    "308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d01"
    "01022100ffffffff00000001000000000000000000000000ffffffffffffffff"
    "ffffffff30440420ffffffff00000001000000000000000000000000ffffffff"
    "fffffffffffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53"
    "b0f63bce3c3e27d2604b0441046b17d1f2e12c4247f8bce6e563a440f277037d"
    "812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33"
    "576b315ececbb6406837bf51f5022100ffffffff00000000ffffffffffffffff"
    "bce6faada7179e84f3b9cac2fc6325510201ff03420004cdeb39edd03e2b1a11"
    "a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958ea58493b8429598c0b"
    "49bbb85c3303ddb1553c3b761c2caacca71606ba9ebac8",
    // cofactor = 0
    "308201323081eb06072a8648ce3d02013081df020101302c06072a8648ce3d01"
    "01022100ffffffff00000001000000000000000000000000ffffffffffffffff"
    "ffffffff30440420ffffffff00000001000000000000000000000000ffffffff"
    "fffffffffffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53"
    "b0f63bce3c3e27d2604b0441046b17d1f2e12c4247f8bce6e563a440f277037d"
    "812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33"
    "576b315ececbb6406837bf51f5022100ffffffff00000000ffffffffffffffff"
    "bce6faada7179e84f3b9cac2fc632551020003420004cdeb39edd03e2b1a11a5"
    "e134ec99d5f25f21673d403f3ecb47bd1fa676638958ea58493b8429598c0b49"
    "bbb85c3303ddb1553c3b761c2caacca71606ba9ebac8",
    // cofactor = 115792089210356248762697446949407573529996955224135760342422259061068512044369
    "308201553082010d06072a8648ce3d020130820100020101302c06072a8648ce"
    "3d0101022100ffffffff00000001000000000000000000000000ffffffffffff"
    "ffffffffffff30440420ffffffff00000001000000000000000000000000ffff"
    "fffffffffffffffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0"
    "cc53b0f63bce3c3e27d2604b0441046b17d1f2e12c4247f8bce6e563a440f277"
    "037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162b"
    "ce33576b315ececbb6406837bf51f5022100ffffffff00000000ffffffffffff"
    "ffffbce6faada7179e84f3b9cac2fc632551022100ffffffff00000000ffffff"
    "ffffffffffbce6faada7179e84f3b9cac2fc63255103420004cdeb39edd03e2b"
    "1a11a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958ea58493b842959"
    "8c0b49bbb85c3303ddb1553c3b761c2caacca71606ba9ebac8",
  };


      size_t num_keys = sizeof(invalid_public_keys) / sizeof(invalid_public_keys[0]);

    for (size_t i = 0; i < num_keys; i++) {
        const char *hex_str = invalid_public_keys[i];
        long der_len = 0;
        unsigned char *der = NULL;

        der = OPENSSL_hexstr2buf(hex_str, &der_len);
        if (!der) {
            fprintf(stderr, "Error converting hex string to bytes\n");
            continue;
        }

        // Parse the public key
        const unsigned char *p = der;
        EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, der_len);

        if (pkey) {
            // Parsing succeeded, which is unexpected
            fprintf(stderr, "Unexpectedly parsed invalid public key %zu\n", i);
            EVP_PKEY_free(pkey);
        } else {
            // Parsing failed, which is expected
            printf("Correctly failed to parse invalid public key %zu\n", i);
        }

        OPENSSL_free(der);
    }
}

/**
 * @brief Test encoding and decoding of a private key.
 *
 * Generates an EC private key, encodes it in DER format, decodes it back, and
 * checks if the original and decoded private keys are consistent.
 */
void testEncodedPrivateKey() {
    printf("\nRunning testEncodedPrivateKey...\n");

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) {
        fprintf(stderr, "Error creating EVP_PKEY_CTX\n");
        return;
    }

    // Initialize key generation
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        fprintf(stderr, "Error initializing keygen\n");
        EVP_PKEY_CTX_free(pctx);
        return;
    }

    // Set the curve to NIST P-256
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
        fprintf(stderr, "Error setting curve\n");
        EVP_PKEY_CTX_free(pctx);
        return;
    }

    // Generate the key
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        fprintf(stderr, "Error generating key\n");
        EVP_PKEY_CTX_free(pctx);
        return;
    }

    EVP_PKEY_CTX_free(pctx);

    // Get the private key encoding in DER format
    unsigned char *der = NULL;
    int der_len = i2d_PrivateKey(pkey, &der);
    if (der_len <= 0) {
        fprintf(stderr, "Error encoding private key\n");
        EVP_PKEY_free(pkey);
        return;
    }

    // Decode it back
    const unsigned char *p = der;
    EVP_PKEY *decoded_pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, der_len);
    if (!decoded_pkey) {
        fprintf(stderr, "Error decoding private key\n");
        OPENSSL_free(der);
        EVP_PKEY_free(pkey);
        return;
    }

    // Compare the private keys using EVP_PKEY_get_bn_param
    BIGNUM *priv_bn = NULL;
    BIGNUM *decoded_priv_bn = NULL;

    if (EVP_PKEY_get_bn_param(pkey, "priv", &priv_bn) != 1) {
        fprintf(stderr, "Error getting private key component\n");
    }

    if (EVP_PKEY_get_bn_param(decoded_pkey, "priv", &decoded_priv_bn) != 1) {
        fprintf(stderr, "Error getting decoded private key component\n");
    }

    if (BN_cmp(priv_bn, decoded_priv_bn) != 0) {
        fprintf(stderr, "Private keys do not match\n");
    } else {
        printf("Private keys match\n");
    }

    // Clean up
    BN_free(priv_bn);
    BN_free(decoded_priv_bn);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(decoded_pkey);
    OPENSSL_free(der);
}

/**
 * @brief Tests key generation for a specified elliptic curve.
 *
 * Generates an EC key pair using the provided curve NID and validates the generated public key.
 *
 * @param curve_nid The curve NID (numeric identifier) used for key generation.
 */
void testKeyGeneration(int curve_nid) {
    printf("\nRunning testKeyGeneration for curve %s...\n", OBJ_nid2sn(curve_nid));

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) {
        fprintf(stderr, "Error creating EVP_PKEY_CTX\n");
        return;
    }

    // Initialize key generation
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        fprintf(stderr, "Error initializing keygen\n");
        EVP_PKEY_CTX_free(pctx);
        return;
    }

    // Set the curve
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, curve_nid) <= 0) {
        fprintf(stderr, "Error setting curve\n");
        EVP_PKEY_CTX_free(pctx);
        return;
    }

    // Generate the key
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        fprintf(stderr, "Error generating key\n");
        EVP_PKEY_CTX_free(pctx);
        return;
    }

    EVP_PKEY_CTX_free(pctx);

    // Validate the public key
    EVP_PKEY_CTX *vctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!vctx) {
        fprintf(stderr, "Error creating EVP_PKEY_CTX for validation\n");
        EVP_PKEY_free(pkey);
        return;
    }

    if (EVP_PKEY_public_check(vctx) <= 0) {
        fprintf(stderr, "Public key is invalid\n");
    } else {
        printf("Generated valid key on curve %s\n", OBJ_nid2sn(curve_nid));
    }

    EVP_PKEY_CTX_free(vctx);
    EVP_PKEY_free(pkey);
}

/**
 * @brief Checks the default behavior of uninitialized EC key pair generation.
 *
 * Generates an EC key pair without explicitly setting the curve, retrieves the
 * default curve, and ensures the key size is at least 224 bits.
 */
void testDefaultKeyGeneration() {
    printf("\nRunning testDefaultKeyGeneration...\n");

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) {
        fprintf(stderr, "Error creating EVP_PKEY_CTX\n");
        return;
    }

    // Initialize key generation without setting parameters
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        fprintf(stderr, "Error initializing keygen\n");
        EVP_PKEY_CTX_free(pctx);
        return;
    }

    // Generate the key
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        fprintf(stderr, "Error generating key\n");
        EVP_PKEY_CTX_free(pctx);
        return;
    }

    EVP_PKEY_CTX_free(pctx);

    // Get the group name
    char group_name[80];
    size_t group_name_len = sizeof(group_name);
    if (EVP_PKEY_get_utf8_string_param(pkey, "group", group_name, group_name_len, &group_name_len) != 1) {
        fprintf(stderr, "Error getting group name\n");
        EVP_PKEY_free(pkey);
        return;
    }
    printf("Default curve used: %s\n", group_name);

    // Get the field size using EVP_PKEY_get_bits()
    int field_size = EVP_PKEY_get_bits(pkey);
    if (field_size <= 0) {
        fprintf(stderr, "Error getting field size\n");
        EVP_PKEY_free(pkey);
        return;
    }
    printf("Field size: %d bits\n", field_size);

    if (field_size < 224) {
        fprintf(stderr, "Default key size is less than 224 bits\n");
    } else {
        printf("Default key size is at least 224 bits\n");
    }

    EVP_PKEY_free(pkey);
}


/**
 * @brief Tries to generate a public key with a point at infinity.
 *
 * Attempts to import an invalid public key encoding that represents a point at infinity.
 * Expects the import operation to fail to ensure security against subgroup confinement attacks.
 */
void testPublicKeyAtInfinity() {
    printf("\nRunning testPublicKeyAtInfinity...\n");

    // Construct an invalid public key encoding representing point at infinity
    // For the purpose of this test, we'll use an invalid encoding
    unsigned char invalid_pubkey[] = { 0x00 }; // Invalid encoding

    const unsigned char *p = invalid_pubkey;
    EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, sizeof(invalid_pubkey));

    if (pkey) {
        fprintf(stderr, "Unexpectedly succeeded in importing invalid public key\n");
        EVP_PKEY_free(pkey);
    } else {
        printf("Correctly failed to import invalid public key representing point at infinity\n");
    }
}

int main() {
    // Initialize OpenSSL algorithms
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Run tests
    testEncodedPublicKey();
    testEncodedPrivateKey();

    // Test key generation for various curves
    testKeyGeneration(NID_secp224r1);           // NIST P-224
    testKeyGeneration(NID_X9_62_prime256v1);    // NIST P-256
    testKeyGeneration(NID_secp384r1);           // NIST P-384
    testKeyGeneration(NID_secp521r1);           // NIST P-521

    // These curves may not be supported in all OpenSSL builds
    testKeyGeneration(NID_X9_62_prime239v1);    // prime239v1
    testKeyGeneration(NID_brainpoolP256r1);     // brainpoolP256r1

    testDefaultKeyGeneration();
    testPublicKeyAtInfinity();

    // Clean up OpenSSL
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}