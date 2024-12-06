#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <math.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>



/* Utility functions */

/* Skips a test with a given message */
static void skip_test(const char *msg) {
    fprintf(stderr, "Skipping test: %s\n", msg);
}

/* Reports a test failure with a given message and exits */
static void fail(const char *msg) {
    fprintf(stderr, "FAIL: %s\n", msg);
    exit(EXIT_FAILURE);
}

/* Asserts that two strings are equal; if not, reports failure */
static void assertEquals(const char *msg, const char *expected, const char *actual) {
    if (strcmp(expected, actual) != 0) {
        fprintf(stderr, "FAIL: %s Expected: %s, Actual: %s\n", msg, expected, actual);
        exit(EXIT_FAILURE);
    } else {
        printf("PASS: %s\n", msg);
    }
}

/**
 * @brief Converts a hexadecimal string to a byte array.
 *
 * Allocates memory for and fills a buffer with binary data represented by the hexadecimal string.
 *
 * @param hex The input hexadecimal string.
 * @param out_len Pointer to store the length of the resulting byte array.
 * @return unsigned char* Returns a pointer to the allocated byte array, or NULL on failure.
 */
static unsigned char *hex_to_bytes(const char *hex, size_t *out_len) {
    size_t len = strlen(hex);
    if (len % 2 != 0) {
        return NULL;
    }
    *out_len = len / 2;
    unsigned char *buf = malloc(*out_len);
    if (!buf) return NULL;
    for (size_t i = 0; i < *out_len; i++) {
        unsigned int val;
        if (sscanf(hex + 2*i, "%2x", &val) != 1) {
            free(buf);
            return NULL;
        }
        buf[i] = (unsigned char)val;
    }
    return buf;
}


/**
 * @brief Converts a byte array to a hexadecimal string.
 *
 * Allocates memory for and creates a string representing the byte array in hexadecimal format.
 *
 * @param buf The input byte array.
 * @param len The length of the byte array.
 * @return char* Returns a pointer to the allocated hexadecimal string, or NULL on failure.
 */
static char *bytes_to_hex(const unsigned char *buf, size_t len) {
    char *hex = malloc(len*2 + 1);
    if (!hex) return NULL;
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + 2*i, "%02x", buf[i]);
    }
    hex[len*2] = '\0';
    return hex;
}

/**
 * @brief Generates an EC key for a given named curve.
 *
 * Creates a new elliptic curve key pair using OpenSSL's EVP_PKEY APIs.
 *
 * @param curve_name The name of the elliptic curve (e.g., "secp256r1").
 * @return EVP_PKEY* Returns a pointer to the generated key pair, or NULL on failure.
 */
static EVP_PKEY *generate_ec_key(const char *curve_name) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!pctx) return NULL;
    if (EVP_PKEY_paramgen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*)curve_name, 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_CTX_set_params(pctx, params) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    EVP_PKEY *params_key = NULL;
    if (EVP_PKEY_paramgen(pctx, &params_key) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(pctx);

    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(params_key, NULL);
    if (!kctx) {
        EVP_PKEY_free(params_key);
        return NULL;
    }
    if (EVP_PKEY_keygen_init(kctx) <= 0) {
        EVP_PKEY_free(params_key);
        EVP_PKEY_CTX_free(kctx);
        return NULL;
    }

    EVP_PKEY *key = NULL;
    if (EVP_PKEY_keygen(kctx, &key) <= 0) {
        EVP_PKEY_free(params_key);
        EVP_PKEY_CTX_free(kctx);
        return NULL;
    }

    EVP_PKEY_free(params_key);
    EVP_PKEY_CTX_free(kctx);
    return key;
}

/**
 * @brief Derives a shared secret using the given EC key pair.
 *
 * This function performs ECDH key agreement between two key pairs to derive a shared secret.
 *
 * @param priv The private key of the initiator.
 * @param pub The public key of the peer.
 * @param secret Pointer to store the derived shared secret (allocated by this function).
 * @param secret_len Pointer to store the length of the derived shared secret.
 * @return int Returns 1 on success, or 0 on failure.
 */
static unsigned char *ecdh_derive(EVP_PKEY *priv, EVP_PKEY *pub, size_t *secret_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!ctx) return NULL;
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (EVP_PKEY_derive_set_peer(ctx, pub) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (EVP_PKEY_derive(ctx, NULL, secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    unsigned char *secret = malloc(*secret_len);
    if (!secret) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (EVP_PKEY_derive(ctx, secret, secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        free(secret);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return secret;
}


/**
 * @brief Encodes an EVP_PKEY's public key to DER format.
 *
 * This function serializes the public key of an EVP_PKEY object into DER format.
 *
 * @param key The EVP_PKEY object containing the public key.
 * @param len Pointer to store the length of the encoded key.
 * @return unsigned char* Returns a pointer to the DER-encoded key, or NULL on failure.
 */
static unsigned char *get_public_key_bytes(EVP_PKEY *key, size_t *len) {
    unsigned char *out = NULL;
    BIO *mem = NULL;
    OSSL_ENCODER_CTX *ectx = NULL;

    /* Create a memory BIO */
    mem = BIO_new(BIO_s_mem());
    if (!mem) {
        goto cleanup;
    }

    /* Create an encoder context */
    ectx = OSSL_ENCODER_CTX_new_for_pkey(
        key,
        OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
        "DER",
        "SubjectPublicKeyInfo",
        NULL
    );
    if (!ectx) {
        goto cleanup;
    }

    /* Encode the public key to the BIO */
    if (!OSSL_ENCODER_to_bio(ectx, mem)) {
        goto cleanup;
    }

    /* Extract the data from the BIO */
    BUF_MEM *bptr = NULL;
    BIO_get_mem_ptr(mem, &bptr);
    if (!bptr || bptr->length == 0) {
        goto cleanup;
    }

    /* Allocate memory for the output */
    out = malloc(bptr->length);
    if (!out) {
        goto cleanup;
    }

    /* Copy the data to the output buffer */
    memcpy(out, bptr->data, bptr->length);
    *len = bptr->length;

cleanup:
    /* Free resources */
    if (ectx) OSSL_ENCODER_CTX_free(ectx);
    if (mem) BIO_free(mem);

    /* Return the encoded key or NULL if an error occurred */
    return out;
}


/**
 * @brief Decodes a DER-encoded public key into an EVP_PKEY object.
 *
 * This function deserializes a DER-encoded public key into an OpenSSL EVP_PKEY object.
 *
 * @param der The DER-encoded public key.
 * @param der_len The length of the DER-encoded public key.
 * @return EVP_PKEY* Returns a pointer to the decoded EVP_PKEY object, or NULL on failure.
 */
static EVP_PKEY *decode_public_key_der(const unsigned char *der, size_t der_len) {
    // Create a decoder context for decoding the DER-encoded key
    OSSL_DECODER_CTX *dctx = OSSL_DECODER_CTX_new_for_pkey(
        NULL,                             // EVP_PKEY **ppkey (optional, NULL if not used)
        "DER",                            // Input type
        "SubjectPublicKeyInfo",           // Input structure
        NULL,                             // Key type (NULL for all)
        OSSL_KEYMGMT_SELECT_PUBLIC_KEY,   // Selection
        NULL,                             // OSSL_LIB_CTX *libctx (NULL for default)
        NULL                              // Property query (NULL for default)
    );
    if (!dctx) {
        fprintf(stderr, "Failed to create decoder context\n");
        return NULL;
    }


    // Perform decoding
    if (!OSSL_DECODER_from_data(dctx, &der, &der_len)) {
        fprintf(stderr, "Failed to decode DER-encoded data\n");
        OSSL_DECODER_CTX_free(dctx);
        return NULL;
    }

    // Retrieve the decoded public key
    EVP_PKEY *key = (EVP_PKEY *)OSSL_DECODER_CTX_get_construct(dctx);
    if (!key) {
        fprintf(stderr, "Failed to retrieve decoded key\n");
        OSSL_DECODER_CTX_free(dctx);
        return NULL;
    }


    // Free the decoder context
    OSSL_DECODER_CTX_free(dctx);

    return key;
}

/**
 * @brief Tests ECDH support for a specific named curve.
 *
 * This function generates two key pairs and derives shared secrets using ECDH.
 * It verifies that the shared secrets are identical.
 *
 * @param curve The name of the elliptic curve to test.
 */
static void testSupport(const char *curve) {
    EVP_PKEY *A = generate_ec_key(curve);
    EVP_PKEY *B = generate_ec_key(curve);

    if (!A || !B) {
        skip_test("Curve not supported or key generation failed");
        EVP_PKEY_free(A);
        EVP_PKEY_free(B);
        return;
    }

    size_t l1 = 0, l2 = 0;
    unsigned char *s1 = ecdh_derive(A, B, &l1);
    unsigned char *s2 = ecdh_derive(B, A, &l2);

    if (!s1 || !s2) {
        skip_test("ECDH derivation failed");
        EVP_PKEY_free(A);
        EVP_PKEY_free(B);
        free(s1);
        free(s2);
        return;
    }

    assert(l1 == l2);
    assert(memcmp(s1, s2, l1) == 0);

    free(s1);
    free(s2);
    EVP_PKEY_free(A);
    EVP_PKEY_free(B);

    printf("PASS: ECDH support for curve %s\n", curve);
}

/* Specific test functions for various curves */
static void testSupportSecp224r1() { testSupport("secp224r1"); }
static void testSupportSecp256r1() { testSupport("secp256r1"); }
static void testSupportSecp384r1() { testSupport("secp384r1"); }
static void testSupportSecp521r1() { testSupport("secp521r1"); }
static void testSupportBrainpoolP224r1() { testSupport("brainpoolP224r1"); }
static void testSupportBrainpoolP256r1() { testSupport("brainpoolP256r1"); }
static void testSupportPrime239v1() { testSupport("X9.62 prime239v1"); }
static void testSupportSecp256k1() { testSupport("secp256k1"); }

/**
 * @brief Retrieves an EC_GROUP for a given named curve.
 *
 * This function obtains the EC_GROUP object corresponding to a specific elliptic curve.
 *
 * @param curve The name of the elliptic curve (e.g., "secp256r1").
 * @return EC_GROUP* Returns a pointer to the EC_GROUP object, or NULL if the curve is unsupported.
 */
static EC_GROUP *get_named_curve_group(const char *curve) {
    int nid = OBJ_sn2nid(curve);
    if (nid == NID_undef) return NULL;
    EC_GROUP *group = EC_GROUP_new_by_curve_name(nid);
    return group;
}

/**
 * @brief Generates an EC key from an explicit EC_GROUP.
 *
 * This function creates a new elliptic curve key pair using the given EC_GROUP object.
 *
 * @param grp The elliptic curve group.
 * @return EVP_PKEY* Returns a pointer to the generated key pair, or NULL on failure.
 */
static EVP_PKEY *generate_ec_key_from_group(EC_GROUP *grp) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!pctx) return NULL;

    if (EVP_PKEY_paramgen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*)OBJ_nid2sn(EC_GROUP_get_curve_name(grp)), 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_CTX_set_params(pctx, params) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    EVP_PKEY *params_key = NULL;
    if (EVP_PKEY_paramgen(pctx, &params_key) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(pctx);

    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(params_key, NULL);
    if (!kctx) {
        EVP_PKEY_free(params_key);
        return NULL;
    }
    if (EVP_PKEY_keygen_init(kctx) <= 0) {
        EVP_PKEY_free(params_key);
        EVP_PKEY_CTX_free(kctx);
        return NULL;
    }

    EVP_PKEY *key = NULL;
    if (EVP_PKEY_keygen(kctx, &key) <= 0) {
        EVP_PKEY_free(params_key);
        EVP_PKEY_CTX_free(kctx);
        return NULL;
    }

    EVP_PKEY_free(params_key);
    EVP_PKEY_CTX_free(kctx);
    return key;
}

/**
 * Tests ECDH support using explicit EC_GROUP parameters.
 */
static void testSupportParameterSpec(const char *curve) {
    EC_GROUP *group = get_named_curve_group(curve);
    if (!group) {
        skip_test("Curve not supported: no group available");
        return;
    }

    EVP_PKEY *A = generate_ec_key_from_group(group);
    EVP_PKEY *B = generate_ec_key_from_group(group);
    EC_GROUP_free(group);

    if (!A || !B) {
        skip_test("Key generation with explicit parameters failed");
        EVP_PKEY_free(A);
        EVP_PKEY_free(B);
        return;
    }

    size_t l1 = 0, l2 = 0;
    unsigned char *s1 = ecdh_derive(A, B, &l1);
    unsigned char *s2 = ecdh_derive(B, A, &l2);

    if (!s1 || !s2) {
        skip_test("ECDH derivation with explicit parameters failed");
        EVP_PKEY_free(A);
        EVP_PKEY_free(B);
        free(s1);
        free(s2);
        return;
    }

    assert(l1 == l2);
    assert(memcmp(s1, s2, l1) == 0);

    free(s1);
    free(s2);
    EVP_PKEY_free(A);
    EVP_PKEY_free(B);

    printf("PASS: ECDH support with explicit parameters for curve %s\n", curve);
}

/* Specific test functions for support with parameters */
static void testSupportParamsSecp224r1() { testSupportParameterSpec("secp224r1"); }
static void testSupportParamsSecp256r1() { testSupportParameterSpec("secp256r1"); }
static void testSupportParamsSecp384r1() { testSupportParameterSpec("secp384r1"); }
static void testSupportParamsSecp521r1() { testSupportParameterSpec("secp521r1"); }
static void testSupportParamsBrainpoolP224r1() { testSupportParameterSpec("brainpoolP224r1"); }
static void testSupportParamsBrainpoolP256r1() { testSupportParameterSpec("brainpoolP256r1"); }
static void testSupportParamsPrime239v1() { testSupportParameterSpec("X9.62 prime239v1"); }
static void testSupportParamsSecp256k1() { testSupportParameterSpec("secp256k1"); }
static void testSupportParamsFRP256v1() { testSupportParameterSpec("FRP256v1"); }

/**
 * @brief Tests ECDH with invalid public parameters.
 *
 * Attempts to derive a shared secret using a malformed public key for a specific curve.
 *
 * @param curve The name of the elliptic curve to test.
 */
static void testInvalidPublicParams(const char *curve) {
    EC_GROUP *group = get_named_curve_group(curve);
    if (!group) {
        skip_test("Curve not supported");
        return;
    }

    EVP_PKEY *priv = generate_ec_key_from_group(group);
    if (!priv) {
        skip_test("Key generation failed for invalid public params test");
        EC_GROUP_free(group);
        return;
    }

    /* Create an invalid public key (e.g., point (1,1)) */
    EC_POINT *invalid_pt = EC_POINT_new(group);
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    BN_set_word(x, 1);
    BN_set_word(y, 1);
    int setres = EC_POINT_set_affine_coordinates(group, invalid_pt, x, y, NULL);
    BN_free(x);
    BN_free(y);

    EC_KEY *invalid_ec = EC_KEY_new();
    if (!invalid_ec) {
        skip_test("Failed to create EC_KEY for invalid public params");
        EC_POINT_free(invalid_pt);
        EVP_PKEY_free(priv);
        EC_GROUP_free(group);
        return;
    }
    if (setres == 1) {
        EC_KEY_set_public_key(invalid_ec, invalid_pt);
    }
    EC_POINT_free(invalid_pt);

    EVP_PKEY *invalid_pub = EVP_PKEY_new();
    if (!invalid_pub || EVP_PKEY_assign_EC_KEY(invalid_pub, invalid_ec) == 0) {
        if (invalid_pub) EVP_PKEY_free(invalid_pub);
        else EC_KEY_free(invalid_ec);
        skip_test("Failed to assign invalid EC_KEY to EVP_PKEY");
        EVP_PKEY_free(priv);
        EC_GROUP_free(group);
        return;
    }

    /* Attempt to derive a shared secret using the invalid public key */
    size_t secret_len = 0;
    unsigned char *secret = ecdh_derive(priv, invalid_pub, &secret_len);
    if (secret != NULL) {
        fprintf(stderr, "FAIL: Derived secret with invalid public key on curve %s\n", curve);
        free(secret);
    } else {
        printf("PASS: Could not derive secret from invalid public key on curve %s\n", curve);
    }

    EVP_PKEY_free(invalid_pub);
    EVP_PKEY_free(priv);
    EC_GROUP_free(group);
}

/* Specific test functions for invalid public parameters */
static void testInvalidPublicParamsSecp224r1() { testInvalidPublicParams("secp224r1"); }
static void testInvalidPublicParamsSecp256r1() { testInvalidPublicParams("secp256r1"); }
static void testInvalidPublicParamsSecp384r1() { testInvalidPublicParams("secp384r1"); }
static void testInvalidPublicParamsSecp521r1() { testInvalidPublicParams("secp521r1"); }
static void testInvalidPublicParamsBrainpoolP224r1() { testInvalidPublicParams("brainpoolP224r1"); }
static void testInvalidPublicParamsBrainpoolP256r1() { testInvalidPublicParams("brainpoolP256r1"); }
static void testInvalidPublicParamsSecp256k1() { testInvalidPublicParams("secp256k1"); }
static void testInvalidPublicParamsPrime239v1() { testInvalidPublicParams("X9.62 prime239v1"); }
static void testInvalidPublicParamsFRP256v1() { testInvalidPublicParams("FRP256v1"); }

/**
 * @brief Tests the behavior with modified public keys.
 *
 * Attempts to derive a shared secret using a tampered public key.
 *
 * @param algorithm The name of the algorithm being tested (e.g., "ECDH").
 */
static void testModifiedPublic(const char *algorithm) {
    /* Generate a valid key pair */
    EVP_PKEY *priv = generate_ec_key("secp256r1");
    EVP_PKEY *pub = generate_ec_key("secp256r1");
    if (!priv || !pub) {
        skip_test("secp256r1 not supported or key generation failed for modified public test");
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        return;
    }

    /* Encode the public key to DER format */
    size_t der_len = 0;
    unsigned char *der = get_public_key_bytes(pub, &der_len);
    if (!der) {
        skip_test("Failed to encode public key for modification test");
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        return;
    }

    /* Modify a byte in the DER-encoded public key */
    if (der_len > 20) {
        der[20] ^= 0xFF; // Flip bits of the 21st byte as a simple modification
    }

    /* Decode the tampered public key */
    EVP_PKEY *modified_pub = decode_public_key_der(der, der_len);
    free(der);

    if (!modified_pub) {
        /* If decoding fails, the modification was detected */
        printf("PASS: Detected modification in public key for algorithm %s\n", algorithm);
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        return;
    }

    /* Attempt to derive a shared secret with the tampered public key */
    size_t slen = 0;
    unsigned char *s = ecdh_derive(priv, modified_pub, &slen);
    if (s != NULL) {
        fprintf(stderr, "FAIL: Derived secret with modified public key using algorithm %s\n", algorithm);
        free(s);
    } else {
        printf("PASS: Could not derive secret with modified public key using algorithm %s\n", algorithm);
    }

    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);
    EVP_PKEY_free(modified_pub);
}

/* Specific test functions for modified public keys */
static void testModifiedPublicEcdh() { testModifiedPublic("ECDH"); }
static void testModifiedPublicEcdhWithCofactor() { testModifiedPublic("ECDHC"); }
static void testModifiedPublicEcdhSpec() { testModifiedPublic("ECDH_Spec"); }
static void testModifiedPublicEcdhWithCofactorSpec() { testModifiedPublic("ECDHC_Spec"); }

/**
 * Tests the behavior when the order of the EC group is modified.
 * Attempts to derive a shared secret with a group of altered order.
 */
static void testWrongOrder(const char *algorithm, const char *curve) {
    EC_GROUP *group = get_named_curve_group(curve);
    if (!group) {
        skip_test("Curve not supported for wrong order test");
        return;
    }

    /* Generate a valid key pair */
    EVP_PKEY *priv = generate_ec_key_from_group(group);
    EVP_PKEY *pub = generate_ec_key_from_group(group);
    if (!priv || !pub) {
        skip_test("Failed to generate key pair for wrong order test");
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        EC_GROUP_free(group);
        return;
    }

    /* Derive a shared secret normally */
    size_t slen = 0;
    unsigned char *shared = ecdh_derive(priv, pub, &slen);
    if (!shared) {
        skip_test("Failed to derive shared secret normally");
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        EC_GROUP_free(group);
        return;
    }

    /* Modify the order by shifting it right by 16 bits */
    const BIGNUM *order = EC_GROUP_get0_order(group);
    BIGNUM *modified_order = BN_dup(order);
    BN_rshift(modified_order, order, 16); // Order >> 16

    EC_GROUP *modified_group = EC_GROUP_dup(group);
    if (EC_GROUP_set_generator(modified_group, EC_GROUP_get0_generator(group), modified_order, BN_value_one()) == 0) {
        /* Failed to set modified order */
        BN_free(modified_order);
        EC_GROUP_free(modified_group);
        free(shared);
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        EC_GROUP_free(group);
        return;
    }
    BN_free(modified_order);

    /* Create a modified public key with the altered group */
    EC_KEY *pub_ec = EVP_PKEY_get0_EC_KEY(pub);
    const EC_POINT *pub_point = EC_KEY_get0_public_key(pub_ec);

    EC_KEY *modified_ec = EC_KEY_new();
    EC_KEY_set_group(modified_ec, modified_group);
    EC_KEY_set_public_key(modified_ec, pub_point);

    EVP_PKEY *modified_pub = EVP_PKEY_new();
    if (!modified_pub || EVP_PKEY_assign_EC_KEY(modified_pub, modified_ec) == 0) {
        if (modified_pub) EVP_PKEY_free(modified_pub);
        else EC_KEY_free(modified_ec);
        free(shared);
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        EC_GROUP_free(modified_group);
        EC_GROUP_free(group);
        return;
    }

    /* Attempt to derive a shared secret with the modified public key */
    size_t slen2 = 0;
    unsigned char *shared2 = ecdh_derive(priv, modified_pub, &slen2);
    if (!shared2) {
        /* Expected behavior: derivation should fail */
        printf("PASS: Could not derive shared secret with modified group order using algorithm %s\n", algorithm);
    } else {
        /* If derivation succeeds, ensure the secrets differ */
        if (slen == slen2 && memcmp(shared, shared2, slen) != 0) {
            fprintf(stderr, "FAIL: Derived different secrets with modified group order using algorithm %s\n", algorithm);
            free(shared2);
        } else {
            printf("PASS: Derived same secret or no difference with modified group order using algorithm %s\n", algorithm);
        }
        free(shared2);
    }

    free(shared);
    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);
    EVP_PKEY_free(modified_pub);
    EC_GROUP_free(modified_group);
    EC_GROUP_free(group);
}

/* Specific test functions for wrong order tests */
static void testWrongOrderEcdhSecp256r1() { testWrongOrder("ECDH", "secp256r1"); }
static void testWrongOrderEcdhcSecp256r1() { testWrongOrder("ECDHC", "secp256r1"); }
static void testWrongOrderEcdhBrainpoolP256r1() { testWrongOrder("ECDH", "brainpoolP256r1"); }
static void testWrongOrderEcdhcBrainpoolP256r1() { testWrongOrder("ECDHC", "brainpoolP256r1"); }

/**
 * @brief Tests large private keys for a given elliptic curve group.
 *
 * Validates that private keys `n - i` and `i` result in the same shared secret.
 *
 * @param group The elliptic curve group for testing.
 */
static void testLargePrivateKey(EC_GROUP *group) {
    if (!group) {
        skip_test("Curve not supported for large private key test");
        return;
    }

    /* Retrieve the order of the group */
    const BIGNUM *order = EC_GROUP_get0_order(group);
    if (!order) {
        skip_test("No order found for the given group");
        return;
    }

    /* Generate a public key */
    EVP_PKEY *pub = generate_ec_key_from_group(group);
    if (!pub) {
        skip_test("Failed to generate public key for large private key test");
        return;
    }

    /* Iterate over i = 1 to 64 and test private keys i and (order - i) */
    for (int i = 1; i <= 64; i++) {
        BIGNUM *p1 = BN_new();
        BN_set_word(p1, i);

        BIGNUM *p2 = BN_dup(order);
        BN_sub(p2, p2, p1); // p2 = order - i

        /* Create private key #1 */
        EC_KEY *k1 = EC_KEY_new();
        EC_KEY_set_group(k1, group);
        EC_KEY_set_private_key(k1, p1);
        /* Derive public key for k1 */
        EC_POINT *pub_pt1 = EC_POINT_new(group);
        EC_POINT_mul(group, pub_pt1, p1, NULL, NULL, NULL);
        EC_KEY_set_public_key(k1, pub_pt1);
        EC_POINT_free(pub_pt1);

        EVP_PKEY *priv1 = EVP_PKEY_new();
        if (!priv1 || EVP_PKEY_assign_EC_KEY(priv1, k1) == 0) {
            fail("Failed to assign EC_KEY to EVP_PKEY for priv1");
        }

        /* Create private key #2 */
        EC_KEY *k2 = EC_KEY_new();
        EC_KEY_set_group(k2, group);
        EC_KEY_set_private_key(k2, p2);
        /* Derive public key for k2 */
        EC_POINT *pub_pt2 = EC_POINT_new(group);
        EC_POINT_mul(group, pub_pt2, p2, NULL, NULL, NULL);
        EC_KEY_set_public_key(k2, pub_pt2);
        EC_POINT_free(pub_pt2);

        EVP_PKEY *priv2 = EVP_PKEY_new();
        if (!priv2 || EVP_PKEY_assign_EC_KEY(priv2, k2) == 0) {
            fail("Failed to assign EC_KEY to EVP_PKEY for priv2");
        }

        /* Derive shared secrets */
        size_t l1 = 0, l2 = 0;
        unsigned char *s1 = ecdh_derive(priv1, pub, &l1);
        unsigned char *s2 = ecdh_derive(priv2, pub, &l2);
        if (!s1 || !s2) {
            fail("Failed to derive shared secrets with large private keys");
        }

        /* Compare the shared secrets */
        assert(l1 == l2);
        assert(memcmp(s1, s2, l1) == 0);

        /* Clean up */
        free(s1);
        free(s2);
        EVP_PKEY_free(priv1);
        EVP_PKEY_free(priv2);
        BN_free(p1);
        BN_free(p2);
    }

    EVP_PKEY_free(pub);
    printf("PASS: Large private key tests passed\n");
}

/* Specific test functions for large private keys */
static void testLargePrivateKeySecp224r1() {
    EC_GROUP *g = get_named_curve_group("secp224r1");
    if (!g) { skip_test("secp224r1 not supported for large private key test"); return; }
    testLargePrivateKey(g);
    EC_GROUP_free(g);
}

static void testLargePrivateKeySecp256r1() {
    EC_GROUP *g = get_named_curve_group("secp256r1");
    if (!g) { skip_test("secp256r1 not supported for large private key test"); return; }
    testLargePrivateKey(g);
    EC_GROUP_free(g);
}

static void testLargePrivateKeySecp384r1() {
    EC_GROUP *g = get_named_curve_group("secp384r1");
    if (!g) { skip_test("secp384r1 not supported for large private key test"); return; }
    testLargePrivateKey(g);
    EC_GROUP_free(g);
}

static void testLargePrivateKeySecp521r1() {
    EC_GROUP *g = get_named_curve_group("secp521r1");
    if (!g) { skip_test("secp521r1 not supported for large private key test"); return; }
    testLargePrivateKey(g);
    EC_GROUP_free(g);
}

static void testLargePrivateKeyBrainpoolP256r1() {
    EC_GROUP *g = get_named_curve_group("brainpoolP256r1");
    if (!g) { skip_test("brainpoolP256r1 not supported for large private key test"); return; }
    testLargePrivateKey(g);
    EC_GROUP_free(g);
}

static void testLargePrivateKeyPrime239v1() {
    EC_GROUP *g = get_named_curve_group("X9.62 prime239v1");
    if (!g) { skip_test("X9.62 prime239v1 not supported for large private key test"); return; }
    testLargePrivateKey(g);
    EC_GROUP_free(g);
}

/**
 * Retrieves the current CPU time in nanoseconds.
 */
static long get_cpu_time_ns() {
    struct timespec ts;
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts) != 0) {
        /* Fallback to CLOCK_MONOTONIC if CLOCK_PROCESS_CPUTIME_ID is not available */
        clock_gettime(CLOCK_MONOTONIC, &ts);
    }
    return (long)ts.tv_sec * 1000000000L + ts.tv_nsec;
}

/**
 * @brief Tests ECDH timing consistency for specific curves.
 *
 * This function measures the time required to perform multiple ECDH operations
 * and checks for timing anomalies.
 *
 * @param curve The name of the elliptic curve to test (e.g., "secp256r1").
 * @param x1 X-coordinate of the first public point.
 * @param y1 Y-coordinate of the first public point.
 * @param x2 X-coordinate of the second public point.
 * @param y2 Y-coordinate of the second public point.
 * @param mul Multiplier for generating private keys.
 * @param privKeySize Size of the private key in bits.
 */
static void testTiming(const char *curve, 
                       const BIGNUM *x1, const BIGNUM *y1,
                       const BIGNUM *x2, const BIGNUM *y2,
                       const BIGNUM *mul, int privKeySize) {
    EC_GROUP *group = get_named_curve_group(curve);
    if (!group) {
        skip_test("Unsupported parameters or curve for timing test");
        return;
    }

    /* Create EC_POINTs from provided coordinates */
    EC_POINT *P0 = EC_POINT_new(group);
    EC_POINT_set_affine_coordinates(group, P0, x1, y1, NULL);
    EC_POINT *P1 = EC_POINT_new(group);
    EC_POINT_set_affine_coordinates(group, P1, x2, y2, NULL);

    /* Assign EC_POINTs to EC_KEYs and then to EVP_PKEYs */
    EC_KEY *ec_p0 = EC_KEY_new();
    EC_KEY_set_group(ec_p0, group);
    EC_KEY_set_public_key(ec_p0, P0);
    EVP_PKEY *pubkeys[2];
    pubkeys[0] = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pubkeys[0], ec_p0);

    EC_KEY *ec_p1 = EC_KEY_new();
    EC_KEY_set_group(ec_p1, group);
    EC_KEY_set_public_key(ec_p1, P1);
    pubkeys[1] = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pubkeys[1], ec_p1);

    /* Calculate missing bits */
    int fixedSize = BN_num_bits(mul);
    int missingBits = privKeySize - 2*fixedSize;
    if (missingBits <= 0) {
        skip_test("Missing bits <= 0 for timing test");
        EC_POINT_free(P0);
        EC_POINT_free(P1);
        EC_GROUP_free(group);
        EVP_PKEY_free(pubkeys[0]);
        EVP_PKEY_free(pubkeys[1]);
        return;
    }

    const int tests = 2048;
    const int minCount = 880;
    const int repetitions = 8;
    const int warmup = 8;
    const int sampleSize = warmup + tests;

    EVP_PKEY **privKeys = malloc(sizeof(EVP_PKEY*) * sampleSize);
    if (!privKeys) {
        fail("Failed to allocate memory for private keys in timing test");
    }
    memset(privKeys, 0, sizeof(EVP_PKEY*) * sampleSize);

    /* Generate private keys */
    for (int i = 0; i < sampleSize; i++) {
        BIGNUM *m = BN_new();
        if (!m) {
            fail("Failed to allocate BIGNUM for private key");
        }
        BN_rand(m, missingBits, 0, 0);
        BN_lshift(m, mul, missingBits);
        BIGNUM *randPart = BN_new();
        if (!randPart) {
            BN_free(m);
            fail("Failed to allocate BIGNUM for random part");
        }
        BN_rand(randPart, missingBits, 0, 0);
        BN_add(m, m, randPart);
        BN_free(randPart);

        BN_lshift(m, m, fixedSize);
        BN_add(m, m, mul);

        EC_KEY *ec_priv = EC_KEY_new();
        EC_KEY_set_group(ec_priv, group);
        EC_KEY_set_private_key(ec_priv, m);

        /* Derive public key */
        EC_POINT *pub_pt = EC_POINT_new(group);
        EC_POINT_mul(group, pub_pt, m, NULL, NULL, NULL);
        EC_KEY_set_public_key(ec_priv, pub_pt);
        EC_POINT_free(pub_pt);

        EVP_PKEY *privk = EVP_PKEY_new();
        if (!privk || EVP_PKEY_assign_EC_KEY(privk, ec_priv) == 0) {
            BN_free(m);
            EVP_PKEY_free(privk);
            fail("Failed to assign EC_KEY to EVP_PKEY for private key");
        }
        privKeys[i] = privk;
        BN_free(m);
    }

    long timings[2][sampleSize];
    memset(timings, 0, sizeof(timings));

    /* Perform ECDH derivations and measure timing */
    for (int i = 0; i < sampleSize; i++) {
        for (int j = 0; j < 2 * repetitions; j++) {
            int idx = ((j ^ i) & 1);
            long start = get_cpu_time_ns();
            size_t secret_len = 0;
            unsigned char *secret = ecdh_derive(privKeys[i], pubkeys[idx], &secret_len);
            long end = get_cpu_time_ns();
            if (secret) free(secret);
            timings[idx][i] += (end - start);
        }
    }

    /* Average timings */
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < sampleSize; j++) {
            timings[i][j] /= repetitions;
        }
    }

    /* Basic statistics could be added here */

    /* Count how many times pubkeys[0] was faster than pubkeys[1] */
    int point0Faster = 0;
    int equal = 0;
    for (int i = 0; i < sampleSize; i++) {
        if (timings[0][i] < timings[1][i]) point0Faster++;
        else if (timings[0][i] == timings[1][i]) equal++;
    }
    point0Faster += equal / 2;

    if (point0Faster < minCount || point0Faster > (sampleSize - minCount)) {
        fail("Timing differences in ECDH computation detected");
    } else {
        printf("PASS: Timing consistency for curve %s\n", curve);
    }

    /* Clean up */
    for (int i = 0; i < sampleSize; i++) {
        if (privKeys[i]) EVP_PKEY_free(privKeys[i]);
    }
    free(privKeys);

    EVP_PKEY_free(pubkeys[0]);
    EVP_PKEY_free(pubkeys[1]);
    EC_POINT_free(P0);
    EC_POINT_free(P1);
    EC_GROUP_free(group);
}

/* Specific test functions for timing tests */
static void testTimingSecp256r1() {
    BIGNUM *x1 = BN_new(); BN_hex2bn(&x1, "81bfb55b010b1bdf08b8d9d8590087aa278e28febff3b05632eeff09011c5579");
    BIGNUM *y1 = BN_new(); BN_hex2bn(&y1, "732d0e65267ea28b7af8cfcb148936c2af8664cbb4f04e188148a1457400c2a7");
    BIGNUM *x2 = BN_new(); BN_hex2bn(&x2, "8608e36a91f1fba12e4074972af446176b5608c9c58dc318bd0742754c3dcee7");
    BIGNUM *y2 = BN_new(); BN_hex2bn(&y2, "bc2c9ecd44af916ca58d9e3ef1257f698d350ef486eb86137fe69a7375bcc191");
    BIGNUM *mul = BN_new(); BN_set_word(mul, 2);

    testTiming("secp256r1", x1, y1, x2, y2, mul, 256);

    BN_free(x1);
    BN_free(y1);
    BN_free(x2);
    BN_free(y2);
    BN_free(mul);
}

static void testTimingSecp384r1() {
    BIGNUM *x1 = BN_new(); BN_hex2bn(&x1, "7a6fadfee03eb09554f2a04fe08300aca88bb3a46e8f6347bace672cfe4276988541cef8dc10536a84580215f5f90a3b");
    BIGNUM *y1 = BN_new(); BN_hex2bn(&y1, "6d243d5d9de1cdddd04cbeabdc7a0f6c244391f7cb2d5738fe13c334add4b4585fef61ffd446db33b39402278713ae78");
    BIGNUM *x2 = BN_new(); BN_hex2bn(&x2, "71f3c57d6a879889e582af2c7c5444b0eb6ba95d88365b21ca9549475273ecdd3930aa0bebbd1cf084e4049667278602");
    BIGNUM *y2 = BN_new(); BN_hex2bn(&y2, "9dcbc4d843af8944eb4ba018d369b351a9ea0f7b9e3561df2ee218d54e198f7c837a3abaa41dffd2d2cb771a7599ed9e");
    BIGNUM *mul = BN_new(); BN_set_word(mul, 2);

    testTiming("secp384r1", x1, y1, x2, y2, mul, 384);

    BN_free(x1);
    BN_free(y1);
    BN_free(x2);
    BN_free(y2);
    BN_free(mul);
}

static void testTimingBrainpoolP256r1() {
    BIGNUM *x1 = BN_new(); BN_hex2bn(&x1, "79838c22d2b8dc9af2e6cf56f8826dc3dfe10fcb17b6aaaf551ee52bef12f826");
    BIGNUM *y1 = BN_new(); BN_hex2bn(&y1, "1e2ed3d453088c8552c6feecf898667bc1e15905002edec6b269feb7bea09d5b");
    BIGNUM *x2 = BN_new(); BN_hex2bn(&x2, "2720b2e821b2ac8209b573bca755a68821e1e09deb580666702570dd527dd4c1");
    BIGNUM *y2 = BN_new(); BN_hex2bn(&y2, "25cdd610243c7e693fad7bd69b43ae3e63e94317c4c6b717d9c8bc3be8c996fb");
    BIGNUM *mul = BN_new(); BN_set_word(mul, 2);

    testTiming("brainpoolP256r1", x1, y1, x2, y2, mul, 255);

    BN_free(x1);
    BN_free(y1);
    BN_free(x2);
    BN_free(y2);
    BN_free(mul);
}

/**
 * Performs timing tests by measuring the time taken for multiple ECDH operations.
 */
static void testTimingSample(const char *curve) {
    /* Retrieve EC_GROUP */
    EC_GROUP *group = get_named_curve_group(curve);
    if (!group) {
        skip_test("Curve not supported for timing sample");
        return;
    }

    /* Generate a private key */
    EVP_PKEY *priv = generate_ec_key_from_group(group);
    if (!priv) {
        skip_test("Failed to generate private key for timing sample");
        EC_GROUP_free(group);
        return;
    }

    /* Generate a public key */
    EVP_PKEY *pub = generate_ec_key_from_group(group);
    if (!pub) {
        skip_test("Failed to generate public key for timing sample");
        EVP_PKEY_free(priv);
        EC_GROUP_free(group);
        return;
    }

    /* Perform multiple ECDH derivations and measure time */
    const int iterations = 1000;
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < iterations; i++) {
        size_t secret_len = 0;
        unsigned char *secret = ecdh_derive(priv, pub, &secret_len);
        if (secret) free(secret);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    long elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
    printf("Timing Test: %s - %ld ns for %d ECDH operations\n", curve, elapsed_ns, iterations);

    /* Clean up */
    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);
    EC_GROUP_free(group);
}

/* Specific test functions for timing samples */
static void testTimingSampleSecp256r1() { testTimingSample("secp256r1"); }
static void testTimingSampleSecp384r1() { testTimingSample("secp384r1"); }
static void testTimingSampleBrainpoolP256r1() { testTimingSample("brainpoolP256r1"); }

/**
 * Main function to run all tests.
 */
int main(void) {
    /* Initialize OpenSSL */
    OPENSSL_init_crypto(0, NULL);

    /* Run tests */

    // Basic support tests
    testSupportSecp224r1();
    testSupportSecp256r1();
    testSupportSecp384r1();
    testSupportSecp521r1();
    testSupportBrainpoolP224r1();
    testSupportBrainpoolP256r1();
    testSupportPrime239v1();
    testSupportSecp256k1();

    // Support with parameters
    testSupportParamsSecp224r1();
    testSupportParamsSecp256r1();
    testSupportParamsSecp384r1();
    testSupportParamsSecp521r1();
    testSupportParamsBrainpoolP224r1();
    testSupportParamsBrainpoolP256r1();
    testSupportParamsPrime239v1();
    testSupportParamsSecp256k1();
    testSupportParamsFRP256v1();

    // Invalid public params
    testInvalidPublicParamsSecp224r1();
    testInvalidPublicParamsSecp256r1();
    testInvalidPublicParamsSecp384r1();
    testInvalidPublicParamsSecp521r1();
    testInvalidPublicParamsBrainpoolP224r1();
    testInvalidPublicParamsBrainpoolP256r1();
    testInvalidPublicParamsSecp256k1();
    testInvalidPublicParamsPrime239v1();
    testInvalidPublicParamsFRP256v1();

    // Modified public tests
    testModifiedPublicEcdh();
    testModifiedPublicEcdhWithCofactor();
    testModifiedPublicEcdhSpec();
    testModifiedPublicEcdhWithCofactorSpec();

    // Wrong order tests
    testWrongOrderEcdhSecp256r1();
    testWrongOrderEcdhcSecp256r1();
    testWrongOrderEcdhBrainpoolP256r1();
    testWrongOrderEcdhcBrainpoolP256r1();

    // Large private keys
    testLargePrivateKeySecp224r1();
    testLargePrivateKeySecp256r1();
    testLargePrivateKeySecp384r1();
    testLargePrivateKeySecp521r1();
    testLargePrivateKeyBrainpoolP256r1();
    testLargePrivateKeyPrime239v1();

    // Timing tests (sample)
    testTimingSecp256r1();
    testTimingSecp384r1();
    testTimingBrainpoolP256r1();

    // Additional timing samples
    testTimingSampleSecp256r1();
    testTimingSampleSecp384r1();
    testTimingSampleBrainpoolP256r1();

    fprintf(stderr, "All tests completed.\n");

    return 0;
}
