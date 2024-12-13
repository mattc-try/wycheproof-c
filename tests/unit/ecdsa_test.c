#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <time.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/evp.h> // Added to ensure EVP_sha* functions are declared
#include <sys/time.h>
#include <unistd.h>

/**
 * @brief Macro for asserting a condition with an error message.
 *
 * If the provided condition is not met, the program prints the provided
 * message and exits with a failure status.
 *
 * @param condition A boolean expression representing the condition to check.
 * @param message A string message printed if the assertion fails.
 */
#define ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "Assertion failed: %s\n", message); \
            exit(EXIT_FAILURE); \
        } \
    } while (0)

/**
 * @brief Prints the OpenSSL error queue and exits with failure.
 *
 * This function retrieves and prints all error messages from the OpenSSL
 * error queue and then terminates the program execution.
 *
 * @param msg A message indicating the context or reason for the error.
 */
void handle_openssl_error(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

/**
 * @brief Retrieves the NID (numeric identifier) for the specified curve name.
 *
 * Given a string representing the name of an elliptic curve (e.g., "secp256r1"),
 * this function returns the corresponding OpenSSL NID. If the curve is unsupported,
 * it returns 0.
 *
 * @param curve_name A string specifying the curve name.
 * @return The NID corresponding to the given curve name, or 0 if unsupported.
 */
int get_curve_nid(const char *curve_name) {
    if (strcmp(curve_name, "secp256r1") == 0) {
        return NID_X9_62_prime256v1;
    } else if (strcmp(curve_name, "secp256k1") == 0) {
        return NID_secp256k1;
    } else if (strcmp(curve_name, "secp224r1") == 0) {
        return NID_secp224r1;
    } else if (strcmp(curve_name, "X9.62 prime239v1") == 0) {
        return NID_X9_62_prime239v1;
    } else if (strcmp(curve_name, "brainpoolP256r1") == 0) {
        return NID_brainpoolP256r1;
    } else if (strcmp(curve_name, "brainpoolP320r1") == 0) {
        return NID_brainpoolP320r1;
    } else if (strcmp(curve_name, "secp384r1") == 0) {
        return NID_secp384r1;
    } else if (strcmp(curve_name, "secp521r1") == 0) {
        return NID_secp521r1;
    } else if (strcmp(curve_name, "FRP256v1") == 0) {
        /* OpenSSL does not have a predefined NID for FRP256v1 */
        return 0;
    } else {
        return 0;
    }
}

/**
 * @brief Retrieves the appropriate hash algorithm (EVP_MD) for a given ECDSA algorithm name.
 *
 * Maps an ECDSA algorithm name such as "SHA256WithECDSA" to the corresponding
 * OpenSSL digest function (e.g., EVP_sha256()).
 *
 * @param ecdsa_algorithm A string representing the ECDSA algorithm (e.g., "SHA256WithECDSA").
 * @return A pointer to the EVP_MD structure for the hash algorithm, or NULL if unsupported.
 */
const EVP_MD* get_hash_algorithm(const char *ecdsa_algorithm) {
    if (strcmp(ecdsa_algorithm, "SHA256WithECDSA") == 0 ||
        strcmp(ecdsa_algorithm, "SHA256WithECDDSA") == 0) {
        return EVP_sha256();
    } else if (strcmp(ecdsa_algorithm, "SHA224WithECDSA") == 0) {
        return EVP_sha224();
    } else if (strcmp(ecdsa_algorithm, "SHA384WithECDSA") == 0) {
        return EVP_sha384();
    } else if (strcmp(ecdsa_algorithm, "SHA512WithECDSA") == 0) {
        return EVP_sha512();
    } else {
        return NULL;
    }
}

/**
 * @brief Generates an EC key pair for the specified curve.
 *
 * Creates and generates a new EC key pair using the named elliptic curve.
 * If the curve is unsupported or key generation fails, it returns NULL.
 *
 * @param curve_name The name of the elliptic curve (e.g., "secp256r1").
 * @return A pointer to the newly generated EC_KEY structure, or NULL on failure.
 */
EC_KEY* generate_ec_key(const char *curve_name) {
    int nid = get_curve_nid(curve_name);
    if (nid == 0) {
        fprintf(stderr, "Unsupported curve: %s\n", curve_name);
        return NULL;
    }

    EC_KEY *eckey = EC_KEY_new_by_curve_name(nid);
    if (eckey == NULL) {
        fprintf(stderr, "Failed to create EC_KEY for curve: %s\n", curve_name);
        return NULL;
    }

    if (EC_KEY_generate_key(eckey) != 1) {
        EC_KEY_free(eckey);
        fprintf(stderr, "Failed to generate EC key for curve: %s\n", curve_name);
        return NULL;
    }

    return eckey;
}

/**
 * @brief Extracts the 'r' component from an ECDSA signature.
 *
 * Given a DER-encoded ECDSA signature, this function decodes it and returns
 * a copy of the 'r' value as a BIGNUM.
 *
 * @param sig A pointer to the signature bytes.
 * @param sig_len The length of the signature in bytes.
 * @return A new BIGNUM containing the 'r' value, or NULL on failure.
 */
BIGNUM* extract_r(const unsigned char *sig, size_t sig_len) {
    const unsigned char *p = sig;
    ECDSA_SIG *ecdsa_sig = d2i_ECDSA_SIG(NULL, &p, sig_len);
    if (ecdsa_sig == NULL) {
        handle_openssl_error("Failed to decode ECDSA signature");
    }
    const BIGNUM *r = NULL;
    ECDSA_SIG_get0(ecdsa_sig, &r, NULL);
    BIGNUM *r_copy = BN_dup(r);
    ECDSA_SIG_free(ecdsa_sig);
    return r_copy;
}

/**
 * @brief Extracts the 's' component from an ECDSA signature.
 *
 * Given a DER-encoded ECDSA signature, this function decodes it and returns
 * a copy of the 's' value as a BIGNUM.
 *
 * @param sig A pointer to the signature bytes.
 * @param sig_len The length of the signature in bytes.
 * @return A new BIGNUM containing the 's' value, or NULL on failure.
 */
BIGNUM* extract_s(const unsigned char *sig, size_t sig_len) {
    const unsigned char *p = sig;
    ECDSA_SIG *ecdsa_sig = d2i_ECDSA_SIG(NULL, &p, sig_len);
    if (ecdsa_sig == NULL) {
        handle_openssl_error("Failed to decode ECDSA signature");
    }
    const BIGNUM *s = NULL;
    ECDSA_SIG_get0(ecdsa_sig, NULL, &s);
    BIGNUM *s_copy = BN_dup(s);
    ECDSA_SIG_free(ecdsa_sig);
    return s_copy;
}

/**
 * @brief Extracts the ephemeral value 'k' used in ECDSA signing.
 *
 * Uses ECDSA_sign_setup to precompute the ephemeral key 'k' and 'r'. Only 'k' is returned.
 *
 * @param eckey A pointer to a valid EC_KEY structure.
 * @param msg A pointer to the message to be signed.
 * @param msg_len The length of the message in bytes.
 * @param k_out A pointer to a BIGNUM* that will hold the extracted 'k'.
 * @return 1 on success, otherwise the function terminates via handle_openssl_error.
 */
int extract_k(EC_KEY *eckey, const unsigned char *msg, size_t msg_len, BIGNUM **k_out) {
    BIGNUM *k = BN_new();
    BIGNUM *r = BN_new();
    if (k == NULL || r == NULL) {
        handle_openssl_error("Failed to allocate BIGNUMs");
    }

    int ret = ECDSA_sign_setup(eckey, NULL, &k, &r);
    if (ret != 1) {
        BN_free(k);
        BN_free(r);
        handle_openssl_error("ECDSA_sign_setup failed");
    }

    *k_out = k;
    BN_free(r);
    return 1;
}

/**
 * @brief Generates a set of messages to sign, either deterministic or constant.
 *
 * If deterministic is true, it creates a set of unique 4-byte messages derived from the index.
 * Otherwise, it returns multiple references to a single constant message.
 *
 * @param count The number of messages to generate.
 * @param deterministic A boolean indicating whether messages are deterministic (unique) or constant.
 * @return An array of pointers to the generated messages.
 */
unsigned char** get_messages_to_sign(int count, int deterministic) {
    unsigned char **messages = malloc(count * sizeof(unsigned char*));
    if (messages == NULL) {
        fprintf(stderr, "Memory allocation failed for messages\n");
        exit(EXIT_FAILURE);
    }

    if (deterministic) {
        for (int i = 0; i < count; i++) {
            messages[i] = malloc(4);
            if (messages[i] == NULL) {
                fprintf(stderr, "Memory allocation failed for message %d\n", i);
                exit(EXIT_FAILURE);
            }
            messages[i][0] = (i >> 24) & 0xFF;
            messages[i][1] = (i >> 16) & 0xFF;
            messages[i][2] = (i >> 8) & 0xFF;
            messages[i][3] = i & 0xFF;
        }
    } else {
        unsigned char *msg = calloc(4, sizeof(unsigned char));
        if (msg == NULL) {
            fprintf(stderr, "Memory allocation failed for constant message\n");
            exit(EXIT_FAILURE);
        }
        for (int i = 0; i < count; i++) {
            messages[i] = msg;
        }
    }

    return messages;
}

/**
 * @brief Frees an array of messages allocated by get_messages_to_sign.
 *
 * If deterministic is true, it frees each message individually. Otherwise,
 * it frees the single shared message once.
 *
 * @param messages An array of message pointers.
 * @param count The number of messages.
 * @param deterministic Indicates whether each message is unique or shared.
 */
void free_messages(unsigned char **messages, int count, int deterministic) {
    if (deterministic) {
        for (int i = 0; i < count; i++) {
            free(messages[i]);
        }
    } else {
        free(messages[0]);
    }
    free(messages);
}

/**
 * @brief Checks if ECDSA signatures are deterministic for a given key and message.
 *
 * Signs the same message twice and checks if the resulting signatures are identical.
 * If they are, it indicates deterministic behavior.
 *
 * @param eckey A pointer to a valid EC_KEY.
 * @param msg The message to sign.
 * @param msg_len The length of the message in bytes.
 * @param md The hashing algorithm to use for signing.
 * @return 1 if signatures are deterministic, 0 otherwise.
 */
int is_deterministic_test(EC_KEY *eckey, const unsigned char *msg, size_t msg_len, const EVP_MD *md) {
    unsigned char *sig1 = NULL, *sig2 = NULL;
    unsigned int sig1_len, sig2_len;
    size_t len1, len2;

    /* First signature */
    sig1 = malloc(ECDSA_size(eckey));
    if (sig1 == NULL) {
        fprintf(stderr, "Memory allocation failed for sig1\n");
        exit(EXIT_FAILURE);
    }
    len1 = ECDSA_sign(0, msg, msg_len, sig1, &sig1_len, eckey);
    if (len1 == 0) {
        handle_openssl_error("ECDSA_sign failed for sig1");
    }

    /* Second signature */
    sig2 = malloc(ECDSA_size(eckey));
    if (sig2 == NULL) {
        fprintf(stderr, "Memory allocation failed for sig2\n");
        exit(EXIT_FAILURE);
    }
    len2 = ECDSA_sign(0, msg, msg_len, sig2, &sig2_len, eckey);
    if (len2 == 0) {
        handle_openssl_error("ECDSA_sign failed for sig2");
    }

    int deterministic = 0;
    if (len1 == len2 && memcmp(sig1, sig2, len1) == 0) {
        deterministic = 1;
    }

    free(sig1);
    free(sig2);
    return deterministic;
}

/**
 * @brief Computes a bias value based on a set of sampled BIGNUM values.
 *
 * This function imitates a bias computation as defined in the reference code.
 * It multiplies each sample by 'm' modulo 'modulus' and then takes a complex sum
 * of sines and cosines to produce a measure of bias.
 *
 * @param samples An array of BIGNUM pointers representing sampled values.
 * @param sample_count The number of samples.
 * @param modulus The modulus used in the computation.
 * @param m A BIGNUM multiplier.
 * @return A double representing the computed bias value.
 */
double compute_bias(const BIGNUM **samples, int sample_count, const BIGNUM *modulus, const BIGNUM *m) {
    double sum_real = 0.0;
    double sum_imag = 0.0;
    BN_CTX *ctx = BN_CTX_new();
    if (ctx == NULL) {
        handle_openssl_error("BN_CTX_new failed");
    }

    for (int i = 0; i < sample_count; i++) {
        BIGNUM *tmp = BN_new();
        if (tmp == NULL) {
            handle_openssl_error("BN_new failed");
        }
        BN_mod_mul(tmp, samples[i], m, modulus, ctx); // tmp = s * m mod modulus

        double multiplier = 1.3951473992034527e-15; // 2 * pi / 2^52
        double quotient = BN_get_word(tmp) * multiplier; // Simplification

        sum_real += cos(quotient);
        sum_imag += sin(quotient);
        BN_free(tmp);
    }

    BN_CTX_free(ctx);
    return sqrt((sum_real * sum_real + sum_imag * sum_imag) / sample_count);
}

/**
 * @brief Performs a basic ECDSA sign and verify test.
 *
 * Generates a key pair for the given curve, signs a fixed message, and verifies the signature.
 * If the verification succeeds, the test passes.
 *
 * @param algorithm The ECDSA algorithm name (e.g., "SHA256WithECDSA").
 * @param curve The curve name (e.g., "secp256r1").
 */
void test_basic(const char *algorithm, const char *curve) {
    printf("Running test_basic with algorithm: %s and curve: %s\n", algorithm, curve);

    EC_KEY *eckey = generate_ec_key(curve);
    if (eckey == NULL) {
        printf("Skipping test_basic: Could not generate EC key pair for curve %s\n", curve);
        return;
    }

    const char *message = "123400";
    unsigned char msg_bytes[6];
    memcpy(msg_bytes, message, 6);

    unsigned char *signature = malloc(ECDSA_size(eckey));
    if (signature == NULL) {
        fprintf(stderr, "Memory allocation failed for signature\n");
        exit(EXIT_FAILURE);
    }
    unsigned int sig_len;
    if (ECDSA_sign(0, msg_bytes, strlen(message), signature, &sig_len, eckey) != 1) {
        handle_openssl_error("ECDSA_sign failed in test_basic");
    }

    int verify = ECDSA_verify(0, msg_bytes, strlen(message), signature, sig_len, eckey);
    ASSERT(verify == 1, "ECDSA_verify failed in test_basic");

    printf("test_basic passed for curve %s\n", curve);
    free(signature);
    EC_KEY_free(eckey);
}

/**
 * @brief Tests ECDSA with constructed parameters.
 *
 * Similar to test_basic, but intended to ensure that ECDSA works correctly with various curves
 * and algorithm configurations. Signs and verifies a message on the specified curve.
 *
 * @param algorithm The ECDSA algorithm name (e.g., "SHA256WithECDSA").
 * @param curve The curve name to test.
 */
void test_ecdsa_constructed(const char *algorithm, const char *curve) {
    printf("Running test_ecdsa_constructed with algorithm: %s and curve: %s\n", algorithm, curve);

    EC_KEY *eckey = generate_ec_key(curve);
    if (eckey == NULL) {
        printf("Skipping test_ecdsa_constructed: Could not generate EC key pair for curve %s\n", curve);
        return;
    }

    const char *message = "123400";
    unsigned char msg_bytes[6];
    memcpy(msg_bytes, message, 6);

    unsigned char *signature = malloc(ECDSA_size(eckey));
    if (signature == NULL) {
        fprintf(stderr, "Memory allocation failed for signature\n");
        exit(EXIT_FAILURE);
    }
    unsigned int sig_len;
    if (ECDSA_sign(0, msg_bytes, strlen(message), signature, &sig_len, eckey) != 1) {
        handle_openssl_error("ECDSA_sign failed in test_ecdsa_constructed");
    }

    int verify = ECDSA_verify(0, msg_bytes, strlen(message), signature, sig_len, eckey);
    ASSERT(verify == 1, "ECDSA_verify failed in test_ecdsa_constructed");

    printf("test_ecdsa_constructed passed for curve %s\n", curve);
    free(signature);
    EC_KEY_free(eckey);
}

/**
 * @brief Tests for bias in the generation of ephemeral keys (k) for ECDSA.
 *
 * Generates multiple signatures, extracts the ephemeral keys, and checks that the
 * distribution of the least and most significant bits of k is uniform enough to
 * avoid bias.
 *
 * @param algorithm The ECDSA algorithm name.
 * @param curve The curve name.
 */
void test_bias(const char *algorithm, const char *curve) {
    printf("Running test_bias with algorithm: %s and curve: %s\n", algorithm, curve);

    const EVP_MD *md = get_hash_algorithm(algorithm);
    if (md == NULL) {
        printf("Skipping test_bias: Unsupported algorithm %s\n", algorithm);
        return;
    }

    EC_KEY *eckey = generate_ec_key(curve);
    if (eckey == NULL) {
        printf("Skipping test_bias: Could not generate EC key pair for curve %s\n", curve);
        return;
    }

    int deterministic = 1; // Assuming deterministic signatures by default
    const int tests = 2048;
    const int mincount = 880;
    unsigned char **messages = get_messages_to_sign(tests, deterministic);

    BIGNUM **k_list = malloc(tests * sizeof(BIGNUM*));
    if (k_list == NULL) {
        fprintf(stderr, "Memory allocation failed for k_list\n");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < tests; i++) {
        unsigned char *sig = malloc(ECDSA_size(eckey));
        if (sig == NULL) {
            fprintf(stderr, "Memory allocation failed for signature in test_bias\n");
            exit(EXIT_FAILURE);
        }
        unsigned int sig_len;

        BIGNUM *k = NULL;
        BIGNUM *r = NULL;
        if (ECDSA_sign_setup(eckey, NULL, &k, &r) != 1) {
            handle_openssl_error("ECDSA_sign_setup failed in test_bias");
        }

        if (ECDSA_sign(0, messages[i], (int)strlen((char*)messages[i]), sig, &sig_len, eckey) != 1) {
            handle_openssl_error("ECDSA_sign failed in test_bias");
        }

        k_list[i] = BN_dup(k);
        if (k_list[i] == NULL) {
            handle_openssl_error("BN_dup failed for k in test_bias");
        }

        BN_free(k);
        BN_free(r);
        free(sig);
    }

    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    BIGNUM *order = BN_new();
    if (order == NULL) {
        handle_openssl_error("BN_new failed for order in test_bias");
    }
    if (EC_GROUP_get_order(group, order, NULL) != 1) {
        handle_openssl_error("EC_GROUP_get_order failed in test_bias");
    }

    BIGNUM *half_order = BN_new();
    if (half_order == NULL) {
        handle_openssl_error("BN_new failed for half_order in test_bias");
    }
    BN_rshift1(half_order, order);

    int count_lsb = 0;
    int count_msb = 0;
    for (int i = 0; i < tests; i++) {
        if (BN_is_bit_set(k_list[i], 0)) {
            count_lsb++;
        }
        if (BN_cmp(k_list[i], half_order) > 0) {
            count_msb++;
        }
    }

    ASSERT(count_lsb >= mincount && count_lsb <= (tests - mincount), "Bias detected in LSB of k");
    ASSERT(count_msb >= mincount && count_msb <= (tests - mincount), "Bias detected in MSB of k");

    for (int i = 0; i < tests; i++) {
        BN_free(k_list[i]);
    }
    free(k_list);
    BN_free(order);
    BN_free(half_order);
    free_messages(messages, tests, deterministic);
    EC_KEY_free(eckey);

    printf("test_bias passed for curve %s\n", curve);
}

/**
 * @brief Tests ECDSA signature generation with default (NULL) randomness.
 *
 * Generates multiple signatures and checks that all 'r' values are unique.
 * Since OpenSSL is deterministic by default for ECDSA (RFC 6979), this
 * ensures uniqueness.
 *
 * @param algorithm The ECDSA algorithm name.
 * @param curve The curve name.
 */
void test_null_random(const char *algorithm, const char *curve) {
    printf("Running test_null_random with algorithm: %s and curve: %s\n", algorithm, curve);

    const EVP_MD *md = get_hash_algorithm(algorithm);
    if (md == NULL) {
        printf("Skipping test_null_random: Unsupported algorithm %s\n", algorithm);
        return;
    }

    EC_KEY *eckey = generate_ec_key(curve);
    if (eckey == NULL) {
        printf("Skipping test_null_random: Could not generate EC key pair for curve %s\n", curve);
        return;
    }

    const int samples = 8;
    int deterministic = 1;
    unsigned char **messages = get_messages_to_sign(samples, deterministic);

    BIGNUM **r_set = malloc(samples * sizeof(BIGNUM*));
    if (r_set == NULL) {
        fprintf(stderr, "Memory allocation failed for r_set in test_null_random\n");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < samples; i++) {
        unsigned char *sig = malloc(ECDSA_size(eckey));
        if (sig == NULL) {
            fprintf(stderr, "Memory allocation failed for signature in test_null_random\n");
            exit(EXIT_FAILURE);
        }
        unsigned int sig_len;

        if (ECDSA_sign(0, messages[i], (int)strlen((char*)messages[i]), sig, &sig_len, eckey) != 1) {
            handle_openssl_error("ECDSA_sign failed in test_null_random");
        }

        BIGNUM *r = extract_r(sig, sig_len);
        for (int j = 0; j < i; j++) {
            ASSERT(BN_cmp(r, r_set[j]) != 0, "Duplicate r detected in test_null_random");
        }
        r_set[i] = r;
        free(sig);
    }

    for (int i = 0; i < samples; i++) {
        BN_free(r_set[i]);
    }
    free(r_set);
    free_messages(messages, samples, deterministic);
    EC_KEY_free(eckey);

    printf("test_null_random passed for curve %s\n", curve);
}

/**
 * @brief Performs a timing-based test to detect bias in ephemeral key generation.
 *
 * Measures the time taken to sign multiple messages and correlates the timing
 * with the ephemeral keys. If a bias is detected (significant deviation from
 * uniform distribution), the test fails.
 *
 * @param algorithm The ECDSA algorithm name.
 * @param curve The curve name.
 */
void test_timing(const char *algorithm, const char *curve) {
    printf("Running test_timing with algorithm: %s and curve: %s\n", algorithm, curve);

    const EVP_MD *md = get_hash_algorithm(algorithm);
    if (md == NULL) {
        printf("Skipping test_timing: Unsupported algorithm %s\n", algorithm);
        return;
    }

    EC_KEY *eckey = generate_ec_key(curve);
    if (eckey == NULL) {
        printf("Skipping test_timing: Could not generate EC key pair for curve %s\n", curve);
        return;
    }

    const int samples = 50000;
    int deterministic = 1;
    unsigned char **messages = get_messages_to_sign(samples, deterministic);

    double *timing = malloc(samples * sizeof(double));
    if (timing == NULL) {
        fprintf(stderr, "Memory allocation failed for timing in test_timing\n");
        exit(EXIT_FAILURE);
    }

    BIGNUM **k_list = malloc(samples * sizeof(BIGNUM*));
    if (k_list == NULL) {
        fprintf(stderr, "Memory allocation failed for k_list in test_timing\n");
        exit(EXIT_FAILURE);
    }

    struct timeval start, end;
    for (int i = 0; i < samples; i++) {
        gettimeofday(&start, NULL);
        unsigned char *sig = malloc(ECDSA_size(eckey));
        if (sig == NULL) {
            fprintf(stderr, "Memory allocation failed for signature in test_timing\n");
            exit(EXIT_FAILURE);
        }
        unsigned int sig_len;

        if (ECDSA_sign(0, messages[i], strlen((char*)messages[i]), sig, &sig_len, eckey) != 1) {
            handle_openssl_error("ECDSA_sign failed in test_timing");
        }

        gettimeofday(&end, NULL);
        double elapsed = (end.tv_sec - start.tv_sec) * 1e6 + (end.tv_usec - start.tv_usec);
        timing[i] = elapsed;

        BIGNUM *k = NULL;
        if (extract_k(eckey, messages[i], strlen((char*)messages[i]), &k) != 1) {
            fprintf(stderr, "Failed to extract k in test_timing\n");
            exit(EXIT_FAILURE);
        }
        k_list[i] = k;

        free(sig);
    }

    double *sorted = malloc(samples * sizeof(double));
    if (sorted == NULL) {
        fprintf(stderr, "Memory allocation failed for sorted timing in test_timing\n");
        exit(EXIT_FAILURE);
    }
    memcpy(sorted, timing, samples * sizeof(double));

    // Simple sort
    for (int i = 0; i < samples - 1; i++) {
        for (int j = i + 1; j < samples; j++) {
            if (sorted[j] < sorted[i]) {
                double temp = sorted[i];
                sorted[i] = sorted[j];
                sorted[j] = temp;
            }
        }
    }

    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    BIGNUM *order = BN_new();
    if (order == NULL) {
        handle_openssl_error("BN_new failed for order in test_timing");
    }
    if (EC_GROUP_get_order(group, order, NULL) != 1) {
        handle_openssl_error("EC_GROUP_get_order failed in test_timing");
    }

    double expected_average = (double)BN_get_word(order) / 2.0;
    double max_sigma = 0.0;

    for (int idx = samples - 1; idx > 10; idx /= 2) {
        double cutoff = sorted[idx];
        int count = 0;
        double total = 0.0;
        for (int i = 0; i < samples; i++) {
            if (timing[i] <= cutoff) {
                double k_val = BN_get_word(k_list[i]);
                total += k_val;
                count++;
            }
        }
        double expected_stddev = ((double)BN_get_word(order)) / sqrt(12.0 * count);
        double average = total / count;
        double sigmas = fabs(expected_average - average) / expected_stddev;
        if (sigmas > max_sigma) {
            max_sigma = sigmas;
        }
        printf("count:%d cutoff:%.2f relative average:%.6f sigmas:%.6f\n",
               count, cutoff, average / expected_average, sigmas);
    }

    ASSERT(max_sigma < 7.0, "Timing attack detected: biased k");

    for (int i = 0; i < samples; i++) {
        BN_free(k_list[i]);
    }
    free(k_list);
    free(timing);
    free(sorted);
    free_messages(messages, samples, deterministic);
    BN_free(order);
    EC_KEY_free(eckey);

    printf("test_timing passed for curve %s\n", curve);
}

/**
 * @brief The main entry point of the test program.
 *
 * Initializes OpenSSL, runs a series of ECDSA tests (basic, constructed parameters,
 * bias tests, null randomness tests, and timing tests), and then cleans up and
 * exits.
 *
 * @return 0 on success, exits with failure otherwise.
 */
int main() {
    /* Initialize OpenSSL */
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    /* Run basic test */
    test_basic("SHA256WithECDSA", "secp256r1");

    /* Run constructed parameter tests */
    test_ecdsa_constructed("SHA256WithECDSA", "secp256r1");
    test_ecdsa_constructed("SHA256WithECDSA", "secp256k1");
    test_ecdsa_constructed("SHA224WithECDSA", "secp224r1");
    test_ecdsa_constructed("SHA256WithECDSA", "X9.62 prime239v1");
    test_ecdsa_constructed("SHA256WithECDSA", "brainpoolP256r1");
    // test_ecdsa_constructed("SHA256WithECDSA", "FRP256v1"); // skip cos openssl

    /* Run bias tests */
    test_bias("SHA224WithECDSA", "secp224r1");
    test_bias("SHA256WithECDSA", "secp256r1");
    test_bias("SHA256WithECDSA", "secp256k1");
    test_bias("SHA384WithECDSA", "secp384r1");
    test_bias("SHA512WithECDSA", "secp521r1");
    test_bias("SHA256WithECDSA", "brainpoolP256r1");
    test_bias("SHA384WithECDSA", "brainpoolP320r1");
    test_bias("SHA256WithECDSA", "X9.62 prime239v1");
    test_bias("SHA256WithECDDSA", "secp256r1");

    /* Run null random tests */
    test_null_random("SHA224WithECDSA", "secp224r1");
    test_null_random("SHA256WithECDSA", "secp256r1");
    test_null_random("SHA384WithECDSA", "secp384r1");
    test_null_random("SHA512WithECDSA", "secp521r1");
    test_null_random("SHA256WithECDDSA", "secp256r1");

    /* Run timing tests */
    test_timing("SHA256WithECDSA", "secp256r1");
    test_timing("SHA256WithECDSA", "brainpoolP256r1");

    /* Cleanup OpenSSL */
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    printf("All tests passed successfully.\n");
    return 0;
}
