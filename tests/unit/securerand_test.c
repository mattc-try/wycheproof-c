#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

/**
 * Converts a byte array to a hex string.
 */
static void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex_out) {
    static const char hexdig[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        unsigned char c = bytes[i];
        hex_out[2*i]     = hexdig[c >> 4];
        hex_out[2*i + 1] = hexdig[c & 0x0F];
    }
    hex_out[2*len] = '\0';
}

/**
 * Checks if a hex string is in a set of previously seen values.
 */
static int seen_contains(char **seen, int seen_count, const char *hex) {
    for (int i = 0; i < seen_count; i++) {
        if (strcmp(seen[i], hex) == 0) {
            return 1;
        }
    }
    return 0;
}

/**
 * Adds a hex string to the seen set.
 */
static void seen_add(char ***seen, int *seen_count, const char *hex) {
    *seen = realloc(*seen, sizeof(char*) * (*seen_count + 1));
    (*seen)[*seen_count] = strdup(hex);
    (*seen_count)++;
}

/**
 * Frees the seen set.
 */
static void seen_free(char **seen, int seen_count) {
    for (int i = 0; i < seen_count; i++) {
        free(seen[i]);
    }
    free(seen);
}

/**
 * Test that uninitialized instance (just using RAND_bytes directly) does not produce deterministic output.
 * Equivalent to testSeedUninitializedInstance in spirit.
 */
static void test_seed_uninitialized_instance(void) {
    const int samples = 10;
    const int outputsize = 8;

    unsigned char bytes[outputsize];
    char **seen = NULL;
    int seen_count = 0;
    char hex[2*outputsize+1];

    // Generate multiple samples and ensure no duplicates.
    for (int i = 0; i < samples; i++) {
        if (RAND_bytes(bytes, outputsize) != 1) {
            fprintf(stderr, "RAND_bytes failed\n");
            exit(1);
        }
        bytes_to_hex(bytes, outputsize, hex);
        if (seen_contains(seen, seen_count, hex)) {
            fprintf(stderr, "Repeated output detected in test_seed_uninitialized_instance.\n");
            exit(1);
        }
        seen_add(&seen, &seen_count, hex);
    }

    seen_free(seen, seen_count);
    printf("test_seed_uninitialized_instance passed.\n");
}

/**
 * Test the effect of seeding right after "construction".
 * In OpenSSL we don't construct per-instance PRNGs easily, but we can simulate by re-seeding.
 * We'll see if adding the same seed before RAND_bytes leads to deterministic output.
 * Equivalent to testSetSeedAfterConstruction in spirit.
 */
static void test_set_seed_after_construction(void) {
    const int samples = 10;
    const int outputsize = 8;
    unsigned char seed[32];
    memset(seed, 0, sizeof(seed));

    char **seen = NULL;
    int seen_count = 0;
    char hex[2*outputsize+1];

    // We'll run multiple attempts: each attempt seeds with the same seed and then generates 8 bytes.
    for (int i = 0; i < samples; i++) {
        // Add seed (this might not reset the DRBG to a deterministic state, it just adds entropy)
        RAND_seed(seed, sizeof(seed));

        unsigned char bytes[outputsize];
        if (RAND_bytes(bytes, outputsize) != 1) {
            fprintf(stderr, "RAND_bytes failed\n");
            exit(1);
        }
        bytes_to_hex(bytes, outputsize, hex);
        seen_add(&seen, &seen_count, hex);
    }

    // Check if all samples are identical or not.
    // If they are all identical, that would mean deterministic output.
    // More likely, they'll all be different.
    // Count distinct values:
    int distinct = seen_count;
    for (int i = 0; i < seen_count; i++) {
        for (int j = i+1; j < seen_count; j++) {
            if (strcmp(seen[i], seen[j]) == 0) {
                distinct--;
                break;
            }
        }
    }

    if (distinct == 1) {
        printf("Seeding after construction results in deterministic output.\n");
    } else {
        printf("Seeding after construction results in non-deterministic output.\n");
        // If it's non-deterministic, we expect no repetitions:
        if (distinct != samples) {
            fprintf(stderr, "Expected all samples distinct but got some repetitions.\n");
            exit(1);
        }
    }

    seen_free(seen, seen_count);
    printf("test_set_seed_after_construction passed.\n");
}

/**
 * Test the default behavior with a given seed passed to SecureRandom (in Java).
 * In OpenSSL, calling RAND_seed before RAND_bytes does not guarantee determinism.
 * Equivalent to testDefaultSecureRandom.
 */
static void test_default_secure_random(void) {
    const int samples = 10;
    const int outputsize = 8;
    unsigned char seed[32];
    memset(seed, 0, sizeof(seed));

    char **seen = NULL;
    int seen_count = 0;
    char hex[2*outputsize+1];

    for (int i = 0; i < samples; i++) {
        // Mimic "new SecureRandom(seed)"
        // In OpenSSL, we can't directly "construct" a new RAND instance easily.
        // We'll just seed the global DRBG again:
        RAND_seed(seed, sizeof(seed));

        unsigned char bytes[outputsize];
        if (RAND_bytes(bytes, outputsize) != 1) {
            fprintf(stderr, "RAND_bytes failed\n");
            exit(1);
        }
        bytes_to_hex(bytes, outputsize, hex);
        seen_add(&seen, &seen_count, hex);
    }

    // Check determinism:
    int distinct = seen_count;
    for (int i = 0; i < seen_count; i++) {
        for (int j = i+1; j < seen_count; j++) {
            if (strcmp(seen[i], seen[j]) == 0) {
                distinct--;
                break;
            }
        }
    }

    if (distinct == 1) {
        printf("Default SecureRandom equivalent results in deterministic output.\n");
    } else {
        printf("Default SecureRandom equivalent results in non-deterministic output.\n");
        if (distinct != samples) {
            fprintf(stderr, "Expected all samples distinct but got some repetitions.\n");
            exit(1);
        }
    }

    seen_free(seen, seen_count);
    printf("test_default_secure_random passed.\n");
}

/**
 * Test that calling setSeed (RAND_seed) after use does not reset determinism.
 * Equivalent to testSetSeedAfterUse.
 */
static void test_set_seed_after_use(void) {
    const int samples = 10;
    const int outputsize = 8;
    unsigned char seed[32];
    memset(seed, 0, sizeof(seed));

    char **seen = NULL;
    int seen_count = 0;
    char hex[2*outputsize+1];

    for (int i = 0; i < samples; i++) {
        // RAND_bytes once to ensure it has been seeded somehow.
        unsigned char dummy[1];
        RAND_bytes(dummy, 1);

        // Now seed again:
        RAND_seed(seed, sizeof(seed));

        // Generate new bytes:
        unsigned char bytes[outputsize];
        if (RAND_bytes(bytes, outputsize) != 1) {
            fprintf(stderr, "RAND_bytes failed\n");
            exit(1);
        }
        bytes_to_hex(bytes, outputsize, hex);
        if (seen_contains(seen, seen_count, hex)) {
            fprintf(stderr, "Repeated output detected in test_set_seed_after_use.\n");
            exit(1);
        }
        seen_add(&seen, &seen_count, hex);
    }

    seen_free(seen, seen_count);
    printf("test_set_seed_after_use passed.\n");
}

int main(void) {
    // Just run the tests one by one:
    test_seed_uninitialized_instance();
    test_set_seed_after_construction();
    test_default_secure_random();
    test_set_seed_after_use();

    printf("All tests passed.\n");
    return 0;
}
