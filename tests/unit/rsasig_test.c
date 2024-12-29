#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

/**
 * Utility function: Print an OpenSSL error message and exit.
 */
static void handleOpenSSLError(const char* msg) {
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

/**
 * Utility function: Convert a buffer to a hex string for printing/comparison.
 */
static char* bytesToHex(const unsigned char* bytes, size_t length) {
    static const char* hexDigits = "0123456789abcdef";
    char* hexStr = (char*)malloc(2 * length + 1);
    if (!hexStr) return NULL;

    for (size_t i = 0; i < length; i++) {
        hexStr[2*i]     = hexDigits[(bytes[i] >> 4) & 0x0F];
        hexStr[2*i + 1] = hexDigits[ bytes[i]       & 0x0F];
    }
    hexStr[2 * length] = '\0';
    return hexStr;
}

/**
 * Creates an EVP_PKEY containing RSA key parameters n, e, d, p, q, dp, dq, qInv (CRT param).
 * IMPORTANT: The pointers are assumed to be owned by this function upon successful return.
 *            That is, RSA_set0_*() will take ownership. So do not BN_free() them yourself!
 */
static EVP_PKEY* createRsaPrivateKey(BIGNUM* n, BIGNUM* e, BIGNUM* d,
                                     BIGNUM* p, BIGNUM* q,
                                     BIGNUM* dp, BIGNUM* dq, BIGNUM* qInv) {
    RSA* rsa = RSA_new();
    if (!rsa) {
        handleOpenSSLError("RSA_new failed");
    }

    // Transfer ownership of n, e, d
    if (RSA_set0_key(rsa, n, e, d) != 1) {
        handleOpenSSLError("RSA_set0_key failed");
    }

    // Transfer ownership of p, q
    if (p && q) {
        if (RSA_set0_factors(rsa, p, q) != 1) {
            handleOpenSSLError("RSA_set0_factors failed");
        }
    }

    // Transfer ownership of dp, dq, qInv
    if (dp && dq && qInv) {
        if (RSA_set0_crt_params(rsa, dp, dq, qInv) != 1) {
            handleOpenSSLError("RSA_set0_crt_params failed");
        }
    }

    // Create an EVP_PKEY to hold this RSA
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) {
        handleOpenSSLError("EVP_PKEY_new failed");
    }
    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        handleOpenSSLError("EVP_PKEY_assign_RSA failed");
    }
    // On success, pkey now owns the RSA object (and its BNs).
    return pkey;
}

/**
 * Generates and verifies an RSA signature using SHA-256 with a 2048-bit key.
 * This corresponds to testBasic() in the Java code.
 */
static void testBasic(void) {
    printf("=== testBasic ===\n");

    // 1. Generate 2048-bit RSA key
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

    // 2. Sign the message "Hello"
    const char* message = "Hello";
    size_t msgLen = strlen(message);

    unsigned char sig[2560]; // more than enough for a 2048-bit signature
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

    // 3. Verify the signature
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

    // Free pkey
    EVP_PKEY_free(pkey);
    printf("=== End testBasic ===\n\n");
}

/**
 * Corresponds to testFaultySigner() in the Java code.
 * Demonstrates how an RSA private key with invalid CRT parameters can yield
 * faulty signatures or be rejected by OpenSSL.
 */
static void testFaultySigner(void) {
    printf("=== testFaultySigner ===\n");

    // Big integers used for constructing the valid RSA key
    // The same decimal strings from the Java test
    BIGNUM *e=NULL, *d=NULL, *p=NULL, *q=NULL;
    BIGNUM *n=NULL, *dp=NULL, *dq=NULL, *crt=NULL;

    // clang-format off
    BN_dec2bn(&e, "65537");
    BN_dec2bn(&d,
      "14915811879728327880845702222151552973538390876305994926106912186098027383804966741416365668088258821394558334495197493887270311755863714879317737445668506391996970567226832402905866180183839810991870468038183256577043506759410925826959933748674595737417072513551423973482044545986645893321692393572214394692273248819124586663892276633030063172712539501295530576183692559166562540988259874420834656560217244588117833618119148668563912480037338671215531501554906114868306919889638573670925006068497222709802245970001447477929238222584572234458480871605408837712480652016613750458797849822813881641713404303944154638273");
    BN_dec2bn(&q,
      "132793025024715329123924083377922814684162059913948098032661563268688232734982803223015180489553317316833584435424507409279594393056349447047388914345605165927201322192706870545643991584573901909956380720426452223425786322547871758965140883127102984930768213198832542217762257092135384802889866043941823057701");
    BN_dec2bn(&p,
      "154673213763844328178472871802515098890174859522244863305437090677243079886695427995292782387465415449562347186164815854271071806134464028933334724614223213582911567222033332353858049787180486831134183057020833545199993077390364959938806689016350223809914176306676019969635213034585825883528127235874684082417");
    // clang-format on

    // n = p * q
    n = BN_new(); 
    BN_CTX* ctx = BN_CTX_new();
    BN_mul(n, p, q, ctx);

    // dp = d mod (p-1)
    dp = BN_new();
    BIGNUM* tmp = BN_new();
    BN_sub(tmp, p, BN_value_one());
    BN_mod(dp, d, tmp, ctx);

    // dq = d mod (q-1)
    dq = BN_new();
    BN_sub(tmp, q, BN_value_one());
    BN_mod(dq, d, tmp, ctx);

    // crt = q^-1 mod p
    crt = BN_new();
    BN_mod_inverse(crt, q, p, ctx);
    BN_free(tmp);
    BN_CTX_free(ctx);

    // Create the valid private key (like RSAPrivateCrtKeySpec in Java)
    //
    // IMPORTANT: We pass BN_dup(...) so that createRsaPrivateKey() takes ownership
    // of copies, and we remain free to BN_free() our originals later.
    EVP_PKEY* validKey = createRsaPrivateKey(
        BN_dup(n), BN_dup(e), BN_dup(d),
        BN_dup(p), BN_dup(q),
        BN_dup(dp), BN_dup(dq), BN_dup(crt)
    );

    // Sign a small message "Test" with the valid private key
    const char* message = "Test";
    size_t msgLen = strlen(message);

    unsigned char validSig[2560];
    size_t validSigLen = sizeof(validSig);
    {
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        if (!mdctx) handleOpenSSLError("EVP_MD_CTX_new failed");

        if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, validKey) <= 0) {
            printf("Could not generate valid signature.\n");
            EVP_MD_CTX_free(mdctx);
            goto cleanup;
        }
        if (EVP_DigestSignUpdate(mdctx, message, msgLen) <= 0) {
            printf("Could not generate valid signature.\n");
            EVP_MD_CTX_free(mdctx);
            goto cleanup;
        }
        if (EVP_DigestSignFinal(mdctx, validSig, &validSigLen) <= 0) {
            printf("Could not generate valid signature.\n");
            EVP_MD_CTX_free(mdctx);
            goto cleanup;
        }
        EVP_MD_CTX_free(mdctx);
    }

    char* validSigHex = bytesToHex(validSig, validSigLen);
    printf("Valid signature: %s\n", validSigHex);

    // Now create 16 different “faulty” private key specs by modifying each parameter
    #define MAKE_BN(DEC) ({ BIGNUM* xx = BN_dup(DEC); xx; })

    BIGNUM* bigOne = BN_new();  BN_set_word(bigOne, 1);
    BIGNUM* bigTwo = BN_new();  BN_set_word(bigTwo, 2);

    struct {
        BIGNUM* n_;  BIGNUM* e_;  BIGNUM* d_;
        BIGNUM* p_;  BIGNUM* q_;
        BIGNUM* dp_; BIGNUM* dq_; BIGNUM* crt_;
        const char* description;
    } faultyKeys[16];

    memset(faultyKeys, 0, sizeof(faultyKeys));

    // Helper to fill each with the valid copy, then override
    #define FILL_FAULTYKEY(idx) do { \
        faultyKeys[idx].n_  = MAKE_BN(n);   \
        faultyKeys[idx].e_  = MAKE_BN(e);   \
        faultyKeys[idx].d_  = MAKE_BN(d);   \
        faultyKeys[idx].p_  = MAKE_BN(p);   \
        faultyKeys[idx].q_  = MAKE_BN(q);   \
        faultyKeys[idx].dp_ = MAKE_BN(dp);  \
        faultyKeys[idx].dq_ = MAKE_BN(dq);  \
        faultyKeys[idx].crt_= MAKE_BN(crt); \
    } while(0)

    for (int i = 0; i < 16; i++) {
        FILL_FAULTYKEY(i);
    }

    // Then override each field as in Java:
    //   0) n=1, 1) e=1, 2) d=1, 3) p=1, 4) q=1, 5) dp=1, 6) dq=1, 7) crt=1
    //   8) n=n+2, 9) e=e+2, 10) d=d+2, 11) p=p+2, 12) q=q+2, 13) dp=dp+2, 14) dq=dq+2, 15) crt=crt+2

    // 0) n=1
    BN_free(faultyKeys[0].n_); faultyKeys[0].n_ = MAKE_BN(bigOne);
    faultyKeys[0].description = "n=1";
    // 1) e=1
    BN_free(faultyKeys[1].e_); faultyKeys[1].e_ = MAKE_BN(bigOne);
    faultyKeys[1].description = "e=1";
    // 2) d=1
    BN_free(faultyKeys[2].d_); faultyKeys[2].d_ = MAKE_BN(bigOne);
    faultyKeys[2].description = "d=1";
    // 3) p=1
    BN_free(faultyKeys[3].p_); faultyKeys[3].p_ = MAKE_BN(bigOne);
    faultyKeys[3].description = "p=1";
    // 4) q=1
    BN_free(faultyKeys[4].q_); faultyKeys[4].q_ = MAKE_BN(bigOne);
    faultyKeys[4].description = "q=1";
    // 5) dp=1
    BN_free(faultyKeys[5].dp_); faultyKeys[5].dp_ = MAKE_BN(bigOne);
    faultyKeys[5].description = "dp=1";
    // 6) dq=1
    BN_free(faultyKeys[6].dq_); faultyKeys[6].dq_ = MAKE_BN(bigOne);
    faultyKeys[6].description = "dq=1";
    // 7) crt=1
    BN_free(faultyKeys[7].crt_); faultyKeys[7].crt_ = MAKE_BN(bigOne);
    faultyKeys[7].description = "crt=1";
    // 8) n=n+2
    BN_add(faultyKeys[8].n_, faultyKeys[8].n_, bigTwo);
    faultyKeys[8].description = "n=n+2";
    // 9) e=e+2
    BN_add(faultyKeys[9].e_, faultyKeys[9].e_, bigTwo);
    faultyKeys[9].description = "e=e+2";
    // 10) d=d+2
    BN_add(faultyKeys[10].d_, faultyKeys[10].d_, bigTwo);
    faultyKeys[10].description = "d=d+2";
    // 11) p=p+2
    BN_add(faultyKeys[11].p_, faultyKeys[11].p_, bigTwo);
    faultyKeys[11].description = "p=p+2";
    // 12) q=q+2
    BN_add(faultyKeys[12].q_, faultyKeys[12].q_, bigTwo);
    faultyKeys[12].description = "q=q+2";
    // 13) dp=dp+2
    BN_add(faultyKeys[13].dp_, faultyKeys[13].dp_, bigTwo);
    faultyKeys[13].description = "dp=dp+2";
    // 14) dq=dq+2
    BN_add(faultyKeys[14].dq_, faultyKeys[14].dq_, bigTwo);
    faultyKeys[14].description = "dq=dq+2";
    // 15) crt=crt+2
    BN_add(faultyKeys[15].crt_, faultyKeys[15].crt_, bigTwo);
    faultyKeys[15].description = "crt=crt+2";

    // Attempt signing with each faulty key
    for (int i = 0; i < 16; i++) {
        printf("Testing faulty key %d: %s\n", i, faultyKeys[i].description);
        EVP_PKEY* faultyPKey = NULL;
        unsigned char faultySig[2560];
        size_t faultySigLen = sizeof(faultySig);
        EVP_MD_CTX* mdctx = NULL;

        // Create the faulty key.
        // We pass BN_dup(...) so createRsaPrivateKey() can own them.
        faultyPKey = createRsaPrivateKey(
            BN_dup(faultyKeys[i].n_),
            BN_dup(faultyKeys[i].e_),
            BN_dup(faultyKeys[i].d_),
            BN_dup(faultyKeys[i].p_),
            BN_dup(faultyKeys[i].q_),
            BN_dup(faultyKeys[i].dp_),
            BN_dup(faultyKeys[i].dq_),
            BN_dup(faultyKeys[i].crt_)
        );

        mdctx = EVP_MD_CTX_new();
        if (!mdctx) {
            printf("Faulty RSA parameters correctly detected (MD_CTX).\n");
            EVP_PKEY_free(faultyPKey);
            continue;
        }

        if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, faultyPKey) <= 0) {
            printf("Faulty RSA parameters correctly detected (DigestSignInit).\n");
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(faultyPKey);
            continue;
        }
        if (EVP_DigestSignUpdate(mdctx, message, msgLen) <= 0) {
            printf("Faulty RSA parameters correctly detected (DigestSignUpdate).\n");
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(faultyPKey);
            continue;
        }
        if (EVP_DigestSignFinal(mdctx, faultySig, &faultySigLen) <= 0) {
            printf("Faulty RSA parameters correctly detected (DigestSignFinal).\n");
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(faultyPKey);
            continue;
        }
        EVP_MD_CTX_free(mdctx);

        // Compare the faulty signature to the valid signature
        char* faultySigHex = bytesToHex(faultySig, faultySigLen);
        if (!faultySigHex) {
            printf("Error converting faulty signature to hex.\n");
            EVP_PKEY_free(faultyPKey);
            continue;
        }

        if ((faultySigLen == validSigLen) && (memcmp(faultySig, validSig, validSigLen) == 0)) {
            printf("Faulty parameter not used for signature generation (signatures match).\n");
        } else {
            printf("ERROR: Generated faulty signature with faulty parameters!\n");
            printf(" valid signature:   %s\n", validSigHex);
            printf(" faulty signature:  %s\n", faultySigHex);
        }

        free(faultySigHex);
        EVP_PKEY_free(faultyPKey);
    }

cleanup:
    free(validSigHex);
    EVP_PKEY_free(validKey);

    // Now that validKey is freed (and thus all the BN_dup copies inside it),
    // we can safely free our original BNs.
    BN_free(n);  BN_free(e);  BN_free(d);
    BN_free(p);  BN_free(q);
    BN_free(dp); BN_free(dq); BN_free(crt);
    BN_free(bigOne); BN_free(bigTwo);

    // Free all faulty BNs
    for (int i = 0; i < 16; i++) {
        BN_free(faultyKeys[i].n_);
        BN_free(faultyKeys[i].e_);
        BN_free(faultyKeys[i].d_);
        BN_free(faultyKeys[i].p_);
        BN_free(faultyKeys[i].q_);
        BN_free(faultyKeys[i].dp_);
        BN_free(faultyKeys[i].dq_);
        BN_free(faultyKeys[i].crt_);
    }

    printf("=== End testFaultySigner ===\n\n");
}

int main(void) {
    // Initialize OpenSSL
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    testBasic();
    testFaultySigner();

    // Cleanup
    EVP_cleanup();      // For older versions or transitional usage
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    return 0;
}
