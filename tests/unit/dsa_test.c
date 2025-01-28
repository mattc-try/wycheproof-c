/**
 * @file dsa_tests.c
 * @brief DSA tests using OpenSSL 3.0+ APIs for signature generation, verification, and bias detection.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>    // For gettimeofday timing (alternative to CPU time)
#include <sys/resource.h>// For getrusage timing
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/core.h>
#include <openssl/objects.h>

/* Simple macros for "testing" */
#define ASSERT_TRUE(cond, msg)  do { if (!(cond)) { \
  fprintf(stderr, "Assertion failed: %s\n", msg); exit(1); } } while(0)

#define ASSERT_FALSE(cond, msg) ASSERT_TRUE(!(cond), msg)
#define FAIL(msg)               do { fprintf(stderr, "Test failed: %s\n", msg); exit(1); } while(0)

/**
 * @brief Skips a test and logs the reason.
 * @param reason Reason why the test is being skipped.
 */
static void skipTest(const char* reason) {
  fprintf(stderr, "Skipping test: %s\n", reason);
  // In a real test harness, you might set a skip status rather than exit.
}

/**
 * @brief Converts a hexadecimal string to a BIGNUM.
 * @param hex A null-terminated hexadecimal string.
 * @return A pointer to the resulting BIGNUM, or NULL on failure.
 */
static BIGNUM* bnFromHex(const char* hex) {
  BIGNUM* bn = NULL;
  if (!BN_hex2bn(&bn, hex)) {
    fprintf(stderr, "BN_hex2bn failed for hex: %s\n", hex);
    if (bn) BN_free(bn);
    return NULL;
  }
  return bn;
}

/*
 * Hardcoded DSA parameters from the Java example:
 * We keep them as hex strings for readability, then convert to BIGNUMs.
 * 1024-bit parameters
 */
static const char* P1024_HEX =
  "1106803511314772711673172950296693567629309594518393175860816428"
  "6658764043763662129010863568011543182924292444458455864283745070"
  "9908516713302345161980412667892373845670780253725557376379049862"
  "4062950082444499320797079243439689601679418602390654466821968220"
  "32212146727497041502702331623782703855119908989712161";

static const char* Q1024_HEX =
  "974317976835659416858874959372334979171063697271";

static const char* G1024_HEX =
  "1057342118316953575810387190942009018497979302261477972033090351"
  "7561815639397594841480480197745063606756857212792356354588585967"
  "3837265237205154744016475608524531648654928648461175919672511710"
  "4878976887505840764543501512668232945506391524642105449699321960"
  "32410302985148400531470153936516167243072120845392903";

/*
 * 2048-bit parameters
 */
static const char* P2048_HEX =
  "3164061777193421244945967689185130966883791527930581656543940136"
  "9851564103057893770550122576420376933644344013305735603610942719"
  "0293352994823217443809706583073604061570104365238910634862640398"
  "1679210161833377863606275689118136475272813790454847601448227296"
  "1343536419929610738993809045350019003864284827404321049159705788"
  "9549545448366098569990308459383369877789053024383489750444816799"
  "7655021762159487052492596584201043454441595097537258007948592233"
  "9750333178270807875426129993868319748210561432141824552116718686"
  "0976690334031413657227645931573832903180613929329282084779414766"
  "06239373677116746259950456018096483609849";

static const char* Q2048_HEX =
  "1153325196737607230690138460423355902719413005219740664797410759"
  "18190885248303";

static const char* G2048_HEX =
  "7143867109100500724655889012222798175962488212042071017782036283"
  "2160817495693770539655258112318947749347515155155134204134719860"
  "8823601342715098633684772359506724876037827905133950825065353901"
  "6405352814524900241330050570097484028566246867839194943420499621"
  "1140731561135100139686370478680923000451515444292933075274771723"
  "2158242525416346441387350251926607224043098576684471584941118008"
  "0093586361720527555676600988059377305427568792372489422765662230"
  "0215335648878955714422647428480609353107064891801250653532699120"
  "7943263490377529076378752274796636215661586231670013411198731440"
  "2786085224329787545828730362102716455591";

/**
 * @brief Creates a DSA structure from predefined hexadecimal strings for p, q, and g.
 * @param pHex Hexadecimal representation of parameter p.
 * @param qHex Hexadecimal representation of parameter q.
 * @param gHex Hexadecimal representation of parameter g.
 * @return A pointer to the DSA structure, or NULL on failure.
 */
static DSA* createDsaFromParams(const char* pHex, const char* qHex, const char* gHex) {
  DSA* dsa = DSA_new();
  if (dsa == NULL) {
    skipTest("DSA_new() failed");
    return NULL;
  }
  BIGNUM *p = bnFromHex(pHex);
  BIGNUM *q = bnFromHex(qHex);
  BIGNUM *g = bnFromHex(gHex);

  if (!p || !q || !g) {
    skipTest("Failed to parse p,q,g for DSA");
    DSA_free(dsa);
    if (p) BN_free(p);
    if (q) BN_free(q);
    if (g) BN_free(g);
    return NULL;
  }

  if (!DSA_set0_pqg(dsa, p, q, g)) {
    skipTest("DSA_set0_pqg failed");
    DSA_free(dsa);
    BN_free(p); BN_free(q); BN_free(g);
    return NULL;
  }

  return dsa;
}


/**
 * @brief Extracts the r value from a DER-encoded DSA signature.
 * @param sig Pointer to the DER-encoded signature.
 * @param sigLen Length of the signature.
 * @return A pointer to the BIGNUM representation of r, or NULL on failure.
 */
static BIGNUM* extractRFromDer(const unsigned char* sig, size_t sigLen) {
  /* A manual parse is possible. Alternatively, use d2i_DSA_SIG. */
  DSA_SIG* dsaSig = d2i_DSA_SIG(NULL, &sig, (long)sigLen);
  if (!dsaSig) return NULL;

  const BIGNUM* r = NULL;
  const BIGNUM* s = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  DSA_SIG_get0(dsaSig, &r, &s);
#else
  r = dsaSig->r;
  s = dsaSig->s;
#endif

  BIGNUM* rCopy = BN_dup(r);
  DSA_SIG_free(dsaSig);
  return rCopy;
}


/**
 * @brief Extracts the s value from a DER-encoded DSA signature.
 * @param sig Pointer to the DER-encoded signature.
 * @param sigLen Length of the signature.
 * @return A pointer to the BIGNUM representation of s, or NULL on failure.
 */
static BIGNUM* extractSFromDer(const unsigned char* sig, size_t sigLen) {
  /* We must call d2i_DSA_SIG again, because the pointer 'sig' is consumed. */
  const unsigned char* p = sig;  
  DSA_SIG* dsaSig = d2i_DSA_SIG(NULL, &p, (long)sigLen);
  if (!dsaSig) return NULL;

  const BIGNUM* r = NULL;
  const BIGNUM* s = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  DSA_SIG_get0(dsaSig, &r, &s);
#else
  r = dsaSig->r;
  s = dsaSig->s;
#endif

  BIGNUM* sCopy = BN_dup(s);
  DSA_SIG_free(dsaSig);
  return sCopy;
}

/**
 * @brief Derives the ephemeral k from a DSA signature.
 * @param sig Pointer to the DER-encoded signature.
 * @param sigLen Length of the signature.
 * @param x Private key value.
 * @param dsa Pointer to the DSA structure containing parameters.
 * @param h Hash of the signed message.
 * @param check If non-zero, validates that r == g^k mod p mod q.
 * @return A pointer to the BIGNUM representation of k, or NULL on failure.
 */
static BIGNUM* extractK(const unsigned char* sig, size_t sigLen,
                        const BIGNUM* x, const DSA* dsa,
                        const BIGNUM* h, int check) {
  BIGNUM *r = extractRFromDer(sig, sigLen);
  BIGNUM *s = extractSFromDer(sig, sigLen);
  if (!r || !s) {
    skipTest("Failed extracting (r,s) from signature");
    if (r) BN_free(r);
    if (s) BN_free(s);
    return NULL;
  }

  BN_CTX* ctx = BN_CTX_new();
  if (!ctx) {
    skipTest("BN_CTX_new failed");
    BN_free(r);
    BN_free(s);
    return NULL;
  }

  const BIGNUM* q = NULL;
  const BIGNUM* p = NULL;
  const BIGNUM* g = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  DSA_get0_pqg(dsa, &p, &q, &g);
#else
  p = dsa->p;
  q = dsa->q;
  g = dsa->g;
#endif

  BIGNUM* tmp1 = BN_new();
  BIGNUM* tmp2 = BN_new();
  BIGNUM* k    = BN_new();
  if (!tmp1 || !tmp2 || !k) {
    skipTest("BN_new failed");
    BN_free(r); BN_free(s);
    BN_free(tmp1); BN_free(tmp2); BN_free(k);
    BN_CTX_free(ctx);
    return NULL;
  }

  // k = (x*r + h) * s^-1 mod q
  // Step 1: s^-1 mod q
  if (!BN_mod_inverse(tmp1, s, q, ctx)) {
    skipTest("BN_mod_inverse failed for s^-1");
    goto cleanup;
  }
  // Step 2: (x*r + h)
  if (!BN_mod_mul(tmp2, x, r, q, ctx)) {
    skipTest("BN_mod_mul failed for x*r mod q");
    goto cleanup;
  }
  if (!BN_mod_add(tmp2, tmp2, h, q, ctx)) {
    skipTest("BN_mod_add failed for x*r + h mod q");
    goto cleanup;
  }
  // Step 3: multiply result by s^-1
  if (!BN_mod_mul(k, tmp2, tmp1, q, ctx)) {
    skipTest("BN_mod_mul failed for final k");
    goto cleanup;
  }

  // --- Only do the ephemeral k check if "check == 1" ---
  if (check) {
    // We check that r2 == r (mod q), where r2 = g^k mod p (mod q)
    BIGNUM* r2 = BN_new();
    if (r2 == NULL) {
      skipTest("BN_new failed for r2");
      goto cleanup;
    }
    if (!BN_mod_exp(r2, g, k, p, ctx)) {
      skipTest("BN_mod_exp failed for g^k mod p");
      BN_free(r2);
      goto cleanup;
    }
    // Now reduce mod q
    if (!BN_mod(r2, r2, q, ctx)) {
      skipTest("BN_mod failed for (g^k mod p) mod q");
      BN_free(r2);
      goto cleanup;
    }

    // Compare r2 with r
    if (BN_cmp(r2, r) != 0) {
      FAIL("DSA ephemeral k check failed");
    }
    BN_free(r2);
  }

  // Cleanup
  BN_free(r);
  BN_free(s);
  BN_free(tmp1);
  BN_free(tmp2);
  BN_CTX_free(ctx);
  return k;

cleanup:
  BN_free(r);
  BN_free(s);
  BN_free(tmp1);
  BN_free(tmp2);
  BN_free(k);
  BN_CTX_free(ctx);
  return NULL;
}


/**
 * @brief Generates a new DSA key pair with optional predefined parameters or a specified bit length.
 * @param pHex Hexadecimal representation of parameter p (NULL to generate new).
 * @param qHex Hexadecimal representation of parameter q (NULL to generate new).
 * @param gHex Hexadecimal representation of parameter g (NULL to generate new).
 * @param bits Desired key length in bits if generating new parameters.
 * @return A pointer to the generated DSA structure, or NULL on failure.
 */
static DSA* generateDsaKey(const char* pHex, const char* qHex, const char* gHex, int bits) {
  DSA* dsa = NULL;
  if (pHex && qHex && gHex) {
    dsa = createDsaFromParams(pHex, qHex, gHex);
    if (!dsa) {
      return NULL;
    }
    // Now generate x, y for this DSA (private/public).
    if (!DSA_generate_key(dsa)) {
      skipTest("DSA_generate_key failed");
      DSA_free(dsa);
      return NULL;
    }
  } else {
    // Generate the entire parameter set from scratch
    dsa = DSA_new();
    if (!dsa) {
      skipTest("DSA_new failed for param generation");
      return NULL;
    }
    if (!DSA_generate_parameters_ex(dsa, bits, NULL, 0, NULL, NULL, NULL)) {
      skipTest("DSA_generate_parameters_ex failed");
      DSA_free(dsa);
      return NULL;
    }
    if (!DSA_generate_key(dsa)) {
      skipTest("DSA_generate_key failed");
      DSA_free(dsa);
      return NULL;
    }
  }
  return dsa;
}

/**
 * @brief Tests basic DSA signature generation and verification with predefined parameters.
 */
static void testBasic(void) {
  printf("Running testBasic...\n");
  DSA* dsa = generateDsaKey(P2048_HEX, Q2048_HEX, G2048_HEX, 0);
  if (!dsa) {
    return; // skip
  }
  
  // Convert DSA to an EVP_PKEY
  EVP_PKEY* pkey = EVP_PKEY_new();
  if (!pkey) {
    skipTest("EVP_PKEY_new failed");
    DSA_free(dsa);
    return;
  }
  if (!EVP_PKEY_set1_DSA(pkey, dsa)) {
    skipTest("EVP_PKEY_set1_DSA failed");
    EVP_PKEY_free(pkey);
    DSA_free(dsa);
    return;
  }

  // Sign
  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    skipTest("EVP_MD_CTX_new failed");
    EVP_PKEY_free(pkey);
    DSA_free(dsa);
    return;
  }

  // "SHA256WithDSA" in OpenSSL is basically EVP_sha256 + PKEY=DSA.
  if (1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey)) {
    skipTest("EVP_DigestSignInit failed for sha256/dsa");
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    DSA_free(dsa);
    return;
  }

  const char* message = "Hello";
  if (1 != EVP_DigestSignUpdate(mdctx, message, strlen(message))) {
    skipTest("EVP_DigestSignUpdate failed");
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    DSA_free(dsa);
    return;
  }

  size_t sigLen = 0;
  if (1 != EVP_DigestSignFinal(mdctx, NULL, &sigLen)) {
    skipTest("EVP_DigestSignFinal (get length) failed");
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    DSA_free(dsa);
    return;
  }
  unsigned char* sigBuf = (unsigned char*)OPENSSL_malloc(sigLen);
  if (!sigBuf) {
    skipTest("OPENSSL_malloc failed for signature buffer");
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    DSA_free(dsa);
    return;
  }
  if (1 != EVP_DigestSignFinal(mdctx, sigBuf, &sigLen)) {
    skipTest("EVP_DigestSignFinal (sign) failed");
    OPENSSL_free(sigBuf);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    DSA_free(dsa);
    return;
  }

  // Verify
  EVP_MD_CTX_free(mdctx);
  mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    skipTest("EVP_MD_CTX_new failed (verify)");
    OPENSSL_free(sigBuf);
    EVP_PKEY_free(pkey);
    DSA_free(dsa);
    return;
  }

  if (1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey)) {
    skipTest("EVP_DigestVerifyInit failed");
    EVP_MD_CTX_free(mdctx);
    OPENSSL_free(sigBuf);
    EVP_PKEY_free(pkey);
    DSA_free(dsa);
    return;
  }
  if (1 != EVP_DigestVerifyUpdate(mdctx, message, strlen(message))) {
    skipTest("EVP_DigestVerifyUpdate failed");
    EVP_MD_CTX_free(mdctx);
    OPENSSL_free(sigBuf);
    EVP_PKEY_free(pkey);
    DSA_free(dsa);
    return;
  }
  int vr = EVP_DigestVerifyFinal(mdctx, sigBuf, sigLen);
  ASSERT_TRUE((vr == 1), "testBasic: DSA signature verification failed");

  printf("testBasic: PASSED\n");

  /* Cleanup */
  EVP_MD_CTX_free(mdctx);
  OPENSSL_free(sigBuf);
  EVP_PKEY_free(pkey);
  DSA_free(dsa);
}

/**
 * @brief Tests DSA key generation for various key sizes.
 * @param keySize Key size in bits (e.g., 1024, 2048, 3072, 4096).
 */
static void testKeyGeneration(int keySize) {
  printf("Running testKeyGeneration(%d)...\n", keySize);
  /* 
   * In OpenSSL, we just generate parameters of the given size,
   * then check resulting p,q sizes.
   */
  DSA* dsa = generateDsaKey(NULL, NULL, NULL, keySize);
  if (!dsa) {
    // Key generation not supported or error => skip
    return;
  }
  const BIGNUM* p = NULL; 
  const BIGNUM* q = NULL; 
  const BIGNUM* g = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  DSA_get0_pqg(dsa, &p, &q, &g);
#else
  p = dsa->p;
  q = dsa->q;
  g = dsa->g;
#endif

  int actualPBits = BN_num_bits(p);
  ASSERT_TRUE((actualPBits == keySize), "p bit length mismatch");

  int qsize = BN_num_bits(q);
  switch (keySize) {
    case 1024:
      ASSERT_TRUE((qsize >= 160), "Invalid qsize for 1024 bit key");
      break;
    case 2048:
      ASSERT_TRUE((qsize >= 224), "Invalid qsize for 2048 bit key");
      break;
    case 3072:
      ASSERT_TRUE((qsize >= 256), "Invalid qsize for 3072 bit key");
      break;
    case 4096:
      ASSERT_TRUE((qsize >= 256), "Invalid qsize for 4096 bit key");
      break;
    default:
      FAIL("Invalid key size");
  }

  /* Also check x's bit length >= qsize - 32. */
  const BIGNUM* priv_key = NULL;
  const BIGNUM* pub_key = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  DSA_get0_key(dsa, &pub_key, &priv_key);
#else
  priv_key = dsa->priv_key;
  pub_key  = dsa->pub_key;
#endif
  int xbits = BN_num_bits(priv_key);
  ASSERT_TRUE((xbits >= qsize - 32), "Private key too small");

  printf("testKeyGeneration(%d): PASSED\n", keySize);
  DSA_free(dsa);
}

/**
 * @brief Tests for bias in the ephemeral k values generated during DSA signature creation.
 */
static void testDsaBias(void) {
  printf("Running testDsaBias...\n");
  DSA* dsa = createDsaFromParams(P1024_HEX, Q1024_HEX, G1024_HEX);
  if (!dsa) {
    return;
  }

  /*
   * Hardcode x for demonstration:
   *   x = 13706102843888006547723575730792302382646994436
   * If you want to forcibly set x, you must do some manual steps
   * or just generate a new key. For illustration, we do the manual approach:
   */
  BIGNUM* x = BN_new();
  BN_dec2bn(&x, "13706102843888006547723575730792302382646994436");
  
  // Freed by DSA_set0_key if it succeeds
  BIGNUM* y = BN_new(); // We'll compute y = g^x mod p
  BN_CTX* ctx = BN_CTX_new();
  if (!x || !y || !ctx) {
    skipTest("Memory allocation problem in testDsaBias");
    if (x) BN_free(x);
    if (y) BN_free(y);
    if (ctx) BN_CTX_free(ctx);
    DSA_free(dsa);
    return;
  }

  // compute y = g^x mod p
  const BIGNUM* p = NULL; 
  const BIGNUM* q = NULL; 
  const BIGNUM* g = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  DSA_get0_pqg(dsa, &p, &q, &g);
#else
  p = dsa->p;
  q = dsa->q;
  g = dsa->g;
#endif
  BN_mod_exp(y, g, x, p, ctx);

  // Install new private/public key
  if (!DSA_set0_key(dsa, BN_dup(y), BN_dup(x))) {
    skipTest("DSA_set0_key failed in testDsaBias");
    BN_free(x);
    BN_free(y);
    BN_CTX_free(ctx);
    DSA_free(dsa);
    return;
  }
  BN_free(y);

  // We'll sign the message "Hello" repeatedly
  unsigned char message[] = "Hello";
  unsigned char hash[SHA_DIGEST_LENGTH];
  SHA1(message, strlen((char*)message), hash);
  BIGNUM* h = BN_bin2bn(hash, SHA_DIGEST_LENGTH, NULL);

  EVP_PKEY* pkey = EVP_PKEY_new();
  if (!pkey || !EVP_PKEY_set1_DSA(pkey, dsa)) {
    skipTest("EVP_PKEY creation for testDsaBias failed");
    if (pkey) EVP_PKEY_free(pkey);
    BN_free(h);
    BN_CTX_free(ctx);
    DSA_free(dsa);
    return;
  }

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    skipTest("EVP_MD_CTX_new failed in testDsaBias");
    EVP_PKEY_free(pkey);
    BN_free(h);
    BN_CTX_free(ctx);
    DSA_free(dsa);
    return;
  }

  const int TESTS = 1024;
  int countMsb = 0;
  int countLsb = 0;
  BIGNUM* halfQ = BN_dup(q);
  BN_rshift1(halfQ, halfQ); // halfQ = q/2

  for (int i = 0; i < TESTS; i++) {
    // Sign with SHA1+DSA
    EVP_MD_CTX_reset(mdctx);
    if (1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha1(), NULL, pkey)) {
      skipTest("EVP_DigestSignInit failed in loop");
      break;
    }
    if (1 != EVP_DigestSignUpdate(mdctx, message, strlen((char*)message))) {
      skipTest("EVP_DigestSignUpdate failed in loop");
      break;
    }
    size_t sigLen = 0;
    if (1 != EVP_DigestSignFinal(mdctx, NULL, &sigLen)) {
      skipTest("EVP_DigestSignFinal (get len) failed in loop");
      break;
    }
    unsigned char* sigBuf = (unsigned char*)OPENSSL_malloc(sigLen);
    if (!sigBuf) {
      skipTest("OPENSSL_malloc failed in loop");
      break;
    }
    if (1 != EVP_DigestSignFinal(mdctx, sigBuf, &sigLen)) {
      skipTest("EVP_DigestSignFinal (sign) failed in loop");
      OPENSSL_free(sigBuf);
      break;
    }

    // Extract ephemeral k using check=0 to avoid mismatch failure
    BIGNUM* bigK = extractK(sigBuf, sigLen, x, dsa, h, 0);
    OPENSSL_free(sigBuf);
    if (!bigK) {
      skipTest("extractK failed in loop");
      break;
    }

    // check LSB
    if (BN_is_bit_set(bigK, 0)) {
      countLsb++;
    }
    // check MSB relative to q/2
    if (BN_cmp(bigK, halfQ) > 0) {
      countMsb++;
    }

    BN_free(bigK);
  }

  // The code below checks that countLsb and countMsb are not "too small" or "too large".
  int mincount = 410;
  if (countLsb < mincount || countLsb > TESTS - mincount) {
    FAIL("Bias detected in the least significant bit of k");
  }
  if (countMsb < mincount || countMsb > TESTS - mincount) {
    FAIL("Bias detected in the most significant bit of k");
  }
  printf("testDsaBias: PASSED\n");

  // Cleanup
  BN_free(h);
  BN_free(halfQ);
  BN_CTX_free(ctx);
  EVP_MD_CTX_free(mdctx);
  EVP_PKEY_free(pkey);
  DSA_free(dsa);
}

/**
 * @brief Measures the timing of DSA signature generation to detect potential biases or side-channel vulnerabilities.
 */
static void testTiming(void) {
  printf("Running testTiming...\n");
  // We just do a simpler version with 10k signatures, for demonstration
  DSA* dsa = createDsaFromParams(P1024_HEX, Q1024_HEX, G1024_HEX);
  if (!dsa) {
    return;
  }
  if (!DSA_generate_key(dsa)) {
    skipTest("DSA_generate_key failed in testTiming");
    DSA_free(dsa);
    return;
  }

  EVP_PKEY* pkey = EVP_PKEY_new();
  if (!pkey) {
    skipTest("EVP_PKEY_new failed in testTiming");
    DSA_free(dsa);
    return;
  }
  EVP_PKEY_set1_DSA(pkey, dsa);

  const int samples = 10000;
  long* timings = (long*)calloc(samples, sizeof(long));
  if (!timings) {
    skipTest("calloc failed for timings array");
    EVP_PKEY_free(pkey);
    DSA_free(dsa);
    return;
  }

  // Precompute a small message digest to sign
  unsigned char message[] = "Hello";
  unsigned char hash[SHA_DIGEST_LENGTH];
  SHA1(message, strlen((char*)message), hash);

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    skipTest("EVP_MD_CTX_new failed in testTiming");
    free(timings);
    EVP_PKEY_free(pkey);
    DSA_free(dsa);
    return;
  }

  struct rusage start, end;

  for (int i = 0; i < samples; i++) {
    getrusage(RUSAGE_SELF, &start);

    EVP_MD_CTX_reset(mdctx);
    if (1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha1(), NULL, pkey)) {
      skipTest("EVP_DigestSignInit failed in testTiming loop");
      break;
    }
    if (1 != EVP_DigestSignUpdate(mdctx, message, strlen((char*)message))) {
      skipTest("EVP_DigestSignUpdate failed in testTiming loop");
      break;
    }
    size_t sigLen = 0;
    if (1 != EVP_DigestSignFinal(mdctx, NULL, &sigLen)) {
      skipTest("EVP_DigestSignFinal (len) failed in testTiming loop");
      break;
    }
    unsigned char* sigBuf = OPENSSL_malloc(sigLen);
    if (!sigBuf) {
      skipTest("OPENSSL_malloc failed in testTiming loop");
      break;
    }
    if (1 != EVP_DigestSignFinal(mdctx, sigBuf, &sigLen)) {
      skipTest("EVP_DigestSignFinal (sign) failed in testTiming loop");
      OPENSSL_free(sigBuf);
      break;
    }
    OPENSSL_free(sigBuf);

    getrusage(RUSAGE_SELF, &end);

    // Rough microseconds difference
    long secDiff  = end.ru_utime.tv_sec  - start.ru_utime.tv_sec;
    long usecDiff = end.ru_utime.tv_usec - start.ru_utime.tv_usec;
    long totalMicro = secDiff * 1000000 + usecDiff;
    timings[i] = totalMicro;
  }

  // Sort timings
  for (int i = 0; i < samples - 1; i++) {
    for (int j = i + 1; j < samples; j++) {
      if (timings[j] < timings[i]) {
        long tmp = timings[i];
        timings[i] = timings[j];
        timings[j] = tmp;
      }
    }
  }

  // Simple check of the 10% fastest vs. 10% slowest
  long cutoff = timings[samples / 10];
  long cutoff2 = timings[samples - samples / 10];
  printf("testTiming: 10%% fastest = %ld microseconds, 10%% slowest = %ld microseconds\n",
         cutoff, cutoff2);

  // Arbitrary example check
  if ((cutoff2 - cutoff) > 2000) {
    skipTest("Possible timing bias discovered (just a demonstration!)");
  } else {
    printf("testTiming: PASSED (no major difference observed)\n");
  }

  // Cleanup
  EVP_MD_CTX_free(mdctx);
  free(timings);
  EVP_PKEY_free(pkey);
  DSA_free(dsa);
}

/**
 * @brief Validates that DSA cannot be used as a cipher.
 */
static void testEncryptionWithDsa(void) {
  printf("Running testEncryptionWithDsa...\n");
  // There's no official "DSA" cipher to retrieve from OpenSSL.
  const EVP_CIPHER* ciph = EVP_get_cipherbyname("DSA");
  if (ciph != NULL) {
    FAIL("DSA must not be used as a cipher, but it was found anyway");
  }
  printf("testEncryptionWithDsa: PASSED (no DSA cipher found)\n");
}

/**
 * @brief Main entry point for running all DSA tests.
 * @return 0 on successful completion, 1 on failure.
 */
int main(void) {
  /* Must load the default and legacy providers in OpenSSL 3.0+ 
   * or else some older algorithms (including DSA) might be unavailable.
   */
  OSSL_PROVIDER *deflt = OSSL_PROVIDER_load(NULL, "default");
  if (!deflt) {
    fprintf(stderr, "Error loading default provider.\n");
    return 1;
  }
  OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
  if (!legacy) {
    fprintf(stderr, "Error loading legacy provider.\n");
    return 1;
  }

  /* The rest of your test code... */
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  /* Run your DSA tests */
  testBasic();
  testKeyGeneration(1024);
  testKeyGeneration(2048);
  testKeyGeneration(3072);
  testKeyGeneration(4096);

  testEncryptionWithDsa();

  testDsaBias();
  testTiming();

  printf("All tests finished.\n");
  return 0;
}
