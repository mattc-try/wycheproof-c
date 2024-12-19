# Failure to Ensure Constant-Time Operations

## CVE-2018-0737: Cache Timing Side-Channel Attack in RSA Key Generation
- **Specification:**  
  This vulnerability affects the RSA key generation process in OpenSSL, where a cache timing side-channel attack could be exploited. Such an attack allows an attacker with sufficient access to monitor cache timings during RSA key generation, potentially enabling them to recover the private key being generated. The vulnerability is particularly concerning in shared environments, such as virtualized or cloud infrastructures.
- **Defect:**  
  The defect is due to the absence of constant-time operations during the RSA key generation process. Timing variations in processing steps can inadvertently leak sensitive information. By analyzing these timing variations, an attacker could potentially deduce the private key, making the key generation process susceptible to side-channel attacks.
- **Impact:**  
  Cache timing side-channel attacks pose a significant threat in cryptographic systems because they target the physical implementation of algorithms rather than the algorithms themselves. In this case, an attacker who can monitor the cache during RSA key generation might be able to recover the private key. This vulnerability is especially critical in environments where hardware resources are shared among multiple users, such as in virtualized environments, leading to a high risk of key compromise.
- **Code Snippet:**  
  The commit addresses the vulnerability by ensuring that the RSA key generation process uses constant-time operations, which mitigates the timing variations that could lead to this type of side-channel attack:
```c
@@ -157,6 +157,7 @@ static int rsa_builtin_keygen(RSA *rsa, int bits, int primes, BIGNUM *e_value,
            pinfo = sk_RSA_PRIME_INFO_value(prime_infos, i - 2);
            prime = pinfo->r;
        }
+       BN_set_flags(prime, BN_FLG_CONSTTIME);

        for (;;) {
 redo:
```
[ling](https://github.com/openssl/openssl/commit/54f007af94b8924a46786b34665223c127c19081)



## CVE-2016-1000341: Timing Attack on DSA Signature Generation in Bouncy Castle
- **Specification:**  
  This vulnerability affects the implementation of the Digital Signature Algorithm (DSA) in the Bouncy Castle cryptographic library. The issue arises due to insufficient randomization during the DSA signature generation process, which makes it vulnerable to timing attacks. An attacker could exploit this weakness to recover the private key used in DSA, potentially leading to a full compromise of the cryptographic system.
- **Defect:**  
  The defect lies in the failure to ensure that DSA operations are performed in constant time. Specifically, the lack of sufficient randomization in the signature generation process creates timing discrepancies that can be observed and analyzed by an attacker. These timing variations can inadvertently leak information about the private key, making the system vulnerable to timing attacks.
- **Impact:**  
  Timing attacks exploit differences in the time it takes to execute cryptographic operations. In this case, the timing variations during the DSA signature generation process can reveal sensitive information about the private key. By analyzing these timing differences over multiple observations, an attacker could potentially recover the private key, leading to a complete compromise of the cryptographic system. This vulnerability is particularly concerning because it is a low-level Hard-to-Find Bug (HFB), making it difficult to detect and exploit but highly damaging if successfully leveraged.
- **Code Snippet:**  
```java
@@ -95,7 +95,8 @@ public BigInteger[] generateSignature(

-       BigInteger  k = kCalculator.nextK();

+       BigInteger  r = params.getG().modPow(k, params.getP()).mod(q);
+       // the randomizer is to conceal timing information related to k and x.
+       BigInteger  r = params.getG().modPow(k.add(getRandomizer(q, random)), params.getP()).mod(q);

        k = k.modInverse(q).multiply(m.add(x.multiply(r)));

@@ -163,4 +164,12 @@ protected SecureRandom initSecureRandom(boolean needed, SecureRandom provided)
    {
        return !needed ? null : (provided != null) ? provided : new SecureRandom();
    }

+    private BigInteger getRandomizer(BigInteger q, SecureRandom provided)
+    {
+       // Calculate a random multiple of q to add to k. Note that g^q = 1 (mod p), so adding    
        //multiple of q to k does not change r.
+        int randomBits = 7;
+
+        return new BigInteger(randomBits, provided != null ? provided : new SecureRandom()).add(BigInteger.valueOf(128)).multiply(q);
+    }
}
```


## CVE-2019-1547: Side-Channel Vulnerability in OpenSSL ECDSA Signature Operation
- **Specification:**  
  CVE-2019-1547 is a vulnerability in OpenSSL that affects the handling of elliptic curve (EC) groups during ECDSA (Elliptic Curve Digital Signature Algorithm) operations. The issue arises when EC groups are constructed using explicit parameters, where the optional cofactor is either zero or absent. In these cases, OpenSSL may revert to using outdated, side-channel-vulnerable code paths during ECDSA signature generation, increasing the risk of timing attacks that could lead to the full recovery of the ECDSA private key.
- **Defect:**  
  The defect lies in the failure to ensure side-channel resistance when the cofactor is missing or improperly set in EC groups created with explicit parameters. Without the cofactor, OpenSSL previously fell back to old, non-side-channel-resistant scalar multiplication code. This vulnerable code path could be exploited by attackers through timing attacks, particularly when the cofactor is absent, leading to the potential leakage of the private key.
- **Impact:**  
  Side-channel attacks, such as timing attacks, exploit variations in the time taken to perform cryptographic operations to gain sensitive information, such as private keys. In this case, the vulnerability allows attackers to perform a timing attack during ECDSA signature generation if the EC group was created without a valid cofactor. This could result in the full recovery of the ECDSA private key, allowing attackers to forge signatures or decrypt sensitive communications, posing a significant security risk.
- **Code Snippet:**  
  The vulnerability was mitigated by modifying the `EC_GROUP_set_generator` function to compute the cofactor when it is not provided, ensuring that the scalar multiplication uses side-channel-resistant code paths. The fix involved the following changes:
  ```c
  /* Either take the provided positive cofactor, or try to compute it */
  if (cofactor != NULL && !BN_is_zero(cofactor)) {
      if (!BN_copy(group->cofactor, cofactor))
          return 0;
  } else if (!ec_guess_cofactor(group)) {
      BN_zero(group->cofactor);
      return 0;
  }
  ```
[lingk](https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=7c1709c2da5414f5b6133d00a03fc8c5bf996c7a)


## GHSA-f6jh-hvg2-9525: KyberSlash2 Vulnerability
- **Specification:**  
  The KyberSlash2 vulnerability relates to the implementation of the CRYSTALS-Kyber post-quantum cryptographic algorithm in the `crystals-go` repository. This vulnerability arises from a side-channel attack that can potentially lead to the leakage of sensitive cryptographic key material. CRYSTALS-Kyber is designed to provide security against quantum computing attacks, but the specific Go implementation did not fully mitigate side-channel risks.
- **Defect:**  
  The defect lies in the inadequate mitigation of side-channel attacks within the Kyber algorithm's implementation. The vulnerability allows an attacker to observe timing variations during cryptographic operations, which can be analyzed to infer sensitive information such as secret keys. This timing variability poses a significant security risk, especially in the context of post-quantum cryptography, where resilience against such attacks is paramount.
- **Impact:**  
  The impact of this vulnerability is critical in environments where the Kyber KEM (Key Encapsulation Mechanism) is used to secure sensitive communications or data. An attacker exploiting this side-channel vulnerability could potentially recover secret keys, leading to the decryption of secure communications or unauthorized access to sensitive information. This is particularly concerning in high-security environments, such as government or military applications, where post-quantum cryptographic algorithms are relied upon for future-proof security.
- **Code Snippet:**  
  The issue was resolved by updating the `crystals-go` implementation to incorporate more robust countermeasures against side-channel attacks. The updated code ensures that cryptographic operations are performed in constant time, regardless of the input data, thereby mitigating the risk of timing attacks. The specific changes made to the code include adjustments to the algorithm's timing behavior to ensure uniformity across different operations.

Here’s the improved and properly formatted documentation for the **Vulnerability in EdDSA Implementations**:

## pqc#1: Vulnerability in EdDSA Implementations
- **Specification:**  
  The vulnerability in EdDSA (Edwards-curve Digital Signature Algorithm) implementations is discussed in the paper "The Fragility of Blind Signature Schemes when Implemented in the Real World" (eprint.iacr.org/2019/525). The issue arises from incorrect implementations that are susceptible to side-channel attacks, particularly timing attacks, which can potentially lead to the extraction of private keys.
- **Defect:**  
  The defect stems from the failure of certain EdDSA implementations to ensure constant-time execution of critical operations during the signature generation process. This oversight allows attackers to exploit timing variations to recover sensitive information, such as private keys, by measuring the time taken for specific cryptographic operations.
- **Impact:**  
  The impact of this vulnerability is severe, particularly in environments where EdDSA is used for crucial cryptographic functions, such as digital signatures or authentication protocols. If successfully exploited, the vulnerability allows attackers to extract the private key, enabling them to forge signatures, impersonate users, or decrypt sensitive communications.
- **Code Snippet:**  
  The resolution involves updating EdDSA implementations to use constant-time algorithms for all cryptographic operations, especially during signature generation. This requires ensuring that the execution time of these operations does not vary based on input values or the state of computation. Implementing additional side-channel defenses, such as blinding techniques, can further mitigate the risk of timing attacks.
  - [The Fragility of Blind Signature Schemes when Implemented in the Real World](https://eprint.iacr.org/2019/525)
  - [PDF of the Paper](https://eprint.iacr.org/2019/525.pdf) (for detailed technical analysis and proofs).


## CVE-2018-12438: ROHNP Vulnerability in `sunec` and `libsunec` Libraries
- **Specification:**  
  CVE-2018-12438 refers to a critical vulnerability in the `sunec` or `libsunec` libraries, which are components of the Elliptic Curve Cryptography (ECC) used in various cryptographic applications. The vulnerability, known as the "Return Of the Hidden Number Problem" (ROHNP), exposes these libraries to a memory-cache side-channel attack during the ECDSA (Elliptic Curve Digital Signature Algorithm) signature generation process. This issue primarily affects environments where the attacker can access the same physical machine, such as through a local machine or a virtual machine on shared hardware.
- **Defect:**  
  The core defect lies in the inadequate defense against side-channel attacks in the `sunec` library's implementation of ECDSA. Specifically, the vulnerability allows attackers to monitor memory access patterns during the ECDSA signature generation process. By analyzing these patterns, an attacker can infer the private key used in the signature process, compromising the security of the cryptographic operations.
- **Impact:**  
  The impact of CVE-2018-12438 is significant, particularly in high-security environments where ECDSA is relied upon for authentication and secure communication. An attacker with sufficient access could exploit this vulnerability to recover the ECDSA private key, leading to unauthorized decryption of communications, forging of signatures, and overall compromise of system integrity. The severity of this vulnerability is amplified in virtualized environments, where multiple users may share the same physical hardware.
- **Code Snippet:**  
  There is no specific public code snippet associated with this vulnerability. However, the issue is rooted in how the `sunec` library handles ECDSA signature generation, where memory access patterns can be observed and exploited in a side-channel attack.


## CVE-2024-36405: Timing Attack Vulnerability in liboqs's Kyber Implementation
- **Specification:**  
  CVE-2024-36405 refers to a vulnerability in the `liboqs` cryptographic library, which provides implementations of post-quantum cryptography algorithms. The issue specifically affects the Kyber key encapsulation mechanism (KEM) in the library. When compiled with certain Clang compiler optimization settings (`-Os`, `-O1`, and others), a control-flow timing leak can occur. This leak allows attackers to exploit the timing variations during the decapsulation process, potentially exposing the entire ML-KEM 512 secret key.
- **Defect:**  
  The defect lies in the Kyber implementation’s susceptibility to timing attacks due to how the library's control flow is handled under specific compiler optimizations. The timing leak enables an attacker to perform end-to-end decapsulation timing measurements, which can reveal the secret key in approximately 10 minutes.
- **Impact:**  
  The impact of this vulnerability is substantial, especially given the high confidentiality requirements associated with post-quantum cryptographic systems. An attacker exploiting this flaw could successfully recover the entire secret key used in the Kyber KEM, leading to the compromise of encrypted communications. The vulnerability is rated as having a medium severity (CVSS score of 5.9) due to the high attack complexity and the local nature of the attack. The confidentiality of the affected system is at high risk, though there are no immediate impacts on integrity or availability.
- **Code Snippet:**  
  There is no specific public code snippet associated with this vulnerability. The issue is related to how the Kyber KEM implementation interacts with the compiler’s optimization settings, which inadvertently introduces a timing side-channel that can be exploited.
[GitHub](https://github.com/open-quantum-safe/liboqs/security/advisories/GHSA-f2v9-5498-2vpp).


### NaCl ed25519: Carry Handling Issue in F25519 Multiplication and Squaring
- **Specification:**  
  The issue pertains to the `F25519` field arithmetic in the NaCl (Networking and Cryptography Library) implementation of the Ed25519 digital signature algorithm, as detailed in the TweetNaCl specification. The problem arises specifically in the handling of carry operations during the multiplication and squaring functions within the 64-bit pseudo-Mersenne implementation, particularly on AMD64 architectures.
- **Defect:**  
  The defect is related to improper carry handling in the `F25519` arithmetic functions. When performing multiplication and squaring, the result can sometimes exceed the expected range, necessitating a carry operation to ensure the result remains within the valid field size. The issue occurs when the carry is not correctly handled, potentially leading to incorrect results in cryptographic computations. This problem can affect the integrity of the Ed25519 signatures generated using this implementation.
- **Impact:**  
  The impact of this defect is significant in cryptographic contexts where accurate arithmetic operations are crucial. Improper carry handling could result in invalid signature generation or verification, compromising the security and reliability of systems using the affected NaCl implementation. Specifically, it may allow attackers to forge signatures or cause legitimate signatures to fail verification, leading to potential unauthorized access or denial of service.
- **Code Snippet:**  
  ```c
  void F25519_mul(uint64_t *out, const uint64_t *a, const uint64_t *b) {
      // Perform multiplication and squaring operations
      // Ensure proper carry handling to maintain field integrity
      // ...
  }
  ```
 [TweetNaCl documentation](https://tweetnacl.cr.yp.to/tweetnacl-20131229.pdf)

 ## CVE-2021-29415: Non-Constant Time ECDSA Vulnerability in ARM TrustZone CryptoCell 310
- **Specification:**  
  CVE-2021-29415 is a vulnerability affecting the elliptic curve cryptography (ECC) hardware accelerator within the ARM® TrustZone® CryptoCell 310, specifically in the Nordic Semiconductor nRF52840 through March 29, 2021. The vulnerability stems from a non-constant time implementation of the Elliptic Curve Digital Signature Algorithm (ECDSA). This flaw can be exploited by an adversary to recover the private ECC key used during ECDSA operations.
- **Defect:**  
  The defect is a result of the non-constant time execution of ECDSA operations in the CryptoCell 310 hardware accelerator. This non-constant time behavior leaks timing information that can be observed and analyzed by an attacker. By analyzing these timing variations, an attacker could infer the private key, particularly when they have the ability to observe or interact with the cryptographic operations multiple times.
- **Impact:**  
  The vulnerability presents a serious risk, particularly in environments where ECC is used for secure communications or sensitive data protection. The ability to recover the private key through timing analysis could compromise the entire security framework of systems utilizing the affected hardware. This could lead to unauthorized access, data breaches, or the ability to forge digital signatures.
- **Code Snippet:**  
  There is no specific code snippet associated with this vulnerability, as it pertains to the hardware-level implementation of the ECDSA algorithm in the CryptoCell 310. However, the issue is related to how the elliptic curve operations are processed in the hardware, leading to observable timing discrepancies.
  - [GitHub Advisory Database](https://github.com/advisories/GHSA-738r-q8gh-xrrc)
