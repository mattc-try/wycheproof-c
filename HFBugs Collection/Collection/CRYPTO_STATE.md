# Mismanagement of Cryptographic State or Context

## openssl#3de81a5#1: BN_FLG_CONSTTIME Flag Propagation Bug
- **Specification:**  
  This vulnerability affects OpenSSL's handling of the `BN_FLG_CONSTTIME` flag within the `BN_MONT_CTX_set` function, which is part of the RSA key generation process. The `BN_FLG_CONSTTIME` flag is critical for ensuring that cryptographic operations, particularly those involving sensitive data like RSA primes `p` and `q`, are executed in constant time to prevent timing attacks. The bug arises from the improper propagation of this flag, potentially exposing sensitive information.
- **Defect:**  
  The defect occurs due to the improper propagation of the `BN_FLG_CONSTTIME` flag within the `BN_MONT_CTX_set` function. This improper handling means that certain operations on RSA primes might not be executed in constant time, increasing the risk of timing attacks. These attacks could allow an attacker to infer details about the RSA primes, which are essential for the security of RSA keys.
- **Impact:**  
  Constant-time operations are a crucial defense against timing attacks, where attackers gain information by measuring the time taken to perform cryptographic operations. In this case, the failure to correctly propagate the `BN_FLG_CONSTTIME` flag could allow timing variations during RSA key generation, potentially revealing parts of the private key (i.e., the primes `p` and `q`). This vulnerability is particularly concerning in environments where RSA key generation is performed frequently, such as on shared systems or cloud platforms.
- **Code Snippet:**  
  The commit [3de81a5912041a70884cf4e52e7213f3b5dfa747](https://github.com/openssl/openssl/commit/3de81a5912041a70884cf4e52e7213f3b5dfa747) addresses the vulnerability by ensuring that the `BN_FLG_CONSTTIME` flag is properly propagated to all relevant `BIGNUM` objects during the Montgomery context setup. This fix helps maintain the security of RSA key generation by ensuring that all operations involving sensitive data are performed in constant time, thus mitigating the risk of timing attacks.


## CVE-2016-0701: Diffie-Hellman (DH) Key Exchange Weakness in OpenSSL
- **Specification:**  
  CVE-2016-0701 is a high-severity vulnerability in OpenSSL's implementation of the Diffie-Hellman (DH) key exchange protocol. The flaw occurs when OpenSSL uses static or reusable private keys in the DH key exchange process, especially when non-"safe" primes are employed. This could allow an attacker to perform a brute-force attack to recover the private key, compromising the security of the key exchange.
- **Defect:**  
  The defect is related to the improper handling of Diffie-Hellman parameters during the key exchange process. If the `SSL_OP_SINGLE_DH_USE` option is not enabled, OpenSSL may reuse the same private DH exponent across multiple sessions, particularly when non-"safe" primes are used, such as those generated with X9.42 style parameters. This reuse significantly weakens the security of the DH key exchange.
- **Impact:**  
  The vulnerability allows an attacker to exploit the DH key exchange by capturing the public key and observing multiple handshakes where the same private key is reused. This could lead to a brute-force attack where the attacker recovers the private key, compromising the confidentiality and integrity of the communication. This issue is especially critical in environments using static DH ciphersuites or non-ephemeral DH (DHE) modes.
- **Code Snippet:**  
  The vulnerability was mitigated in OpenSSL 1.0.2f by enabling the `SSL_OP_SINGLE_DH_USE` option by default, which ensures that a unique private key is generated for each DH key exchange session. This change prevents the reuse of private keys and mitigates the risk of brute-force attacks.

## end-to-end#340
- **Specification:**
The issue pertains to a bug in the Ed25519 elliptic curve implementation within Google's End-to-End encryption project, specifically concerning the `isInfinity()` function.
The problem occurs when using the Ed25519 curve in cryptographic operations. The function `isInfinity()` was incorrectly applied, which fails due to the curve's unique properties where the Z coordinate is never zero.
- **Defect:**
The `isInfinity()` function should not be used for Ed25519. Instead, `isIdentity()` is recommended for verifying the public key.
- **Impact:**
The bug in the Ed25519 implementation caused the `isInfinity()` check to fail incorrectly. The issue was identified, and the correct function, `isIdentity()`, was suggested for use instead. The bug does not lead to security vulnerabilities but was an implementation flaw in the cryptographic logic.
- **Code Snippet:**
```javascript
function testCurve25519Order() {
  var params = e2e.ecc.DomainParam.fromCurve(
      e2e.ecc.PrimeCurve.CURVE_25519);
  var base = params.g;
  var order = params.n;
  assertTrue(base.multiply(order).isInfinity());
  assertFalse(base.multiply(order.subtract(e2e.BigNum.ONE)).isInfinity());
}
```
This code was intended for Curve25519 but failed when adapted for Ed25519 due to the inappropriate use of `isInfinity()`.
[GitHub issue](https://github.com/google/end-to-end/issues/340).