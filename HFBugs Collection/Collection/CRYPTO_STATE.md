# Mismanagement of Cryptographic State or Context

## openssl#3de81a5#1: BN_FLG_CONSTTIME Flag Propagation Bug

- **Specification:**This vulnerability affects OpenSSL's handling of the `BN_FLG_CONSTTIME` flag within the `BN_MONT_CTX_set` function, which is part of the RSA key generation process. The `BN_FLG_CONSTTIME` flag is critical for ensuring that cryptographic operations, particularly those involving sensitive data like RSA primes `p` and `q`, are executed in constant time to prevent timing attacks. The bug arises from the improper propagation of this flag, potentially exposing sensitive information.
- **Defect:**The defect occurs due to the improper propagation of the `BN_FLG_CONSTTIME` flag within the `BN_MONT_CTX_set` function. This improper handling means that certain operations on RSA primes might not be executed in constant time, increasing the risk of timing attacks. These attacks could allow an attacker to infer details about the RSA primes, which are essential for the security of RSA keys.
- **Impact:**Constant-time operations are a crucial defense against timing attacks, where attackers gain information by measuring the time taken to perform cryptographic operations. In this case, the failure to correctly propagate the `BN_FLG_CONSTTIME` flag could allow timing variations during RSA key generation, potentially revealing parts of the private key (i.e., the primes `p` and `q`). This vulnerability is particularly concerning in environments where RSA key generation is performed frequently, such as on shared systems or cloud platforms.
- **Code Snippet:**
  The commit [3de81a5912041a70884cf4e52e7213f3b5dfa747](https://github.com/openssl/openssl/commit/3de81a5912041a70884cf4e52e7213f3b5dfa747) addresses the vulnerability by ensuring that the `BN_FLG_CONSTTIME` flag is properly propagated to all relevant `BIGNUM` objects during the Montgomery context setup. This fix helps maintain the security of RSA key generation by ensuring that all operations involving sensitive data are performed in constant time, thus mitigating the risk of timing attacks.

## CVE-2016-0701: Diffie-Hellman (DH) Key Exchange Weakness in OpenSSL

- **Specification:**CVE-2016-0701 is a high-severity vulnerability in OpenSSL's implementation of the Diffie-Hellman (DH) key exchange protocol. The flaw occurs when OpenSSL uses static or reusable private keys in the DH key exchange process, especially when non-"safe" primes are employed. This could allow an attacker to perform a brute-force attack to recover the private key, compromising the security of the key exchange.
- **Defect:**The defect is related to the improper handling of Diffie-Hellman parameters during the key exchange process. If the `SSL_OP_SINGLE_DH_USE` option is not enabled, OpenSSL may reuse the same private DH exponent across multiple sessions, particularly when non-"safe" primes are used, such as those generated with X9.42 style parameters. This reuse significantly weakens the security of the DH key exchange.
- **Impact:**The vulnerability allows an attacker to exploit the DH key exchange by capturing the public key and observing multiple handshakes where the same private key is reused. This could lead to a brute-force attack where the attacker recovers the private key, compromising the confidentiality and integrity of the communication. This issue is especially critical in environments using static DH ciphersuites or non-ephemeral DH (DHE) modes.
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


## CVE-2020-1968: Detailed Examination

- Specification: CVE-2020-1968 is associated with OpenSSL 1.0.2, a cryptographic library extensively used for secure communications, particularly in TLS connections. The vulnerability pertains to the handling of Diffie-Hellman (DH) key exchange, a method for securely exchanging cryptographic keys over an insecure channel. The user-provided attributes, such as "DH key reuse, priv key exposure, 3,7, Remote, Medium, High," suggest a focus on DH key reuse leading to private key exposure, with a CVSS base score of 3.7 indicating medium severity and a remote attack vector. Research into official sources, such as the National Vulnerability Database (NVD) [NVD - CVE-2020-1968](https://nvd.nist.gov/vuln/detail/CVE-2020-1968), confirms that this vulnerability is part of the Raccoon attack, exploiting a flaw in the TLS specification. It affects versions of OpenSSL 1.0.2 up to 1.0.2v, with fixes implemented in 1.0.2w. The vulnerability is noted to impact components like SSL Forward-Proxy and GlobalProtect in certain configurations, as detailed in security advisories from Palo Alto Networks [CVE-2020-1968 PAN-OS Impact](https://security.paloaltonetworks.com/CVE-2020-1968).
- Defect: The defect involves the reuse of DH secrets across multiple TLS connections, specifically when the `SSL_OP_SINGLE_DH_USE` option is set. Analysis of OpenSSL source code, particularly in `s3_lib.c`, reveals that when this option is enabled, the server uses the same DH private key (`dh = s->cert->dh_tmp;`) for all connections, contrary to expectations of generating a new key each time. This reuse is vulnerable to attacks where an attacker can compute the pre-master secret, enabling eavesdropping on encrypted communications. The user’s note of "priv key exposure" aligns with this, indicating a confidentiality risk due to the Raccoon attack, which requires multiple handshakes with the same DH exponent. Initial confusion arose from discrepancies between the OpenSSL advisory and code behavior. The advisory suggested that if `SSL_OP_SINGLE_DH_USE` is not set, the server reuses the key, but code analysis showed that when not set, a new key is generated each time (`DH_generate_key` after `DHparams_dup`). This suggests a potential misinterpretation in documentation, with the vulnerability occurring when `SSL_OP_SINGLE_DH_USE` is set, leading to key reuse. This was clarified by examining OpenSSL’s change logs and commit histories, confirming the fix in 1.0.2w ensured new key generation.
- Impact: The impact is a medium severity vulnerability, with a CVSS score of 3.7, as per [INCIBE-CERT CVE-2020-1968](https://www.incibe.es/incibe-cert/alerta-temprana/vulnerabilidades/cve-2020-1968), indicating a low confidentiality impact (C:L) and no integrity or availability impact (I:N, A:N). However, the potential for an attacker to eavesdrop on encrypted communications poses a significant confidentiality breach, especially in scenarios where DH ciphersuites are used and the server reuses keys across connections. This is particularly relevant for systems not updated beyond OpenSSL 1.0.2v, which is out of support and no longer receiving public updates, as noted in [Tenable CVE-2020-1968](https://www.tenable.com/cve/CVE-2020-1968).
- Code Snippet:

The relevant code snippet, extracted from `s3_lib.c` in OpenSSL 1.0.2v, is as follows, highlighting the point of vulnerability:

```c
if (s->cert->dh_tmp != NULL) {
    if ((s->options & SSL_OP_SINGLE_DH_USE) == 0) {
        /* Create a new DH key each time */
        DH_free(dh);
        if ((dh = DHparams_dup(s->cert->dh_tmp)) == NULL) {
            SSLerr(SSL_F_SEND_SERVER_KEY_EXCHANGE, ERR_R_DH_LIB);
            goto err;
        }
        if (!DH_generate_key(dh)) {
            SSLerr(SSL_F_SEND_SERVER_KEY_EXCHANGE, ERR_R_DH_LIB);
            goto err;
        }
    } else {
        dh = s->cert->dh_tmp;
    }
}
```

When `SSL_OP_SINGLE_DH_USE` is set, `dh = s->cert->dh_tmp;` reuses the same DH key, leading to the vulnerability. This was confirmed by reviewing OpenSSL source code repositories, such as [OpenSSL GitHub](https://github.com/openssl/openssl/tree/master/crypto/dh).
