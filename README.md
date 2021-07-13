# ROLL13

ROLL13 is a pure python implementation of a TLS 1.3 client, hand-rolled from first principles, including all cryptographic operations. Specifically, it implements the `TLS_AES_128_GCM_SHA256` cipher suite.

### Motivations

I wanted to learn about the protocols and cryptography involved, in excruciating detail. This is explicitly **NOT** intended to be complete, secure, or fast. Although *correctness* is a goal, I can't make any guarantees there either.

As a secondary goal, it proves that modern cryptography standards are still accessible to mere mortals.

The code is intended to be as readable as possible.

### Implemented Specs

The following tree of bullet points lists all the standards/specifications referenced in the code.

- [RFC 8446 - The Transport Layer Security (TLS) Protocol Version 1.3](https://datatracker.ietf.org/doc/html/rfc8446) (2018)
  - [RFC 8032 - Edwards-Curve Digital Signature Algorithm (EdDSA)](https://datatracker.ietf.org/doc/html/rfc8032) (2017)
  - [RFC 5116 - An Interface and Algorithms for Authenticated Encryption](https://datatracker.ietf.org/doc/html/rfc5116) (2008)
    - [NIST SP 800-38D - Recommendation for Block Cipher Modes of Operation:  Galois/Counter Mode (GCM) and GMAC](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) (2007)
      - [FIPS 197 - Announcing the ADVANCED ENCRYPTION STANDARD (AES)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf) (2001)
