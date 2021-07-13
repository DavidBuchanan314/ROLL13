# ROLL13

ROLL13 is a pure python implementation of a TLS 1.3 client, hand-rolled from first principles, including all cryptographic operations. It implements the `TLS_AES_128_GCM_SHA256` cipher suite, and secp256r1 (NIST P-256) for key exchange.

### Motivations

I wanted to learn about the protocols and cryptography involved, in excruciating detail. This is explicitly **NOT** intended to be complete, secure, or fast. Although *correctness* is a goal, I can't make any guarantees there either.

As a secondary goal, it proves that modern cryptography standards are still accessible to mere mortals.

The code is intended to be as readable as possible.

### Self-Imposed Restrictions

- No libraries. Everything is from scratch.
- No reading other peoples' implementations - only specifications. I'm slightly "tainted" in this regard, because I've spent a lot of time reading other peoples' code over the years. However, my goal is to translate the specifications into code as literally as possible.
- No magic numbers, except for those explicitly defined in a spec - and even then, they should be derived from first-principles, if possible.

### Implemented Specs

The following tree of bullet points lists all the standards/specifications referenced in the code.

- [RFC 8446 - The Transport Layer Security (TLS) Protocol Version 1.3](https://datatracker.ietf.org/doc/html/rfc8446) (2018)
  - [RFC 5116 - An Interface and Algorithms for Authenticated Encryption](https://datatracker.ietf.org/doc/html/rfc5116) (2008)
    - [NIST SP 800-38D - Recommendation for Block Cipher Modes of Operation:  Galois/Counter Mode (GCM) and GMAC](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) (2007)
      - [FIPS 197 - Announcing the ADVANCED ENCRYPTION STANDARD (AES)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf) (2001)

To recap, that includes the following cryptographic primitives:

 - SHA-256 hash function.
 - secp256r1 elliptic curves, for signatures and key exchange.
 - AES-128 symmetric encryption,
 - GCM, an authenticated block mode, used with AES.

### How much work would it take to make this competitive with e.g. OpenSSL?

- It needs exponentially more code, to implement the full TLS feature-set.
- It would need to be written in a language that isn't Python, to improve performance.
- The cryptographic implementations would need to be re-worked to prioritise performance (the current priority is readability). This typically results in much more complex code.
- It would need to be audited and tested by a team of professionals.
