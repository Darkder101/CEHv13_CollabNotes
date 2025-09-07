# Cryptography Concepts and Different Encryption Algorithms

## 1. Objectives of Cryptography

### 1.1 Confidentiality
- Ensures that information is accessible only to those authorized to access it
- Prevents unauthorized disclosure of data
- Achieved through encryption techniques

### 1.2 Integrity
- Ensures that data has not been altered or modified during transmission or storage
- Protects against unauthorized modification
- Implemented using hash functions and digital signatures

### 1.3 Authentication
- Verifies the identity of users, systems, or entities
- Ensures that the claimed identity is genuine
- Achieved through digital certificates and authentication protocols

### 1.4 Non-repudiation
- Prevents denial of actions or transactions
- Provides proof of origin and delivery
- Implemented using digital signatures and timestamps

## 2. Cryptography Process

### 2.1 Encryption Process
```
Plaintext → Encryption Algorithm + Key → Ciphertext
```

### 2.2 Decryption Process
```
Ciphertext → Decryption Algorithm + Key → Plaintext
```

### 2.3 Key Components
- **Plaintext**: Original readable data
- **Ciphertext**: Encrypted unreadable data
- **Key**: Secret parameter used in encryption/decryption
- **Algorithm**: Mathematical function for encryption/decryption

## 3. Types of Cryptography

### 3.1 Symmetric Encryption
- **Definition**: Uses the same key for both encryption and decryption
- **Key Characteristic**: Single shared secret key
- **Speed**: Fast encryption/decryption process
- **Key Distribution**: Major challenge - secure key exchange

#### Strengths of Symmetric Encryption:
- Fast processing speed
- Efficient for bulk data encryption
- Low computational overhead
- Suitable for real-time applications

#### Weaknesses of Symmetric Encryption:
- Key distribution problem
- Key management complexity
- Lack of non-repudiation
- Scalability issues (n² keys for n users)

### 3.2 Asymmetric Encryption
- **Definition**: Uses different keys for encryption and decryption
- **Key Characteristic**: Public-private key pairs
- **Speed**: Slower than symmetric encryption
- **Key Distribution**: Solved through public key distribution

#### Strengths of Asymmetric Encryption:
- Solves key distribution problem
- Provides non-repudiation
- Digital signatures capability
- Better scalability (2n keys for n users)

#### Weaknesses of Asymmetric Encryption:
- Computationally intensive
- Slower processing speed
- Complex key management
- Vulnerable to quantum computing attacks

## 4. Government Access to Keys

### 4.1 Key Escrow
- Government agencies hold copies of encryption keys
- Used for law enforcement and national security
- Controversial due to privacy concerns

### 4.2 Key Recovery
- Ability to recover lost or forgotten keys
- Required for business continuity
- Often mandated by regulations

## 5. Ciphers Classification

### 5.1 Classical Ciphers

#### 5.1.1 Substitution Cipher
- **Caesar Cipher**: Shifts letters by fixed positions
- **Monoalphabetic**: Each letter replaced by another letter
- **Polyalphabetic**: Uses multiple substitution alphabets
- **Example**: ROT13 (rotate by 13 positions)

#### 5.1.2 Transposition Cipher
- Rearranges the order of characters
- **Columnar Transposition**: Writes text in columns
- **Rail Fence Cipher**: Zigzag pattern arrangement
- **Block Cipher**: Rearranges blocks of text

### 5.2 Modern Ciphers

#### 5.2.1 Based on Key Type

**Symmetric-Key Algorithms:**
- DES, AES, Blowfish, RC4
- Single key for encryption/decryption

**Asymmetric-Key Algorithms:**
- RSA, ECC, Diffie-Hellman
- Public-private key pairs

#### 5.2.2 Based on Input Data

**Block Cipher:**
- Processes fixed-size blocks of data
- Examples: AES (128-bit blocks), DES (64-bit blocks)
- Uses padding for incomplete blocks

**Stream Cipher:**
- Processes data bit by bit or byte by byte
- Examples: RC4, ChaCha20
- Faster for real-time applications

## 6. Symmetric Encryption Algorithms

### 6.1 Data Encryption Standard (DES)
- **Key Size**: 56 bits (8 parity bits)
- **Block Size**: 64 bits
- **Rounds**: 16 Feistel rounds
- **Status**: Deprecated due to small key size
- **Vulnerability**: Susceptible to brute force attacks

### 6.2 Triple Data Encryption Standard (3DES)
- **Key Size**: 112 or 168 bits
- **Process**: Encrypt-Decrypt-Encrypt (EDE)
- **Variants**: 3DES-EEE, 3DES-EDE
- **Status**: Being phased out for AES

### 6.3 Advanced Encryption Standard (AES)
- **Key Sizes**: 128, 192, 256 bits
- **Block Size**: 128 bits
- **Rounds**: 10, 12, 14 (based on key size)
- **Algorithm**: Rijndael
- **Status**: Current NIST standard

### 6.4 RC Algorithms Family

#### RC4 (Rivest Cipher 4)
- **Type**: Stream cipher
- **Key Size**: 40-2048 bits
- **Usage**: WEP, WPA (deprecated)
- **Vulnerability**: Biased keystream

#### RC5 (Rivest Cipher 5)
- **Type**: Block cipher
- **Key Size**: 0-2048 bits
- **Block Size**: 32, 64, 128 bits
- **Rounds**: 0-255

#### RC6
- **Type**: Block cipher
- **Block Size**: 128 bits
- **Key Size**: 128, 192, 256 bits
- **Status**: AES finalist

### 6.5 Fish Family Ciphers

#### Blowfish
- **Key Size**: 32-448 bits
- **Block Size**: 64 bits
- **Rounds**: 16 Feistel rounds
- **Designer**: Bruce Schneier

#### Twofish
- **Key Size**: 128, 192, 256 bits
- **Block Size**: 128 bits
- **Rounds**: 16
- **Status**: AES finalist

#### Threefish
- **Block Sizes**: 256, 512, 1024 bits
- **Key Size**: Equal to block size
- **Usage**: Core of Skein hash function

### 6.6 Other Symmetric Algorithms

#### Serpent
- **Key Size**: 128, 192, 256 bits
- **Block Size**: 128 bits
- **Rounds**: 32
- **Status**: AES finalist (most secure)

#### TEA (Tiny Encryption Algorithm)
- **Key Size**: 128 bits
- **Block Size**: 64 bits
- **Rounds**: 32 (64 half-rounds)
- **Features**: Simple design, small code size

#### CAST-128
- **Key Size**: 40-128 bits
- **Block Size**: 64 bits
- **Rounds**: 12 or 16
- **Usage**: PGP, RFC 2144

#### GOST Block Cipher
- **Key Size**: 256 bits
- **Block Size**: 64 bits
- **Rounds**: 32
- **Origin**: Russian standard

#### Camellia
- **Key Size**: 128, 192, 256 bits
- **Block Size**: 128 bits
- **Rounds**: 18 or 24
- **Developer**: Mitsubishi and NTT

## 7. Asymmetric Encryption Algorithms

### 7.1 RSA (Rivest-Shamir-Adleman)
- **Key Size**: 1024, 2048, 3072, 4096 bits
- **Security**: Based on integer factorization
- **Usage**: Digital signatures, key exchange
- **Vulnerability**: Quantum computing threat

### 7.2 Diffie-Hellman Key Exchange
- **Purpose**: Key agreement protocol
- **Security**: Discrete logarithm problem
- **Variants**: Static DH, Ephemeral DH (DHE)
- **Vulnerability**: Man-in-the-middle attacks

### 7.3 Elliptic Curve Cryptography (ECC)
- **Key Size**: 160-571 bits (equivalent to 1024-15360 bit RSA)
- **Advantage**: Smaller keys, faster operations
- **Curves**: NIST P-256, Curve25519
- **Usage**: Mobile devices, IoT

### 7.4 Digital Signature Algorithm (DSA)
- **Key Size**: 512-3072 bits
- **Purpose**: Digital signatures only
- **Standard**: FIPS 186-4
- **Variants**: ECDSA (Elliptic Curve DSA)

### 7.5 ElGamal
- **Security**: Discrete logarithm problem
- **Features**: Probabilistic encryption
- **Usage**: Digital signatures, encryption
- **Characteristic**: Ciphertext expansion

## 8. DSA and Related Signature Schemes

### 8.1 DSA Process
1. **Key Generation**: Generate public/private key pair
2. **Signature Generation**: Create signature using private key
3. **Signature Verification**: Verify using public key

### 8.2 DSA Algorithm Steps
#### Signature Generation:
1. Generate random number k
2. Calculate r = (g^k mod p) mod q
3. Calculate s = (k^-1 × (H(m) + x×r)) mod q
4. Signature = (r, s)

#### Signature Verification:
1. Calculate w = s^-1 mod q
2. Calculate u1 = H(m) × w mod q
3. Calculate u2 = r × w mod q
4. Calculate v = ((g^u1 × y^u2) mod p) mod q
5. Verify if v = r

## 9. Message Digest Functions

### 9.1 One-Way Hash Functions
- **Property**: Easy to compute forward, infeasible to reverse
- **Applications**: Password storage, digital signatures
- **Requirements**: Pre-image resistance, collision resistance

### 9.2 Common Hash Functions

#### MD5 (Message Digest 5)
- **Output Size**: 128 bits
- **Status**: Cryptographically broken
- **Vulnerabilities**: Collision attacks
- **Usage**: Legacy systems (not recommended)

#### SHA-1 (Secure Hash Algorithm 1)
- **Output Size**: 160 bits
- **Status**: Deprecated (2017)
- **Vulnerabilities**: Collision attacks demonstrated

#### SHA-2 Family
- **SHA-224**: 224-bit output
- **SHA-256**: 256-bit output (most common)
- **SHA-384**: 384-bit output
- **SHA-512**: 512-bit output

#### SHA-3 (Keccak)
- **Output Sizes**: 224, 256, 384, 512 bits
- **Algorithm**: Different from SHA-2 (sponge construction)
- **Status**: NIST standard since 2015

### 9.3 Hash Function Tools

#### MD5 Calculator
- Command-line tools: `md5sum`, `md5`
- Online calculators available
- Usage: File integrity verification

#### HashMyFiles
- Windows utility for multiple hash algorithms
- Supports MD5, SHA-1, SHA-256, CRC32
- Batch processing capabilities

### 9.4 Multilayer Hashing
- **Purpose**: Enhanced security through multiple hash layers
- **Implementation**: Hash(Hash(data + salt))
- **Benefits**: Increased computational cost for attackers
- **Applications**: Password protection systems

## 10. Hardware-Based Encryption

### 10.1 TPM (Trusted Platform Module)
- **Purpose**: Hardware security chip
- **Functions**: Key generation, storage, attestation
- **Versions**: TPM 1.2, TPM 2.0
- **Applications**: BitLocker, device authentication

### 10.2 HSM (Hardware Security Module)
- **Purpose**: Dedicated cryptographic hardware
- **Types**: Network-based, PCIe cards, USB tokens
- **Features**: FIPS 140-2 Level 3/4 compliance
- **Applications**: Certificate authorities, SSL acceleration

### 10.3 Full Disk Encryption
- **Purpose**: Encrypt entire storage device
- **Technologies**: BitLocker, FileVault, LUKS
- **Key Management**: TPM integration, password-based
- **Performance**: Hardware acceleration support

## 11. Quantum Cryptography

### 11.1 Quantum Key Distribution (QKD)
- **Principle**: Quantum mechanics properties
- **Security**: Detection of eavesdropping
- **Protocols**: BB84, E91
- **Limitations**: Distance and practical deployment

### 11.2 Quantum-Safe Cryptography
- **Need**: Protection against quantum computers
- **Approaches**: Lattice-based, hash-based, code-based
- **Timeline**: NIST standardization process
- **Migration**: Hybrid classical-quantum systems

## 12. Advanced Encryption Technologies

### 12.1 Homomorphic Encryption
- **Capability**: Computation on encrypted data
- **Types**: Partially, somewhat, fully homomorphic
- **Applications**: Cloud computing, privacy-preserving analytics
- **Challenges**: Performance overhead

### 12.2 Post-Quantum Cryptography
- **Purpose**: Resistance to quantum attacks
- **Candidates**: CRYSTALS-Kyber, CRYSTALS-Dilithium
- **Status**: NIST standardization complete (2022)
- **Implementation**: Gradual migration required

### 12.3 Lightweight Cryptography
- **Target**: IoT and resource-constrained devices
- **Requirements**: Low power, small code size
- **Algorithms**: PRESENT, SIMON, SPECK
- **Standard**: NIST lightweight crypto standardization

## 13. Cipher Modes of Operation

### 13.1 Electronic Codebook (ECB) Mode
- **Operation**: Each block encrypted independently
- **Advantage**: Parallel processing, simple implementation
- **Disadvantage**: Pattern preservation, not semantically secure
- **Usage**: Not recommended for general use

### 13.2 Cipher Block Chaining (CBC) Mode
- **Operation**: Each block XORed with previous ciphertext
- **Initialization Vector (IV)**: Required for first block
- **Advantages**: Hides patterns, widely supported
- **Vulnerabilities**: Padding oracle attacks

### 13.3 Cipher Feedback (CFB) Mode
- **Operation**: Block cipher used as stream cipher
- **Self-synchronizing**: Error recovery capability
- **Variants**: CFB-1, CFB-8, CFB-64
- **Usage**: Character-oriented applications

### 13.4 Counter (CTR) Mode
- **Operation**: Counter encrypted and XORed with plaintext
- **Advantages**: Parallelizable, random access
- **Requirements**: Unique counter values
- **Performance**: High throughput

## 14. Modes of Authenticated Encryption

### 14.1 Encrypt-then-MAC
- **Process**: Encrypt plaintext, then MAC the ciphertext
- **Security**: Provides both confidentiality and authenticity
- **Standard**: Recommended approach
- **Examples**: TLS record protocol

### 14.2 Encrypt-and-MAC
- **Process**: Encrypt plaintext and MAC plaintext separately
- **Security**: May leak information about plaintext
- **Usage**: Some legacy protocols
- **Issues**: Not recommended

### 14.3 MAC-then-Encrypt
- **Process**: MAC the plaintext, then encrypt both
- **Security**: Vulnerable to padding oracle attacks
- **Examples**: Some implementations of SSL/TLS
- **Recommendation**: Generally not preferred

### 14.4 Authenticated Encryption (AE) Modes
- **GCM (Galois/Counter Mode)**: Fast, parallelizable
- **CCM (Counter with CBC-MAC)**: NIST standard
- **ChaCha20-Poly1305**: Modern stream cipher with MAC
- **OCB (Offset Codebook)**: High performance

## **Key CEH v13 Exam Points**

### **Critical Concepts**
1. **Symmetric vs Asymmetric**: Understand key differences, use cases, and performance trade-offs
2. **Hash Functions**: Master MD5, SHA family, and their security properties
3. **Digital Signatures**: Know RSA, DSA, ECDSA algorithms and verification process
4. **Block vs Stream Ciphers**: Differentiate encryption methods and applications
5. **Cipher Modes**: Understand ECB, CBC, CTR, GCM modes and their vulnerabilities
6. **Key Management**: Comprehend key generation, distribution, and storage
7. **Quantum Impact**: Recognize post-quantum cryptography requirements

### **Exam Focus Areas**
* **AES Implementation**: Key sizes, rounds, and security strength
* **RSA Mathematics**: Key generation, encryption/decryption process
* **Hash Collisions**: MD5/SHA-1 vulnerabilities and attack implications
* **PKI Components**: Certificate authorities, trust chains, revocation
* **TPM/HSM**: Hardware security modules and trusted computing
* **Quantum Threats**: Impact on current cryptographic systems
* **Compliance Standards**: FIPS 140-2, Common Criteria requirements

### **Practical Skills**
* Identify appropriate encryption algorithms for specific use cases
* Recognize cryptographic vulnerabilities in implementations
* Evaluate hash function security and collision resistance
* Understand certificate validation and trust establishment
* Assess quantum-safe migration strategies
* Implement proper key management practices
* Analyze cipher mode security properties and attack vectors
