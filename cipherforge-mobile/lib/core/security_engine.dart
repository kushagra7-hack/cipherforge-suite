// =============================================================================
// SecurityEngine — Core Cryptographic Operations
// =============================================================================
//
// This module is the cryptographic heart of the application. It provides:
//
// 1. **Argon2id Key Derivation Function (KDF)**
//    - Derives a 256-bit master key from a user's master password + random salt.
//    - Argon2id is the OWASP-recommended KDF, combining Argon2i's resistance
//      to side-channel attacks with Argon2d's resistance to GPU cracking.
//    - Parameters: 3 iterations, 65536 KB memory, 4 parallelism lanes.
//
// 2. **AES-256-GCM Authenticated Encryption**
//    - Encrypts plaintext with a random 96-bit IV (nonce) prepended to output.
//    - GCM mode provides both confidentiality AND integrity (AEAD).
//    - Output format: [12-byte IV][ciphertext][16-byte GCM tag]
//
// 3. **Secure Password Generation**
//    - Uses dart:math Random.secure() backed by OS CSPRNG (/dev/urandom, etc.).
//    - NEVER uses Math.random() or unseeded Random() — those are predictable.
//
// 4. **Shannon Entropy Calculation**
//    - Measures password strength in bits of entropy.
//    - Weak < 50 bits, Good 50-70 bits, Excellent > 70 bits.
//
// SECURITY INVARIANTS:
// - All random values come from Random.secure() (CSPRNG).
// - Master key is always Uint8List, never converted to String.
// - IV is never reused — generated fresh for every encryption operation.
// - GCM tag is always verified during decryption (implicit in GCM mode).
// =============================================================================

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// The core cryptographic engine for all security operations.
///
/// This class is intentionally stateless — it takes keys and data as parameters
/// rather than storing them internally. This prevents accidental key retention
/// in memory and makes the security boundary explicit.
class SecurityEngine {
  // ===========================================================================
  // CONSTANTS
  // ===========================================================================

  /// Length of the AES key in bytes (256 bits = 32 bytes).
  /// AES-256 provides a 128-bit security level against brute force.
  static const int _aesKeyLength = 32;

  /// Length of the GCM initialization vector (IV/nonce) in bytes.
  /// NIST SP 800-38D recommends 96 bits (12 bytes) for GCM IVs.
  /// Using a random 96-bit IV gives a collision probability of ~2^-48
  /// after 2^32 encryptions, which is acceptable for our use case.
  static const int _gcmIvLength = 12;

  /// Length of the GCM authentication tag in bits.
  /// 128-bit tags provide the maximum integrity assurance.
  static const int _gcmTagLengthBits = 128;

  /// Salt length in bytes for Argon2id.
  /// 16 bytes (128 bits) exceeds the OWASP minimum of 128 bits.
  static const int saltLength = 16;

  // ---------------------------------------------------------------------------
  // Argon2id parameters — tuned per OWASP recommendations.
  // These values balance security vs. mobile device performance.
  // ---------------------------------------------------------------------------

  /// Number of Argon2id iterations (time cost).
  /// Higher values increase computation time linearly.
  /// 3 iterations is the OWASP minimum for Argon2id with 64MB memory.
  static const int _argon2Iterations = 3;

  /// Memory cost in KB for Argon2id.
  /// 65536 KB = 64 MB. This is the OWASP-recommended minimum for Argon2id
  /// when using 3 iterations. Higher memory makes GPU attacks more expensive.
  static const int _argon2MemoryKB = 65536;

  /// Parallelism lanes for Argon2id.
  /// 4 lanes allows the KDF to utilize multiple CPU cores.
  static const int _argon2Parallelism = 4;

  /// Desired output key length from Argon2id in bytes.
  /// 32 bytes = 256 bits, matching our AES key length.
  static const int _argon2KeyLength = 32;

  // ===========================================================================
  // CRYPTOGRAPHICALLY SECURE RANDOM NUMBER GENERATOR
  // ===========================================================================

  /// The CSPRNG instance used for all random value generation.
  ///
  /// [Random.secure()] delegates to the platform's CSPRNG:
  /// - Linux/Android: /dev/urandom
  /// - iOS/macOS: SecRandomCopyBytes
  /// - Windows: BCryptGenRandom
  ///
  /// CRITICAL: Never replace this with Random() or Random(seed) — those use
  /// a predictable PRNG that would completely compromise all security.
  static final Random _secureRandom = Random.secure();

  // ===========================================================================
  // KEY DERIVATION
  // ===========================================================================

  /// Derives a 256-bit master key from a password and salt using Argon2id.
  ///
  /// Argon2id combines the side-channel resistance of Argon2i (data-independent
  /// memory access in the first pass) with the GPU-resistance of Argon2d
  /// (data-dependent memory access in subsequent passes).
  ///
  /// [password] — The user's master password as a UTF-8 string.
  /// [salt] — A random 16-byte salt, unique per user. Must be stored alongside
  ///          the auth hash but is NOT secret (its purpose is to prevent
  ///          rainbow table attacks and ensure identical passwords produce
  ///          different hashes).
  ///
  /// Returns a 32-byte (256-bit) derived key as [Uint8List].
  /// The caller is responsible for zeroing this key when done.
  static Uint8List deriveKey(String password, Uint8List salt) {
    // Encode the password as UTF-8 bytes.
    // We work with bytes, not strings, for the KDF input.
    final passwordBytes = utf8.encode(password);

    // Configure the Argon2id parameters.
    final parameters = Argon2Parameters(
      Argon2Parameters.ARGON2_id, // Argon2id variant (hybrid)
      salt, // Random salt
      desiredKeyLength: _argon2KeyLength, // 32 bytes output
      iterations: _argon2Iterations, // Time cost
      memory: _argon2MemoryKB, // Memory cost in KB
      lanes: _argon2Parallelism, // Parallelism
    );

    // Instantiate the Argon2 key derivator from pointycastle.
    final argon2 = Argon2BytesGenerator();
    argon2.init(parameters);

    // Derive the key. The output buffer must be exactly _argon2KeyLength bytes.
    final derivedKey = Uint8List(_argon2KeyLength);
    argon2.generateBytes(passwordBytes, derivedKey);

    return derivedKey;
  }

  /// Generates a cryptographically random salt for Argon2id.
  ///
  /// The salt MUST be stored (in flutter_secure_storage) so that the same
  /// master password always derives the same key. The salt is not secret —
  /// it only needs to be unique per user.
  static Uint8List generateSalt() {
    return _generateSecureRandomBytes(saltLength);
  }

  // ===========================================================================
  // AES-256-GCM AUTHENTICATED ENCRYPTION
  // ===========================================================================

  /// Encrypts [plaintext] using AES-256-GCM with the given [key].
  ///
  /// Output format: [12-byte IV || ciphertext || 16-byte GCM tag]
  ///
  /// GCM (Galois/Counter Mode) provides:
  /// - **Confidentiality**: AES in counter mode encrypts the data.
  /// - **Integrity**: The GCM tag detects any tampering with the ciphertext.
  /// - **Authenticity**: Only someone with the key could have produced the tag.
  ///
  /// The IV is generated randomly for each encryption and prepended to the
  /// output. This is safe because GCM only requires IV uniqueness per key,
  /// and a random 96-bit IV has negligible collision probability for our
  /// volume of operations.
  ///
  /// [plaintext] — The data to encrypt, as a UTF-8 string.
  /// [key] — The 256-bit AES key as a 32-byte [Uint8List].
  ///
  /// Returns the concatenation [IV || ciphertext || tag] as [Uint8List].
  /// Throws if the key is not exactly 32 bytes.
  static Uint8List encrypt(String plaintext, Uint8List key) {
    assert(key.length == _aesKeyLength,
        'AES-256 requires a 32-byte key, got ${key.length}');

    // Generate a fresh random IV for this encryption operation.
    // CRITICAL: Never reuse an IV with the same key — this would completely
    // break GCM's confidentiality and integrity guarantees.
    final iv = _generateSecureRandomBytes(_gcmIvLength);

    // Configure the AES-GCM cipher.
    final cipher = GCMBlockCipher(AESEngine())
      ..init(
        true, // true = encrypt mode
        AEADParameters(
          KeyParameter(key), // The 256-bit key
          _gcmTagLengthBits, // 128-bit authentication tag
          iv, // The random IV/nonce
          Uint8List(0), // No additional authenticated data (AAD)
        ),
      );

    // Encode plaintext to UTF-8 bytes.
    final plaintextBytes = utf8.encode(plaintext);

    // Allocate output buffer. GCM output = plaintext length + tag length.
    // The tag is appended automatically by pointycastle's GCM implementation.
    final ciphertextWithTag = Uint8List(
      plaintextBytes.length + cipher.macSize, // macSize = tag length in bytes
    );

    // Process the plaintext through the cipher.
    var offset = 0;
    offset += cipher.processBytes(
      Uint8List.fromList(plaintextBytes),
      0,
      plaintextBytes.length,
      ciphertextWithTag,
      0,
    );

    // Finalize — this computes and appends the GCM authentication tag.
    cipher.doFinal(ciphertextWithTag, offset);

    // Prepend the IV to the ciphertext+tag so the decryptor can extract it.
    // Final output format: [IV (12 bytes) || ciphertext || tag (16 bytes)]
    final result = Uint8List(iv.length + ciphertextWithTag.length);
    result.setAll(0, iv);
    result.setAll(iv.length, ciphertextWithTag);

    return result;
  }

  /// Decrypts data produced by [encrypt] using AES-256-GCM.
  ///
  /// Input format: [12-byte IV || ciphertext || 16-byte GCM tag]
  ///
  /// This method:
  /// 1. Extracts the IV from the first 12 bytes.
  /// 2. Passes the remaining bytes (ciphertext + tag) to GCM decryption.
  /// 3. GCM automatically verifies the authentication tag.
  /// 4. If the tag verification fails (data tampered), an exception is thrown.
  ///
  /// [encryptedData] — The output from [encrypt]: IV || ciphertext || tag.
  /// [key] — The same 256-bit AES key used for encryption.
  ///
  /// Returns the decrypted plaintext as a UTF-8 [String].
  /// Throws [InvalidCipherTextException] if the authentication tag is invalid
  /// (indicating the ciphertext was tampered with or the wrong key was used).
  static String decrypt(Uint8List encryptedData, Uint8List key) {
    assert(key.length == _aesKeyLength,
        'AES-256 requires a 32-byte key, got ${key.length}');

    // Extract the IV from the first 12 bytes.
    final iv = encryptedData.sublist(0, _gcmIvLength);

    // The remainder is ciphertext + GCM tag.
    final ciphertextWithTag = encryptedData.sublist(_gcmIvLength);

    // Configure the AES-GCM cipher for decryption.
    final cipher = GCMBlockCipher(AESEngine())
      ..init(
        false, // false = decrypt mode
        AEADParameters(
          KeyParameter(key),
          _gcmTagLengthBits,
          iv,
          Uint8List(0), // No AAD
        ),
      );

    // Allocate output buffer for the plaintext.
    // Output length = ciphertextWithTag length - tag length.
    final plaintext = Uint8List(
      ciphertextWithTag.length - cipher.macSize,
    );

    // Process the ciphertext through the cipher.
    var offset = 0;
    offset += cipher.processBytes(
      ciphertextWithTag,
      0,
      ciphertextWithTag.length,
      plaintext,
      0,
    );

    // Finalize — this verifies the GCM authentication tag.
    // If the tag doesn't match, doFinal throws InvalidCipherTextException.
    // This protects against ciphertext tampering and wrong-key scenarios.
    cipher.doFinal(plaintext, offset);

    return utf8.decode(plaintext);
  }

  // ===========================================================================
  // SECURE PASSWORD GENERATION
  // ===========================================================================

  /// Generates a cryptographically secure random password.
  ///
  /// The password is constructed by selecting characters uniformly at random
  /// from the specified character pools using [Random.secure()].
  ///
  /// [length] — Desired password length. Minimum 8, default 20.
  /// [includeUppercase] — Include A-Z characters.
  /// [includeLowercase] — Include a-z characters.
  /// [includeDigits] — Include 0-9 characters.
  /// [includeSpecial] — Include special characters (!@#\$%^&*...).
  ///
  /// Returns a random password string.
  /// Throws [ArgumentError] if length < 8 or no character sets are selected.
  static String generatePassword({
    int length = 20,
    bool includeUppercase = true,
    bool includeLowercase = true,
    bool includeDigits = true,
    bool includeSpecial = true,
  }) {
    // Enforce minimum length for security.
    if (length < 8) {
      throw ArgumentError('Password length must be at least 8 characters');
    }

    // Build the character pool from selected character sets.
    final StringBuffer charPool = StringBuffer();

    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const digits = '0123456789';
    const special = '!@#\$%^&*()_+-=[]{}|;:,.<>?';

    if (includeUppercase) charPool.write(uppercase);
    if (includeLowercase) charPool.write(lowercase);
    if (includeDigits) charPool.write(digits);
    if (includeSpecial) charPool.write(special);

    final chars = charPool.toString();
    if (chars.isEmpty) {
      throw ArgumentError('At least one character set must be selected');
    }

    // Generate the password using CSPRNG.
    // Each character is selected uniformly at random from the pool.
    final password = List.generate(
      length,
      (_) => chars[_secureRandom.nextInt(chars.length)],
    ).join();

    // Ensure at least one character from each selected set is present.
    // This is a usability feature — without it, a generated password might
    // randomly exclude a character set, which could fail site requirements.
    // We verify and regenerate if needed (statistically rare for length >= 12).
    if (_meetsRequirements(
      password,
      includeUppercase: includeUppercase,
      includeLowercase: includeLowercase,
      includeDigits: includeDigits,
      includeSpecial: includeSpecial,
    )) {
      return password;
    }

    // If requirements not met (very rare), inject one of each required type
    // at random positions. This is more efficient than regenerating.
    return _enforceCharacterRequirements(
      password,
      includeUppercase: includeUppercase,
      includeLowercase: includeLowercase,
      includeDigits: includeDigits,
      includeSpecial: includeSpecial,
    );
  }

  /// Checks if a password contains at least one character from each
  /// required character set.
  static bool _meetsRequirements(
    String password, {
    required bool includeUppercase,
    required bool includeLowercase,
    required bool includeDigits,
    required bool includeSpecial,
  }) {
    if (includeUppercase && !password.contains(RegExp(r'[A-Z]'))) return false;
    if (includeLowercase && !password.contains(RegExp(r'[a-z]'))) return false;
    if (includeDigits && !password.contains(RegExp(r'[0-9]'))) return false;
    if (includeSpecial &&
        !password.contains(RegExp(r'[!@#\$%^&*()_+\-=\[\]{}|;:,.<>?]'))) {
      return false;
    }
    return true;
  }

  /// Injects one character from each required set at random positions.
  ///
  /// This guarantees the password meets all character requirements
  /// without reducing entropy significantly (we're replacing at most
  /// 4 characters out of 20+).
  static String _enforceCharacterRequirements(
    String password, {
    required bool includeUppercase,
    required bool includeLowercase,
    required bool includeDigits,
    required bool includeSpecial,
  }) {
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const digits = '0123456789';
    const special = '!@#\$%^&*()_+-=[]{}|;:,.<>?';

    final chars = password.split('');

    // Collect positions where we'll inject required characters.
    // Use a set to avoid replacing the same position twice.
    final positions = <int>{};

    void injectIfNeeded(bool needed, String pool, RegExp test) {
      if (needed && !password.contains(test)) {
        int pos;
        do {
          pos = _secureRandom.nextInt(chars.length);
        } while (positions.contains(pos));
        positions.add(pos);
        chars[pos] = pool[_secureRandom.nextInt(pool.length)];
      }
    }

    injectIfNeeded(includeUppercase, uppercase, RegExp(r'[A-Z]'));
    injectIfNeeded(includeLowercase, lowercase, RegExp(r'[a-z]'));
    injectIfNeeded(includeDigits, digits, RegExp(r'[0-9]'));
    injectIfNeeded(
        includeSpecial, special, RegExp(r'[!@#\$%^&*()_+\-=\[\]{}|;:,.<>?]'));

    return chars.join();
  }

  // ===========================================================================
  // SHANNON ENTROPY CALCULATION
  // ===========================================================================

  /// Calculates the Shannon entropy of a password in bits.
  ///
  /// Shannon entropy measures the information content based on character
  /// frequency distribution. It estimates how many bits would be needed
  /// to encode the password optimally.
  ///
  /// Strength thresholds:
  /// - **Weak**: < 50 bits — vulnerable to offline brute force
  /// - **Good**: 50–70 bits — adequate for most purposes
  /// - **Excellent**: > 70 bits — resistant to all known attacks
  ///
  /// Note: This is a statistical measure, not a security guarantee.
  /// A password like "aaaaaaaaaa" has 0 bits of entropy despite being 10
  /// characters long. Real-world password strength also depends on whether
  /// the password appears in dictionary/breach databases.
  ///
  /// [password] — The password to analyze.
  ///
  /// Returns the entropy in bits as a [double].
  static double calculateShannonEntropy(String password) {
    if (password.isEmpty) return 0.0;

    final length = password.length;

    // Count the frequency of each character.
    final frequencies = <String, int>{};
    for (final char in password.split('')) {
      frequencies[char] = (frequencies[char] ?? 0) + 1;
    }

    // Calculate Shannon entropy: H = -Σ p(x) * log2(p(x))
    // where p(x) is the probability of each unique character.
    double entropy = 0.0;
    for (final count in frequencies.values) {
      final probability = count / length;
      // log2(p) = ln(p) / ln(2)
      entropy -= probability * (log(probability) / ln2);
    }

    // Multiply by password length to get total entropy in bits.
    // This gives a more useful measure than per-character entropy.
    return entropy * length;
  }

  /// Returns a human-readable strength label based on entropy bits.
  ///
  /// Thresholds align with NIST SP 800-63B guidance:
  /// - Weak: easily crackable with commodity hardware
  /// - Good: resistant to online attacks, marginal offline
  /// - Excellent: resistant to offline attacks with dedicated hardware
  static String entropyToStrengthLabel(double entropyBits) {
    if (entropyBits < 50.0) return 'Weak';
    if (entropyBits <= 70.0) return 'Good';
    return 'Excellent';
  }

  // ===========================================================================
  // UTILITY METHODS
  // ===========================================================================

  /// Generates [length] bytes of cryptographically secure random data.
  ///
  /// Uses [Random.secure()] which delegates to the platform CSPRNG.
  /// This is the ONLY source of randomness in the entire application.
  static Uint8List _generateSecureRandomBytes(int length) {
    return Uint8List.fromList(
      List.generate(length, (_) => _secureRandom.nextInt(256)),
    );
  }

  /// Securely zeroes a [Uint8List] by overwriting all bytes with 0x00.
  ///
  /// This should be called on any key material when it is no longer needed.
  /// While Dart's garbage collector may not immediately free memory, zeroing
  /// the buffer reduces the window of vulnerability for memory dump attacks.
  ///
  /// Note: This is a best-effort measure. The Dart VM may have copied the
  /// data during GC compaction, and we cannot guarantee those copies are
  /// zeroed. For maximum security, the master key should be held in
  /// platform-native secure memory (Android Keystore, iOS Secure Enclave).
  static void secureZero(Uint8List data) {
    for (var i = 0; i < data.length; i++) {
      data[i] = 0;
    }
  }

  /// Generates a secure random [Uint8List] of the specified [length].
  ///
  /// Public wrapper around [_generateSecureRandomBytes] for use by other
  /// modules that need cryptographic randomness (e.g., for generating
  /// intermediate keys in hardware vault binding).
  static Uint8List generateSecureRandomBytes(int length) {
    return _generateSecureRandomBytes(length);
  }
}
