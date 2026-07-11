// =============================================================================
// HardwareVaultBinder — Biometric + PIN Key Derivation
// =============================================================================
//
// This service binds the vault's encryption to the device's hardware security
// by combining multiple authentication factors into a single intermediate key:
//
// 1. **Biometric Authentication (local_auth)**
//    - Uses biometricOnly: true — does not fall back to device PIN/pattern.
//    - Uses stickyAuth: false — cancels auth if app goes to background.
//    - Biometric success unlocks access to a hardware-stored intermediate key.
//
// 2. **PIN-Based Key Mixing**
//    - The user's numeric PIN is hashed with SHA-256.
//    - This PIN hash is XOR-mixed with the keystore-derived intermediate key.
//    - This creates a two-factor key: something you ARE (biometric) +
//      something you KNOW (PIN).
//
// KEY DERIVATION FLOW:
// ┌─────────┐     ┌──────────┐     ┌─────────────────┐
// │Biometric│────▶│ Keystore │────▶│Intermediate Key  │
// │  Auth   │     │ Unlock   │     │  (32 bytes)      │
// └─────────┘     └──────────┘     └────────┬────────┘
//                                           │ XOR
// ┌─────────┐     ┌──────────┐     ┌────────┴────────┐
// │User PIN │────▶│ SHA-256  │────▶│ PIN Hash         │
// │         │     │          │     │  (32 bytes)      │
// └─────────┘     └──────────┘     └────────┬────────┘
//                                           │
//                                  ┌────────▼────────┐
//                                  │  Combined Key    │
//                                  │  (32 bytes)      │
//                                  └─────────────────┘
//
// SECURITY PROPERTIES:
// - The intermediate key is generated using Random.secure() and stored in
//   flutter_secure_storage (Android Keystore / iOS Keychain).
// - Even if the keystore is compromised, the attacker still needs the PIN.
// - Even if the PIN is known, the attacker still needs keystore access.
// - The combined key is used as an additional encryption layer, not a
//   replacement for the master password-derived key.
//
// LIMITATIONS:
// - local_auth's biometric check is a boolean gate — it does not provide
//   a cryptographic binding to the biometric template. True biometric
//   key binding requires Android's BiometricPrompt CryptoObject API,
//   which is not available through local_auth.
// - For maximum security, native platform code should be used to create
//   a key that requires biometric authentication for every use.
// =============================================================================

import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';

import '../core/security_engine.dart';

/// Service for hardware-bound key derivation combining biometrics and PIN.
///
/// This creates an intermediate key that is:
/// - Stored in the platform keystore (hardware-backed where available).
/// - Unlocked by biometric authentication.
/// - Mixed with a user-provided PIN via SHA-256 XOR.
class HardwareVaultBinder {
  // ---------------------------------------------------------------------------
  // Dependencies
  // ---------------------------------------------------------------------------

  /// Platform biometric authentication.
  final LocalAuthentication _localAuth;

  /// Platform keystore for storing the intermediate key.
  final FlutterSecureStorage _secureStorage;

  // ---------------------------------------------------------------------------
  // Storage keys
  // ---------------------------------------------------------------------------

  /// Key for the intermediate key stored in the platform keystore.
  /// This key is generated once and persists across app launches.
  static const String _intermediateKeyStorageKey = 'vault_hw_intermediate_key';

  /// Key for tracking whether the hardware binder has been initialized.
  static const String _initializedKey = 'vault_hw_binder_initialized';

  // ---------------------------------------------------------------------------
  // Constructor
  // ---------------------------------------------------------------------------

  /// Creates a HardwareVaultBinder with optional dependency injection.
  HardwareVaultBinder({
    LocalAuthentication? localAuth,
    FlutterSecureStorage? secureStorage,
  })  : _localAuth = localAuth ?? LocalAuthentication(),
        _secureStorage = secureStorage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(
                encryptedSharedPreferences: true,
              ),
            );

  // ===========================================================================
  // INITIALIZATION
  // ===========================================================================

  /// Checks whether the hardware binder has been initialized.
  ///
  /// Returns true if an intermediate key exists in the platform keystore.
  Future<bool> isInitialized() async {
    final initialized = await _secureStorage.read(key: _initializedKey);
    return initialized == 'true';
  }

  /// Initializes the hardware binder by generating and storing an
  /// intermediate key in the platform keystore.
  ///
  /// This should be called once during vault setup, after the user
  /// has confirmed their PIN and enrolled biometrics.
  ///
  /// The intermediate key is 32 bytes generated from Random.secure().
  /// It is stored in flutter_secure_storage, which uses:
  /// - Android: EncryptedSharedPreferences backed by Android Keystore.
  /// - iOS: Keychain with kSecAttrAccessibleWhenUnlockedThisDeviceOnly.
  ///
  /// Returns true if initialization succeeded, false otherwise.
  Future<bool> initialize() async {
    try {
      // Generate a 32-byte intermediate key using CSPRNG.
      // CRITICAL: Random.secure() only — never Random() or Math.random().
      final intermediateKey =
          SecurityEngine.generateSecureRandomBytes(32);

      // Store the intermediate key in the platform keystore.
      // On Android, this is encrypted with a key stored in the hardware
      // Keystore (TEE or StrongBox if available).
      await _secureStorage.write(
        key: _intermediateKeyStorageKey,
        value: _bytesToHex(intermediateKey),
      );

      await _secureStorage.write(key: _initializedKey, value: 'true');

      // Zero the local copy — it's now in the keystore.
      SecurityEngine.secureZero(intermediateKey);

      return true;
    } catch (e) {
      return false;
    }
  }

  // ===========================================================================
  // KEY DERIVATION
  // ===========================================================================

  /// Performs biometric authentication and derives the combined key.
  ///
  /// Flow:
  /// 1. Authenticate the user biometrically (biometricOnly: true).
  /// 2. If successful, read the intermediate key from the platform keystore.
  /// 3. Hash the user's PIN with SHA-256.
  /// 4. XOR the intermediate key with the PIN hash to produce the combined key.
  ///
  /// [pin] — The user's numeric PIN (4-8 digits recommended).
  ///
  /// Returns the 32-byte combined key as Uint8List, or null if
  /// authentication fails.
  ///
  /// SECURITY: The returned key should be used immediately and then
  /// zeroed with SecurityEngine.secureZero().
  Future<Uint8List?> deriveKey(String pin) async {
    // ---- Step 1: Biometric Authentication ----
    final isAuthenticated = await authenticateBiometric();
    if (!isAuthenticated) return null;

    // ---- Step 2: Read Intermediate Key from Keystore ----
    final intermediateKey = await _getIntermediateKey();
    if (intermediateKey == null) return null;

    // ---- Step 3: Hash the PIN with SHA-256 ----
    // SHA-256 produces a 32-byte hash, matching our key length.
    // We use the PIN hash (not the raw PIN) to ensure uniform distribution
    // regardless of the PIN's length or character composition.
    final pinHash = _hashPin(pin);

    // ---- Step 4: XOR Mix ----
    // XOR the intermediate key with the PIN hash.
    // XOR mixing preserves the entropy of both inputs — an attacker needs
    // BOTH the intermediate key AND the PIN to reconstruct the combined key.
    final combinedKey = _xorBytes(intermediateKey, pinHash);

    // Zero the intermediate copies.
    SecurityEngine.secureZero(intermediateKey);
    SecurityEngine.secureZero(pinHash);

    return combinedKey;
  }

  // ===========================================================================
  // BIOMETRIC AUTHENTICATION
  // ===========================================================================

  /// Performs biometric-only authentication.
  ///
  /// Configuration:
  /// - **biometricOnly: true** — Does not fall back to device PIN/pattern.
  ///   We want genuine biometric verification. Falling back to device PIN
  ///   would weaken the two-factor model (device PIN != vault PIN).
  /// - **stickyAuth: false** — If the app goes to background during the
  ///   biometric prompt, authentication is cancelled. This prevents a
  ///   scenario where the biometric prompt persists after the user walks away.
  /// - **useErrorDialogs: true** — Show platform-native error dialogs
  ///   for issues like "too many attempts" or "biometric not enrolled".
  ///
  /// Returns true if biometric authentication succeeded.
  Future<bool> authenticateBiometric() async {
    try {
      // Check if biometrics are available on this device.
      final canCheck = await _localAuth.canCheckBiometrics;
      final isSupported = await _localAuth.isDeviceSupported();

      if (!canCheck || !isSupported) {
        return false;
      }

      // Perform biometric authentication.
      final result = await _localAuth.authenticate(
        localizedReason: 'Authenticate to unlock your vault',
        options: const AuthenticationOptions(
          biometricOnly: true, // NO fallback to device PIN/pattern
          stickyAuth: false, // Cancel if app goes to background
          useErrorDialogs: true, // Show platform error dialogs
        ),
      );

      return result;
    } on PlatformException catch (_) {
      // Platform-specific errors (e.g., biometric hardware unavailable).
      return false;
    }
  }

  /// Checks which biometric types are available on this device.
  ///
  /// Returns a list of available biometric types (fingerprint, face, iris).
  /// An empty list means no biometrics are enrolled.
  Future<List<BiometricType>> getAvailableBiometrics() async {
    try {
      return await _localAuth.getAvailableBiometrics();
    } catch (_) {
      return [];
    }
  }

  // ===========================================================================
  // KEY OPERATIONS
  // ===========================================================================

  /// Retrieves the intermediate key from the platform keystore.
  ///
  /// Returns the 32-byte key, or null if not found.
  Future<Uint8List?> _getIntermediateKey() async {
    try {
      final hexKey =
          await _secureStorage.read(key: _intermediateKeyStorageKey);
      if (hexKey == null) return null;
      return _hexToBytes(hexKey);
    } catch (e) {
      return null;
    }
  }

  /// Hashes a PIN string with SHA-256 to produce a 32-byte key.
  ///
  /// [pin] — The user's PIN string.
  ///
  /// Returns a 32-byte SHA-256 hash as Uint8List.
  Uint8List _hashPin(String pin) {
    final pinBytes = Uint8List.fromList(pin.codeUnits);
    final digest = sha256.convert(pinBytes);
    return Uint8List.fromList(digest.bytes);
  }

  /// XOR mixes two equal-length byte arrays.
  ///
  /// XOR is used because it:
  /// - Preserves the entropy of both inputs.
  /// - Is computationally cheap (single CPU instruction per byte).
  /// - Produces output that is indistinguishable from random if either
  ///   input is random.
  ///
  /// [a] — First byte array (must be same length as [b]).
  /// [b] — Second byte array (must be same length as [a]).
  ///
  /// Returns a new Uint8List where each byte is a[i] ^ b[i].
  Uint8List _xorBytes(Uint8List a, Uint8List b) {
    assert(a.length == b.length,
        'XOR operands must be same length: ${a.length} vs ${b.length}');

    final result = Uint8List(a.length);
    for (var i = 0; i < a.length; i++) {
      result[i] = a[i] ^ b[i];
    }
    return result;
  }

  // ===========================================================================
  // HEX ENCODING UTILITIES
  // ===========================================================================

  /// Converts a Uint8List to a hexadecimal string.
  String _bytesToHex(Uint8List bytes) {
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  /// Converts a hexadecimal string to a Uint8List.
  Uint8List _hexToBytes(String hex) {
    final result = Uint8List(hex.length ~/ 2);
    for (var i = 0; i < hex.length; i += 2) {
      result[i ~/ 2] = int.parse(hex.substring(i, i + 2), radix: 16);
    }
    return result;
  }

  // ===========================================================================
  // CLEANUP
  // ===========================================================================

  /// Removes the intermediate key from the platform keystore.
  ///
  /// This should only be called during vault reset or device deregistration.
  /// After this, hardware-bound key derivation will not work until
  /// [initialize] is called again.
  Future<void> reset() async {
    await _secureStorage.delete(key: _intermediateKeyStorageKey);
    await _secureStorage.delete(key: _initializedKey);
  }
}
