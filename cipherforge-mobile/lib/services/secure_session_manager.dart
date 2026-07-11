// =============================================================================
// SecureSessionManager — Master Key Lifecycle Management
// =============================================================================
//
// This module manages the master encryption key's lifecycle using Riverpod
// for state management and WidgetsBindingObserver for app lifecycle events.
//
// CRITICAL SECURITY INVARIANTS:
//
// 1. **Master key is ALWAYS Uint8List, NEVER String.**
//    - Strings in Dart are immutable and interned — once a key is converted
//      to a String, there's no way to zero it from memory.
//    - Uint8List allows byte-level zeroing via secureZero().
//
// 2. **Key zeroing on app lifecycle changes.**
//    - When the app transitions to paused, inactive, or detached state,
//      the master key is immediately zeroed.
//    - This protects against:
//      - Memory dump attacks when the app is in background.
//      - Cold boot attacks on devices without full-disk encryption.
//      - Forensic analysis of process memory.
//
// 3. **On-demand decryption.**
//    - The decryptSingleField() method decrypts a single field and returns
//      the plaintext. The caller should use the result immediately and
//      avoid storing it longer than necessary.
//
// 4. **Riverpod StateNotifier pattern.**
//    - The master key is stored in a StateNotifier, which provides:
//      - Reactive updates (UI rebuilds when key is set/cleared).
//      - Proper disposal semantics (key is zeroed on provider disposal).
//      - Type safety (state is Uint8List? — nullable indicates no session).
//
// ARCHITECTURE:
// - SecureSessionManager (StateNotifier) holds the key.
// - SessionLifecycleObserver (WidgetsBindingObserver) watches app state.
// - The observer holds a reference to the notifier and calls clearMasterKey()
//   on lifecycle transitions.
// =============================================================================

import 'dart:typed_data';

import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../core/security_engine.dart';

// =============================================================================
// RIVERPOD PROVIDER
// =============================================================================

/// Riverpod provider for the secure session manager.
///
/// The state is Uint8List? where:
/// - null = no active session (user must authenticate)
/// - Uint8List = active session with the master key in memory
///
/// Usage:
/// - Read key: ref.read(secureSessionManagerProvider)
/// - Watch key: ref.watch(secureSessionManagerProvider)
/// - Set key:   ref.read(secureSessionManagerProvider.notifier).setMasterKey(key)
/// - Clear key: ref.read(secureSessionManagerProvider.notifier).clearMasterKey()
final secureSessionManagerProvider =
    StateNotifierProvider<SecureSessionManager, Uint8List?>((ref) {
  return SecureSessionManager();
});

// =============================================================================
// SECURE SESSION MANAGER
// =============================================================================

/// Manages the master encryption key's lifecycle.
///
/// The master key exists in memory ONLY during an active session.
/// It is zeroed (overwritten with 0x00) when:
/// - The user explicitly locks the vault.
/// - The app goes to background (paused/inactive/detached).
/// - The provider is disposed.
///
/// THREAD SAFETY NOTE: Dart is single-threaded (event loop), so there's no
/// risk of concurrent access to the key. However, isolates get their own
/// memory, so the key cannot be accessed from a background isolate.
class SecureSessionManager extends StateNotifier<Uint8List?> {
  /// The actual master key bytes. We keep a reference separate from the
  /// Riverpod state so we can zero it even after setting state to null.
  Uint8List? _masterKeyBytes;

  /// Creates a new session manager with no active session.
  SecureSessionManager() : super(null);

  // ---------------------------------------------------------------------------
  // KEY MANAGEMENT
  // ---------------------------------------------------------------------------

  /// Sets the master key for the current session.
  ///
  /// This should be called ONLY after successful master password verification
  /// or vault initialization. The key is the output of Argon2id KDF.
  ///
  /// [key] — The 32-byte (256-bit) master key as Uint8List.
  ///
  /// SECURITY: The key is stored by reference — we do NOT copy it.
  /// This means the caller should NOT modify or zero the original buffer
  /// after passing it here. The session manager takes ownership.
  void setMasterKey(Uint8List key) {
    assert(key.length == 32,
        'Master key must be exactly 32 bytes (256 bits), got ${key.length}');

    // If there's an existing key, zero it first.
    _zeroExistingKey();

    // Store the new key.
    _masterKeyBytes = key;
    state = key;
  }

  /// Clears and zeroes the master key, ending the current session.
  ///
  /// After calling this:
  /// - The Riverpod state becomes null.
  /// - The Uint8List bytes are overwritten with 0x00.
  /// - Any UI watching the provider will rebuild (detecting no session).
  ///
  /// This is called:
  /// - Explicitly by the user (lock button).
  /// - Automatically by SessionLifecycleObserver on app lifecycle changes.
  /// - On provider disposal.
  void clearMasterKey() {
    _zeroExistingKey();
    state = null;
  }

  /// Zeroes the existing master key bytes in memory.
  ///
  /// This is a best-effort security measure. Dart's GC may have created
  /// copies during compaction, and we cannot guarantee those are zeroed.
  /// However, zeroing the primary buffer:
  /// - Eliminates the most accessible copy of the key.
  /// - Reduces the window for memory dump attacks.
  /// - Is a defense-in-depth measure alongside platform keystore usage.
  void _zeroExistingKey() {
    if (_masterKeyBytes != null) {
      SecurityEngine.secureZero(_masterKeyBytes!);
      _masterKeyBytes = null;
    }
  }

  // ---------------------------------------------------------------------------
  // ON-DEMAND DECRYPTION
  // ---------------------------------------------------------------------------

  /// Decrypts a single encrypted field using the current master key.
  ///
  /// This method exists to support the pattern of decrypting data only
  /// when it's needed (e.g., when the user taps "reveal password"),
  /// rather than decrypting everything upfront.
  ///
  /// [encryptedData] — The AES-256-GCM encrypted data (IV + ciphertext + tag).
  ///
  /// Returns the decrypted plaintext string.
  /// Throws [StateError] if no master key is active (session expired).
  /// Throws [InvalidCipherTextException] if the data is corrupt or tampered.
  String decryptSingleField(Uint8List encryptedData) {
    final key = _masterKeyBytes;
    if (key == null) {
      throw StateError(
        'Cannot decrypt: no active session. '
        'The master key has been zeroed (session expired or app was backgrounded).',
      );
    }

    return SecurityEngine.decrypt(encryptedData, key);
  }

  /// Encrypts a single plaintext field using the current master key.
  ///
  /// [plaintext] — The plaintext string to encrypt.
  ///
  /// Returns the AES-256-GCM encrypted data (IV + ciphertext + tag).
  /// Throws [StateError] if no master key is active.
  Uint8List encryptSingleField(String plaintext) {
    final key = _masterKeyBytes;
    if (key == null) {
      throw StateError(
        'Cannot encrypt: no active session. '
        'The master key has been zeroed.',
      );
    }

    return SecurityEngine.encrypt(plaintext, key);
  }

  /// Checks whether a master key is currently held in memory.
  ///
  /// This is a convenience method — callers can also check
  /// `state != null` directly.
  bool get hasActiveSession => _masterKeyBytes != null;

  // ---------------------------------------------------------------------------
  // DISPOSAL
  // ---------------------------------------------------------------------------

  /// Called when the Riverpod provider is disposed.
  ///
  /// Ensures the master key is zeroed even if the provider is disposed
  /// without explicitly calling clearMasterKey() (e.g., during app shutdown).
  @override
  void dispose() {
    _zeroExistingKey();
    super.dispose();
  }
}

// =============================================================================
// APP LIFECYCLE OBSERVER
// =============================================================================

/// Watches app lifecycle events and zeroes the master key when the app
/// goes to background.
///
/// This observer MUST be registered in main.dart and given a reference
/// to the SecureSessionManager's notifier.
///
/// Lifecycle states that trigger key zeroing:
/// - **paused**: App is in background (user switched to another app).
/// - **inactive**: App is partially obscured (e.g., incoming call overlay).
/// - **detached**: App is about to be destroyed by the OS.
/// - **hidden**: App is hidden (recent apps view on some platforms).
///
/// We do NOT zero the key on **resumed** — that's when the user returns.
///
/// RATIONALE:
/// When the app is in background, an attacker with physical access could:
/// 1. Connect the device to a computer.
/// 2. Dump the process memory.
/// 3. Search for the 32-byte key pattern.
/// By zeroing the key immediately when the app leaves the foreground,
/// we minimize this attack window.
class SessionLifecycleObserver extends WidgetsBindingObserver {
  /// Reference to the session manager for key zeroing.
  final SecureSessionManager _sessionManager;

  /// Creates an observer linked to the given session manager.
  SessionLifecycleObserver(this._sessionManager);

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    super.didChangeAppLifecycleState(state);

    switch (state) {
      case AppLifecycleState.paused:
        // App moved to background — zero the master key immediately.
        // The user will need to re-authenticate when they return.
        _sessionManager.clearMasterKey();
        break;

      case AppLifecycleState.inactive:
        // App is partially obscured (e.g., phone call overlay, app switcher).
        // On iOS, this includes the app switcher where a screenshot is taken.
        // We zero the key here too for maximum security.
        _sessionManager.clearMasterKey();
        break;

      case AppLifecycleState.detached:
        // App is being destroyed by the OS.
        // Zero the key as a final cleanup measure.
        _sessionManager.clearMasterKey();
        break;

      case AppLifecycleState.hidden:
        // App is hidden (e.g., moved to recent apps tray on some platforms).
        _sessionManager.clearMasterKey();
        break;

      case AppLifecycleState.resumed:
        // App returned to foreground — do NOT set a key here.
        // The user must re-authenticate through the auth screen.
        break;
    }
  }
}
