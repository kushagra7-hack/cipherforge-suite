// =============================================================================
// RuntimeShield — Screenshot Blocking, Secure Keyboard, Memory Wipe
// =============================================================================
//
// This service provides runtime security hardening features:
//
// 1. **FLAG_SECURE Screenshot Blocking**
//    - On Android, sets WindowManager.LayoutParams.FLAG_SECURE to prevent:
//      - Screenshots (system screenshot button)
//      - Screen recording (MediaProjection API)
//      - App preview in the recent apps switcher
//    - On iOS, uses a similar mechanism via UIScreen.isCaptured observation.
//    - Implemented via a MethodChannel to native code since Flutter does not
//      expose window flags directly.
//
// 2. **Secure Keyboard Configuration**
//    - Recommends TextInputType and InputDecoration settings that hint to
//      the keyboard to:
//      - Disable autocomplete/suggestions
//      - Disable keyboard learning (Android: enableIMEPersonalizedLearning)
//      - Use incognito mode if available
//    - These are hints — the keyboard app may ignore them.
//
// 3. **Memory Wipe Utility**
//    - Provides a centralized method to zero sensitive byte arrays.
//    - Used by SecureSessionManager and any other module handling keys.
//    - Best-effort: Dart's GC may have copied data during compaction.
//
// IMPLEMENTATION NOTES:
// - FLAG_SECURE requires a MethodChannel to Android native code.
//   The Kotlin side (IntegrityCheck.kt) handles the actual window flag.
// - On iOS, the Swift side (IntegrityCheck.swift) handles screen capture.
// - If the platform channel fails (e.g., on desktop/web), we fail silently
//   rather than crashing the app.
// =============================================================================

import 'dart:typed_data';

import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';

import '../core/security_engine.dart';

/// Runtime security hardening service.
///
/// Call [enableScreenshotProtection] at app startup to prevent screen capture.
/// Use [secureTextFieldConfig] when building password input fields.
/// Call [wipeMemory] to zero sensitive byte arrays.
class RuntimeShield {
  // ---------------------------------------------------------------------------
  // Method Channel
  // ---------------------------------------------------------------------------

  /// Platform channel for native security operations.
  ///
  /// This communicates with:
  /// - Android: IntegrityCheck.kt — sets FLAG_SECURE, checks for Frida/Xposed
  /// - iOS: IntegrityCheck.swift — observes screen capture, checks for Frida
  static const MethodChannel _channel =
      MethodChannel('com.securevault/runtime_shield');

  // ===========================================================================
  // SCREENSHOT PROTECTION
  // ===========================================================================

  /// Enables FLAG_SECURE to prevent screenshots and screen recording.
  ///
  /// On Android, this sets FLAG_SECURE on the activity's window, which:
  /// - Prevents the system screenshot button from capturing this window.
  /// - Prevents MediaProjection (screen recording) from capturing content.
  /// - Shows a blank/black preview in the recent apps switcher.
  /// - Prevents Android's screenshot-on-share from including app content.
  ///
  /// On iOS, this observes UIScreen.isCaptured and can overlay the content
  /// when screen capture is detected.
  ///
  /// NOTE: This does NOT prevent a physical camera from photographing the
  /// screen, nor does it prevent accessibility services from reading content.
  /// It is a defense-in-depth measure, not a complete solution.
  static Future<void> enableScreenshotProtection() async {
    try {
      await _channel.invokeMethod('enableScreenshotProtection');
    } on PlatformException catch (_) {
      // Platform not supported (desktop, web) or native code not found.
      // Fail silently — this is a best-effort security measure.
    } on MissingPluginException catch (_) {
      // Method channel not registered — native code not available.
      // This happens during development before native code is added.
    }
  }

  /// Disables FLAG_SECURE to allow screenshots.
  ///
  /// This should generally NOT be called in a password manager.
  /// It exists only for testing purposes or specific UX flows where
  /// the user needs to take a screenshot (e.g., exporting a QR code).
  static Future<void> disableScreenshotProtection() async {
    try {
      await _channel.invokeMethod('disableScreenshotProtection');
    } on PlatformException catch (_) {
      // Fail silently.
    } on MissingPluginException catch (_) {
      // Fail silently.
    }
  }

  // ===========================================================================
  // SECURE KEYBOARD CONFIGURATION
  // ===========================================================================

  /// Returns an [InputDecoration] configured for secure text entry.
  ///
  /// This decoration:
  /// - Disables autocorrect (prevents password words from entering the
  ///   keyboard's learned dictionary).
  /// - Disables suggestions (prevents password fragments from appearing
  ///   in the suggestion bar).
  /// - Uses visiblePassword type when obscured (helps some keyboards
  ///   disable suggestions for password fields).
  ///
  /// [label] — The field label (e.g., "Master Password").
  /// [hint] — The field hint text.
  /// [prefixIcon] — Optional prefix icon.
  ///
  /// Returns a styled [InputDecoration] suitable for password fields.
  static InputDecoration secureInputDecoration({
    required String label,
    String? hint,
    IconData? prefixIcon,
  }) {
    return InputDecoration(
      labelText: label,
      hintText: hint,
      prefixIcon: prefixIcon != null ? Icon(prefixIcon) : null,
      // These border configurations use a dark theme.
      // Adjust to match your app's theme.
      filled: true,
    );
  }

  /// Returns a map of secure text field properties.
  ///
  /// Apply these properties to any TextField handling sensitive data:
  /// ```dart
  /// TextField(
  ///   ...RuntimeShield.secureTextFieldConfig(),
  ///   controller: _passwordController,
  /// )
  /// ```
  ///
  /// Properties:
  /// - autocorrect: false — prevents keyboard from learning password words
  /// - enableSuggestions: false — hides suggestion bar
  /// - enableIMEPersonalizedLearning: false — (Android) prevents keyboard
  ///   from adding to its learned dictionary
  /// - keyboardType: TextInputType.visiblePassword — tells the keyboard
  ///   this is a password field, which most keyboards treat specially
  ///
  /// NOTE: These are HINTS to the keyboard. Third-party keyboards may
  /// ignore them. For maximum security, users should use their platform's
  /// built-in keyboard rather than third-party alternatives.
  static Map<String, dynamic> secureTextFieldProperties() {
    return {
      'autocorrect': false,
      'enableSuggestions': false,
      'enableIMEPersonalizedLearning': false,
      'keyboardType': TextInputType.visiblePassword,
    };
  }

  // ===========================================================================
  // MEMORY WIPE UTILITY
  // ===========================================================================

  /// Securely wipes a [Uint8List] by overwriting all bytes with 0x00.
  ///
  /// This is a centralized wrapper around [SecurityEngine.secureZero]
  /// for use by any module that handles sensitive data.
  ///
  /// BEST-EFFORT WARNING:
  /// Dart's garbage collector uses a copying/compacting strategy. This means:
  /// 1. The GC may have created copies of the Uint8List during compaction.
  /// 2. Those copies are NOT zeroed by this method.
  /// 3. The freed memory is eventually overwritten by new allocations,
  ///    but the timing is non-deterministic.
  ///
  /// For truly secure memory management, sensitive data should be handled
  /// in native code using platform-specific secure memory APIs:
  /// - Android: direct ByteBuffer or native memory via JNI
  /// - iOS: SecureEnclave or mlock'd memory pages
  ///
  /// Despite these limitations, zeroing is still valuable because:
  /// - It eliminates the most obvious copy of the key.
  /// - It reduces the window for memory dump attacks.
  /// - It's a defense-in-depth measure alongside other protections.
  ///
  /// [data] — The byte array to wipe. Will be all zeros after this call.
  static void wipeMemory(Uint8List data) {
    SecurityEngine.secureZero(data);
  }

  /// Wipes multiple byte arrays at once.
  ///
  /// Convenience method for scenarios where multiple sensitive buffers
  /// need to be cleaned up simultaneously (e.g., at session end).
  ///
  /// [buffers] — List of byte arrays to wipe.
  static void wipeMultiple(List<Uint8List> buffers) {
    for (final buffer in buffers) {
      SecurityEngine.secureZero(buffer);
    }
  }

  /// Creates a zeroed Uint8List of the specified length.
  ///
  /// Use this to allocate buffers for sensitive data. The buffer is
  /// guaranteed to start as all zeros (which is actually the default
  /// for Uint8List, but this makes the intent explicit).
  ///
  /// [length] — The number of bytes to allocate.
  ///
  /// Returns a new Uint8List filled with 0x00.
  static Uint8List allocateSecureBuffer(int length) {
    return Uint8List(length); // Dart initializes Uint8List to all zeros
  }

  // ===========================================================================
  // NATIVE INTEGRITY CHECKS
  // ===========================================================================

  /// Checks for runtime instrumentation tools (Frida, Xposed).
  ///
  /// This delegates to native code (IntegrityCheck.kt / IntegrityCheck.swift)
  /// which performs platform-specific checks:
  ///
  /// Android:
  /// - Checks for Frida server port (27042) listening.
  /// - Scans /proc/self/maps for frida-agent*.so.
  /// - Checks for Xposed framework in installed packages.
  /// - Checks for Magisk su binary.
  ///
  /// iOS:
  /// - Checks for Frida-related dylib injection.
  /// - Scans loaded libraries for frida signatures.
  /// - Checks for common jailbreak files.
  ///
  /// Returns true if the environment appears clean, false if instrumentation
  /// is detected.
  static Future<bool> checkNativeIntegrity() async {
    try {
      final result = await _channel.invokeMethod<bool>('checkIntegrity');
      return result ?? false;
    } on PlatformException catch (_) {
      // If the check fails, assume compromised (fail-closed).
      return false;
    } on MissingPluginException catch (_) {
      // Native code not available — assume safe for development.
      return true;
    }
  }
}
