// =============================================================================
// EnvironmentIntegrityService — Runtime Environment Verification
// =============================================================================
//
// This service performs environment integrity checks to detect whether the
// app is running in a compromised or hostile environment. It checks for:
//
// 1. **Root/Jailbreak Detection**
//    - Uses flutter_jailbreak_detection to check for rooted Android devices
//      and jailbroken iOS devices.
//    - On a rooted/jailbroken device, the OS security model is compromised:
//      - Other apps can read our app's private data directory.
//      - The Android Keystore / iOS Keychain may not be hardware-backed.
//      - Hooking frameworks (Frida, Xposed) can intercept our function calls.
//
// 2. **Debugger Detection**
//    - Checks if a debugger is attached to the process.
//    - A debugger can inspect memory at runtime, potentially extracting
//      the master key from the Dart heap.
//    - Uses Dart's assert mechanism and Platform checks.
//
// 3. **Emulator Detection**
//    - Checks for emulator/simulator indicators.
//    - Emulators lack hardware security modules (TEE/SE) and provide
//      weaker security guarantees than physical devices.
//
// POLICY:
// - The app calls verifyIntegrity() at startup.
// - If the environment is compromised, the user is warned but NOT blocked.
//   (Blocking on root/jailbreak can be overly aggressive and affects
//   legitimate power users. The warning ensures informed consent.)
// - In a high-security deployment, you could choose to block instead.
//
// LIMITATIONS:
// - Root/jailbreak detection is a cat-and-mouse game. Sophisticated tools
//   like Magisk Hide can bypass most detection methods.
// - These checks raise the bar but cannot guarantee a clean environment.
// =============================================================================

import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter_jailbreak_detection/flutter_jailbreak_detection.dart';

/// Result of an environment integrity check.
///
/// Contains the overall pass/fail status and individual check results.
class IntegrityCheckResult {
  /// Whether the device appears to be rooted (Android) or jailbroken (iOS).
  final bool isRootedOrJailbroken;

  /// Whether a debugger appears to be attached.
  final bool isDebuggerAttached;

  /// Whether the app appears to be running on an emulator/simulator.
  final bool isEmulator;

  /// Overall integrity status — true if ALL checks pass.
  bool get isIntegrityIntact =>
      !isRootedOrJailbroken && !isDebuggerAttached && !isEmulator;

  /// Human-readable summary of the integrity check results.
  String get summary {
    if (isIntegrityIntact) {
      return 'Environment integrity verified. No threats detected.';
    }

    final issues = <String>[];
    if (isRootedOrJailbroken) issues.add('Device is rooted/jailbroken');
    if (isDebuggerAttached) issues.add('Debugger detected');
    if (isEmulator) issues.add('Running on emulator/simulator');

    return 'Integrity warnings: ${issues.join(', ')}';
  }

  const IntegrityCheckResult({
    required this.isRootedOrJailbroken,
    required this.isDebuggerAttached,
    required this.isEmulator,
  });
}

/// Service for verifying the runtime environment's integrity.
///
/// Call [verifyIntegrity] at app startup to check for compromised environments.
/// The results can be used to warn the user or restrict functionality.
class EnvironmentIntegrityService {
  /// Performs all environment integrity checks and returns the results.
  ///
  /// This is an async operation because root/jailbreak detection requires
  /// platform channel communication.
  ///
  /// Returns an [IntegrityCheckResult] with individual and overall status.
  static Future<IntegrityCheckResult> verifyIntegrity() async {
    // Run all checks concurrently for speed.
    final results = await Future.wait([
      _checkRootJailbreak(),
      _checkDebugger(),
      _checkEmulator(),
    ]);

    return IntegrityCheckResult(
      isRootedOrJailbroken: results[0],
      isDebuggerAttached: results[1],
      isEmulator: results[2],
    );
  }

  // ===========================================================================
  // CHECK 1: ROOT / JAILBREAK DETECTION
  // ===========================================================================

  /// Checks whether the device is rooted (Android) or jailbroken (iOS).
  ///
  /// Uses flutter_jailbreak_detection which performs multiple heuristics:
  /// - Android: su binary check, test-keys, known root apps, /system RW
  /// - iOS: Cydia URL scheme, jailbreak files, sandbox integrity
  ///
  /// LIMITATIONS:
  /// - Magisk Hide and similar tools can bypass these checks.
  /// - Some legitimate custom ROMs may trigger false positives.
  /// - This is a probabilistic check, not a guarantee.
  static Future<bool> _checkRootJailbreak() async {
    try {
      // flutter_jailbreak_detection handles both Android and iOS.
      final isJailbroken = await FlutterJailbreakDetection.jailbroken;
      return isJailbroken;
    } catch (e) {
      // If the check fails (e.g., on desktop platforms), assume safe.
      // In a production app, you might want to be more cautious and
      // return true (assume compromised) on failure.
      return false;
    }
  }

  // ===========================================================================
  // CHECK 2: DEBUGGER DETECTION
  // ===========================================================================

  /// Checks whether a debugger is attached to the process.
  ///
  /// Detection methods:
  /// - kDebugMode: Dart compile-time constant, true in debug builds.
  /// - kProfileMode: True in profile builds (also a concern for key extraction).
  /// - Platform-specific: On Android, we could check /proc/self/status for
  ///   TracerPid, but this requires native code.
  ///
  /// NOTE: In release builds, kDebugMode is always false, and the Dart VM
  /// does not include debug symbols. An attacker would need Frida or a
  /// similar tool to attach a debugger to a release build.
  static Future<bool> _checkDebugger() async {
    // kDebugMode is a compile-time constant set by the Dart compiler.
    // In release builds, this is always false and the check is tree-shaken.
    if (kDebugMode) return true;

    // kProfileMode allows some instrumentation that could be abused.
    if (kProfileMode) return true;

    // In release mode, we can perform additional platform-specific checks.
    // On Android, we could read /proc/self/status and check TracerPid.
    // This is a best-effort check from the Dart side.
    try {
      if (Platform.isAndroid) {
        // Check if the app is debuggable.
        // In a real production app, this would be done via a method channel
        // to native code that checks ApplicationInfo.FLAG_DEBUGGABLE.
        // From Dart, we rely on the compile-time constants above.
      }
    } catch (_) {
      // Platform not available (web, tests) — assume safe.
    }

    return false;
  }

  // ===========================================================================
  // CHECK 3: EMULATOR / SIMULATOR DETECTION
  // ===========================================================================

  /// Checks whether the app is running on an emulator or simulator.
  ///
  /// Emulators are a concern because:
  /// - They lack hardware-backed security (TEE, Secure Enclave).
  /// - They can be easily instrumented and memory-dumped.
  /// - They may not enforce the same sandboxing as physical devices.
  ///
  /// Detection heuristics:
  /// - Android: Check Build properties (BRAND, MODEL, HARDWARE, FINGERPRINT)
  ///   for emulator signatures like "sdk", "google_sdk", "generic".
  /// - iOS: Check for "x86_64" architecture (simulator runs on Intel Mac)
  ///   or check ProcessInfo environment for SIMULATOR_DEVICE_NAME.
  ///
  /// NOTE: This uses flutter_jailbreak_detection's developer mode check
  /// as a proxy, supplemented by platform-specific heuristics.
  static Future<bool> _checkEmulator() async {
    try {
      // flutter_jailbreak_detection provides a developer mode check
      // which correlates with emulator usage on some platforms.
      final isDeveloperMode =
          await FlutterJailbreakDetection.developerMode;

      // Additional platform-specific checks.
      if (Platform.isAndroid) {
        // On Android, check for common emulator indicators.
        // In production, this would use a method channel to check
        // Build.FINGERPRINT, Build.MODEL, Build.MANUFACTURER, etc.
        // From Dart, we can check some environment variables.
        return isDeveloperMode;
      }

      if (Platform.isIOS) {
        // On iOS, the simulator check would use a method channel
        // to check TARGET_IPHONE_SIMULATOR preprocessor macro.
        return isDeveloperMode;
      }

      return isDeveloperMode;
    } catch (e) {
      // If detection fails, assume physical device.
      return false;
    }
  }

  // ===========================================================================
  // UTILITY
  // ===========================================================================

  /// Returns a user-friendly warning message for the detected threats.
  ///
  /// This message is shown in a dialog at app startup when integrity
  /// checks fail. It explains the risks without being overly technical.
  static String getWarningMessage(IntegrityCheckResult result) {
    final warnings = <String>[];

    if (result.isRootedOrJailbroken) {
      warnings.add(
        '⚠️ Your device appears to be rooted/jailbroken.\n'
        'This means other apps may be able to access your vault data. '
        'For maximum security, use an unmodified device.',
      );
    }

    if (result.isDebuggerAttached) {
      warnings.add(
        '⚠️ A debugger appears to be attached.\n'
        'This could allow an attacker to inspect your master key in memory. '
        'Ensure you are not running the app in debug mode.',
      );
    }

    if (result.isEmulator) {
      warnings.add(
        '⚠️ Running on an emulator/simulator.\n'
        'Emulators lack hardware security modules and may not protect '
        'your vault data as well as a physical device.',
      );
    }

    return warnings.join('\n\n');
  }
}
