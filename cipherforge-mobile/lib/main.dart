// =============================================================================
// Flutter Vault — Application Entry Point
// =============================================================================
//
// This is the main entry point for the Flutter Vault password manager.
// It wires together all security services and configures the app.
//
// STARTUP SEQUENCE:
// 1. Initialize Flutter bindings.
// 2. Enable screenshot protection (FLAG_SECURE).
// 3. Perform environment integrity checks (root/jailbreak/debugger/emulator).
// 4. Check native integrity (Frida/Xposed detection).
// 5. Register the WidgetsBindingObserver for lifecycle-based key zeroing.
// 6. Launch the app with Riverpod provider scope.
//
// ARCHITECTURE:
// - Riverpod ProviderScope wraps the entire app for state management.
// - SecureSessionManager manages the master key lifecycle.
// - SessionLifecycleObserver watches app lifecycle for key zeroing.
// - EnvironmentIntegrityService runs checks at startup.
// - RuntimeShield provides screenshot protection.
// - AuthScreen is the initial route (login gate).
//
// SECURITY NOTES:
// - No sensitive data is logged or printed in release builds.
// - The app theme uses a dark color scheme to minimize shoulder-surfing.
// - All navigation routes are protected by the session state.
// =============================================================================

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'screens/auth_screen.dart';
import 'services/environment_integrity_service.dart';
import 'services/runtime_shield.dart';
import 'services/secure_session_manager.dart';

/// Application entry point.
///
/// Initializes all security services before launching the UI.
void main() async {
  // Ensure Flutter bindings are initialized before calling native code.
  // This is required for MethodChannel calls and plugin initialization.
  WidgetsFlutterBinding.ensureInitialized();

  // --------------------------------------------------------------------------
  // STEP 1: Enable Screenshot Protection
  // --------------------------------------------------------------------------
  // Set FLAG_SECURE to prevent screenshots, screen recording, and app
  // preview in the recent apps switcher. This is done as early as possible
  // to protect even the login screen.
  await RuntimeShield.enableScreenshotProtection();

  // --------------------------------------------------------------------------
  // STEP 2: Lock Screen Orientation (optional but recommended)
  // --------------------------------------------------------------------------
  // Lock to portrait mode. In landscape, shoulder-surfing is easier because
  // the screen is wider and more visible from adjacent seats.
  await SystemChrome.setPreferredOrientations([
    DeviceOrientation.portraitUp,
    DeviceOrientation.portraitDown,
  ]);

  // --------------------------------------------------------------------------
  // STEP 3: Configure System UI
  // --------------------------------------------------------------------------
  // Set the system chrome to dark mode to match our dark theme.
  SystemChrome.setSystemUIOverlayStyle(
    const SystemUiOverlayStyle(
      statusBarColor: Color(0xFF0D1117),
      statusBarIconBrightness: Brightness.light,
      systemNavigationBarColor: Color(0xFF0D1117),
      systemNavigationBarIconBrightness: Brightness.light,
    ),
  );

  // --------------------------------------------------------------------------
  // STEP 4: Run Environment Integrity Checks
  // --------------------------------------------------------------------------
  // These checks detect compromised environments (root/jailbreak, debugger,
  // emulator). Results are passed to the app for user warning display.
  final integrityResult =
      await EnvironmentIntegrityService.verifyIntegrity();

  // --------------------------------------------------------------------------
  // STEP 5: Check Native Integrity (Frida/Xposed)
  // --------------------------------------------------------------------------
  final nativeIntegrityOk = await RuntimeShield.checkNativeIntegrity();

  // --------------------------------------------------------------------------
  // STEP 6: Launch the App
  // --------------------------------------------------------------------------
  runApp(
    // ProviderScope is the root Riverpod container.
    // All providers (including SecureSessionManager) are scoped to this.
    ProviderScope(
      child: FlutterVaultApp(
        integrityResult: integrityResult,
        nativeIntegrityOk: nativeIntegrityOk,
      ),
    ),
  );
}

/// Root application widget.
///
/// Configures the Material theme and sets up the lifecycle observer
/// for master key zeroing.
class FlutterVaultApp extends ConsumerStatefulWidget {
  /// Results of the environment integrity check.
  final IntegrityCheckResult integrityResult;

  /// Whether native integrity checks passed.
  final bool nativeIntegrityOk;

  const FlutterVaultApp({
    super.key,
    required this.integrityResult,
    required this.nativeIntegrityOk,
  });

  @override
  ConsumerState<FlutterVaultApp> createState() => _FlutterVaultAppState();
}

class _FlutterVaultAppState extends ConsumerState<FlutterVaultApp> {
  /// The lifecycle observer that zeroes the master key on app background.
  SessionLifecycleObserver? _lifecycleObserver;

  /// Whether the integrity warning dialog has been shown.
  bool _integrityWarningShown = false;

  @override
  void initState() {
    super.initState();

    // Register the lifecycle observer after the first frame.
    // We need to wait because the Riverpod ref is not available
    // until the widget is fully mounted.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _registerLifecycleObserver();
      _showIntegrityWarningIfNeeded();
    });
  }

  /// Registers the [SessionLifecycleObserver] with the WidgetsBinding.
  ///
  /// This observer watches for app lifecycle changes (paused, inactive,
  /// detached) and zeroes the master key when the app leaves the foreground.
  void _registerLifecycleObserver() {
    // Get the SecureSessionManager notifier.
    final sessionManager =
        ref.read(secureSessionManagerProvider.notifier);

    // Create and register the observer.
    _lifecycleObserver = SessionLifecycleObserver(sessionManager);
    WidgetsBinding.instance.addObserver(_lifecycleObserver!);
  }

  /// Shows a warning dialog if environment integrity checks failed.
  ///
  /// This informs the user about potential security risks without blocking
  /// app usage. The user can acknowledge and continue.
  void _showIntegrityWarningIfNeeded() {
    if (_integrityWarningShown) return;

    final hasIssues = !widget.integrityResult.isIntegrityIntact ||
        !widget.nativeIntegrityOk;

    if (hasIssues && mounted) {
      _integrityWarningShown = true;

      final warningMessage = StringBuffer();

      if (!widget.integrityResult.isIntegrityIntact) {
        warningMessage.writeln(
          EnvironmentIntegrityService.getWarningMessage(
              widget.integrityResult),
        );
      }

      if (!widget.nativeIntegrityOk) {
        warningMessage.writeln(
          '\n⚠️ Runtime instrumentation detected.\n'
          'A hooking framework (e.g., Frida, Xposed) may be present. '
          'Your vault data could be intercepted.',
        );
      }

      showDialog(
        context: context,
        barrierDismissible: false,
        builder: (context) => AlertDialog(
          backgroundColor: const Color(0xFF161B22),
          title: const Row(
            children: [
              Icon(Icons.warning_amber, color: Colors.orange, size: 28),
              SizedBox(width: 8),
              Text(
                'Security Warning',
                style: TextStyle(color: Colors.white),
              ),
            ],
          ),
          content: SingleChildScrollView(
            child: Text(
              warningMessage.toString(),
              style: const TextStyle(color: Colors.white70, fontSize: 14),
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('I Understand the Risks'),
            ),
          ],
        ),
      );
    }
  }

  @override
  void dispose() {
    // Unregister the lifecycle observer to prevent memory leaks.
    if (_lifecycleObserver != null) {
      WidgetsBinding.instance.removeObserver(_lifecycleObserver!);
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter Vault',
      debugShowCheckedModeBanner: false,

      // ----- Dark Theme -----
      // A dark color scheme reduces shoulder-surfing visibility and
      // provides a professional appearance for a security app.
      theme: ThemeData(
        brightness: Brightness.dark,
        scaffoldBackgroundColor: const Color(0xFF0D1117),
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFF1A73E8),
          secondary: Color(0xFF1A73E8),
          surface: Color(0xFF161B22),
          error: Color(0xFFCF6679),
        ),
        appBarTheme: const AppBarTheme(
          backgroundColor: Color(0xFF161B22),
          elevation: 0,
        ),
        cardTheme: CardTheme(
          color: const Color(0xFF161B22),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
        ),
        inputDecorationTheme: InputDecorationTheme(
          filled: true,
          fillColor: const Color(0xFF161B22),
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(12),
            borderSide: BorderSide.none,
          ),
          labelStyle: const TextStyle(color: Colors.white54),
        ),
        elevatedButtonTheme: ElevatedButtonThemeData(
          style: ElevatedButton.styleFrom(
            backgroundColor: const Color(0xFF1A73E8),
            foregroundColor: Colors.white,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(12),
            ),
          ),
        ),
        snackBarTheme: const SnackBarThemeData(
          backgroundColor: Color(0xFF161B22),
          contentTextStyle: TextStyle(color: Colors.white),
          behavior: SnackBarBehavior.floating,
        ),
      ),

      // ----- Routes -----
      home: const AuthScreen(),
      routes: {
        '/auth': (context) => const AuthScreen(),
      },
    );
  }
}
