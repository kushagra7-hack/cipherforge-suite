// =============================================================================
// AuthScreen — Master Password & Biometric Authentication
// =============================================================================
//
// This screen is the security gateway to the vault. It provides:
//
// 1. **Master Password Entry**
//    - A minimalist, secure text field for the master password.
//    - On first launch, it creates the vault (sets up salt + auth hash).
//    - On subsequent launches, it verifies the password.
//
// 2. **Biometric Authentication**
//    - Integrates with local_auth for fingerprint/Face ID.
//    - biometricOnly: true — does not fall back to device PIN/pattern.
//    - stickyAuth: false — re-authenticates if the app goes to background.
//    - Only available after the master password has been verified at least once
//      in the current install (the vault must be initialized first).
//
// 3. **5-Attempt Lockout with 30-Second Timer**
//    - After 5 failed password attempts, the UI locks for 30 seconds.
//    - The counter is reset on successful authentication.
//    - This is a UI-level rate limit — the Argon2id KDF provides the real
//      brute-force protection (each attempt takes ~1 second).
//
// SECURITY NOTES:
// - The password text field uses obscureText: true.
// - The password string is cleared from the TextEditingController after use.
// - The derived key is immediately passed to SecureSessionManager and never
//   stored in widget state.
// =============================================================================

import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:local_auth/local_auth.dart';

import '../data/vault_repository.dart';
import '../services/secure_session_manager.dart';
import 'vault_screen.dart';

/// The authentication screen — first screen the user sees.
///
/// Uses [ConsumerStatefulWidget] for Riverpod state access and
/// [StatefulWidget] lifecycle for managing the lockout timer.
class AuthScreen extends ConsumerStatefulWidget {
  const AuthScreen({super.key});

  @override
  ConsumerState<AuthScreen> createState() => _AuthScreenState();
}

class _AuthScreenState extends ConsumerState<AuthScreen> {
  // ---------------------------------------------------------------------------
  // Controllers and instances
  // ---------------------------------------------------------------------------

  /// Text controller for the master password field.
  /// We clear this after use to minimize the time the password exists in memory.
  final TextEditingController _passwordController = TextEditingController();

  /// Local authentication instance for biometric integration.
  final LocalAuthentication _localAuth = LocalAuthentication();

  /// Vault repository for password verification and initialization.
  final VaultRepository _repository = VaultRepository();

  // ---------------------------------------------------------------------------
  // State variables
  // ---------------------------------------------------------------------------

  /// Whether the vault has been initialized (master password set).
  bool _isVaultInitialized = false;

  /// Whether a password confirmation field should be shown (first-time setup).
  bool _isConfirmMode = false;

  /// Number of failed authentication attempts in the current session.
  int _failedAttempts = 0;

  /// Maximum allowed failed attempts before lockout.
  static const int _maxAttempts = 5;

  /// Lockout duration in seconds.
  static const int _lockoutDurationSeconds = 30;

  /// Whether the user is currently locked out.
  bool _isLockedOut = false;

  /// Remaining lockout seconds for the countdown display.
  int _lockoutSecondsRemaining = 0;

  /// Timer for the lockout countdown.
  Timer? _lockoutTimer;

  /// Whether an authentication operation is in progress.
  bool _isLoading = false;

  /// Error message to display to the user.
  String? _errorMessage;

  /// Whether biometric authentication is available on this device.
  bool _biometricsAvailable = false;

  /// Controller for the confirmation password field.
  final TextEditingController _confirmPasswordController =
      TextEditingController();

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  @override
  void initState() {
    super.initState();
    _initializeState();
  }

  /// Checks vault initialization status and biometric availability.
  Future<void> _initializeState() async {
    final isInitialized = await _repository.isVaultInitialized();
    final canCheckBiometrics = await _localAuth.canCheckBiometrics;
    final isDeviceSupported = await _localAuth.isDeviceSupported();

    // Check which biometric types are available.
    List<BiometricType> availableBiometrics = [];
    if (canCheckBiometrics) {
      availableBiometrics = await _localAuth.getAvailableBiometrics();
    }

    if (mounted) {
      setState(() {
        _isVaultInitialized = isInitialized;
        _isConfirmMode = !isInitialized;
        _biometricsAvailable = canCheckBiometrics &&
            isDeviceSupported &&
            availableBiometrics.isNotEmpty;
      });
    }
  }

  @override
  void dispose() {
    // Clear password from memory.
    _passwordController.clear();
    _passwordController.dispose();
    _confirmPasswordController.clear();
    _confirmPasswordController.dispose();
    _lockoutTimer?.cancel();
    super.dispose();
  }

  // ---------------------------------------------------------------------------
  // Authentication Logic
  // ---------------------------------------------------------------------------

  /// Handles the master password submission.
  ///
  /// For first-time setup: initializes the vault with the new password.
  /// For subsequent logins: verifies the password against stored auth hash.
  Future<void> _handlePasswordSubmit() async {
    // Check lockout.
    if (_isLockedOut) return;

    final password = _passwordController.text;

    // Validate input.
    if (password.isEmpty) {
      setState(() => _errorMessage = 'Please enter your master password');
      return;
    }

    // For first-time setup, validate password strength and confirmation.
    if (_isConfirmMode) {
      if (password.length < 12) {
        setState(() => _errorMessage =
            'Master password must be at least 12 characters');
        return;
      }

      if (_confirmPasswordController.text != password) {
        setState(() => _errorMessage = 'Passwords do not match');
        return;
      }
    }

    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      Uint8List? masterKey;

      if (!_isVaultInitialized) {
        // First-time setup: initialize the vault.
        masterKey = await _repository.initializeVault(password);
      } else {
        // Subsequent login: verify the password.
        masterKey = await _repository.verifyMasterPassword(password);
      }

      if (masterKey != null) {
        // Success — reset failed attempts.
        _failedAttempts = 0;

        // Store the master key in the secure session manager.
        // The key is stored as Uint8List, NEVER converted to String.
        ref.read(secureSessionManagerProvider.notifier).setMasterKey(masterKey);

        // Clear the password from the text controller immediately.
        _passwordController.clear();
        _confirmPasswordController.clear();

        // Navigate to the vault screen.
        if (mounted) {
          Navigator.of(context).pushReplacement(
            MaterialPageRoute(builder: (_) => const VaultScreen()),
          );
        }
      } else {
        // Failed attempt.
        _failedAttempts++;
        _passwordController.clear();

        if (_failedAttempts >= _maxAttempts) {
          _startLockout();
        } else {
          setState(() {
            _errorMessage =
                'Incorrect password. ${_maxAttempts - _failedAttempts} attempts remaining.';
          });
        }
      }
    } catch (e) {
      setState(() => _errorMessage = 'Authentication error. Please try again.');
    } finally {
      if (mounted) {
        setState(() => _isLoading = false);
      }
    }
  }

  /// Initiates the 30-second lockout after 5 failed attempts.
  ///
  /// This is a UI-level rate limit. The real brute-force protection comes
  /// from Argon2id's computational cost (~1 second per attempt on mobile).
  /// The lockout prevents rapid guessing in case the KDF is somehow bypassed.
  void _startLockout() {
    setState(() {
      _isLockedOut = true;
      _lockoutSecondsRemaining = _lockoutDurationSeconds;
      _errorMessage =
          'Too many failed attempts. Locked for $_lockoutDurationSeconds seconds.';
    });

    _lockoutTimer?.cancel();
    _lockoutTimer = Timer.periodic(const Duration(seconds: 1), (timer) {
      if (_lockoutSecondsRemaining <= 1) {
        timer.cancel();
        if (mounted) {
          setState(() {
            _isLockedOut = false;
            _lockoutSecondsRemaining = 0;
            _failedAttempts = 0;
            _errorMessage = null;
          });
        }
      } else {
        if (mounted) {
          setState(() {
            _lockoutSecondsRemaining--;
            _errorMessage =
                'Locked out. Try again in $_lockoutSecondsRemaining seconds.';
          });
        }
      }
    });
  }

  /// Handles biometric authentication.
  ///
  /// Biometric auth is a convenience feature — it does NOT replace the master
  /// password. The master key must have been previously derived and stored
  /// in the SecureSessionManager or a biometric-protected keystore entry.
  ///
  /// Configuration:
  /// - biometricOnly: true — don't fall back to device PIN/pattern.
  ///   We want genuine biometric verification, not a weaker fallback.
  /// - stickyAuth: false — if the app goes to background during biometric
  ///   prompt, the authentication is cancelled (not resumed). This prevents
  ///   a scenario where someone could approve the biometric prompt after
  ///   the legitimate user has walked away.
  Future<void> _handleBiometricAuth() async {
    if (!_biometricsAvailable || !_isVaultInitialized) return;

    try {
      final isAuthenticated = await _localAuth.authenticate(
        localizedReason: 'Authenticate to access your vault',
        options: const AuthenticationOptions(
          biometricOnly: true, // No fallback to device PIN/pattern
          stickyAuth: false, // Cancel if app goes to background
          useErrorDialogs: true, // Show platform error dialogs
        ),
      );

      if (isAuthenticated) {
        // Biometric auth succeeded.
        // In a full implementation, this would retrieve the master key
        // from a biometric-protected keystore entry.
        // For now, we still need the master password for the key.
        if (mounted) {
          setState(() {
            _errorMessage =
                'Biometric verified. Please enter master password for key derivation.';
          });
        }
      }
    } catch (e) {
      if (mounted) {
        setState(() => _errorMessage = 'Biometric authentication failed.');
      }
    }
  }

  // ---------------------------------------------------------------------------
  // UI
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      backgroundColor: const Color(0xFF0D1117),
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.symmetric(horizontal: 32.0),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                // ----- App Icon -----
                Container(
                  width: 80,
                  height: 80,
                  decoration: BoxDecoration(
                    color: const Color(0xFF1A73E8).withOpacity(0.15),
                    borderRadius: BorderRadius.circular(20),
                    border: Border.all(
                      color: const Color(0xFF1A73E8).withOpacity(0.3),
                    ),
                  ),
                  child: const Icon(
                    Icons.lock_outlined,
                    size: 40,
                    color: Color(0xFF1A73E8),
                  ),
                ),
                const SizedBox(height: 24),

                // ----- Title -----
                Text(
                  'Flutter Vault',
                  style: theme.textTheme.headlineMedium?.copyWith(
                    color: Colors.white,
                    fontWeight: FontWeight.bold,
                    letterSpacing: 1.2,
                  ),
                ),
                const SizedBox(height: 8),

                Text(
                  _isConfirmMode
                      ? 'Create your master password'
                      : 'Enter your master password',
                  style: theme.textTheme.bodyLarge?.copyWith(
                    color: Colors.white54,
                  ),
                ),
                const SizedBox(height: 40),

                // ----- Master Password Field -----
                _buildPasswordField(
                  controller: _passwordController,
                  label: 'Master Password',
                  hint: 'Enter master password',
                ),
                const SizedBox(height: 16),

                // ----- Confirm Password Field (first-time setup only) -----
                if (_isConfirmMode) ...[
                  _buildPasswordField(
                    controller: _confirmPasswordController,
                    label: 'Confirm Password',
                    hint: 'Re-enter master password',
                  ),
                  const SizedBox(height: 16),
                ],

                // ----- Error Message -----
                if (_errorMessage != null)
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: Colors.red.withOpacity(0.1),
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: Colors.red.withOpacity(0.3)),
                    ),
                    child: Row(
                      children: [
                        const Icon(Icons.warning_amber, color: Colors.red, size: 20),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            _errorMessage!,
                            style: const TextStyle(color: Colors.red, fontSize: 13),
                          ),
                        ),
                      ],
                    ),
                  ),
                const SizedBox(height: 24),

                // ----- Unlock / Create Button -----
                SizedBox(
                  width: double.infinity,
                  height: 50,
                  child: ElevatedButton(
                    onPressed: (_isLoading || _isLockedOut)
                        ? null
                        : _handlePasswordSubmit,
                    style: ElevatedButton.styleFrom(
                      backgroundColor: const Color(0xFF1A73E8),
                      foregroundColor: Colors.white,
                      disabledBackgroundColor: Colors.grey[800],
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(12),
                      ),
                    ),
                    child: _isLoading
                        ? const SizedBox(
                            width: 24,
                            height: 24,
                            child: CircularProgressIndicator(
                              strokeWidth: 2,
                              color: Colors.white,
                            ),
                          )
                        : Text(
                            _isLockedOut
                                ? 'Locked ($_lockoutSecondsRemaining s)'
                                : (_isConfirmMode
                                    ? 'Create Vault'
                                    : 'Unlock Vault'),
                            style: const TextStyle(
                              fontSize: 16,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                  ),
                ),
                const SizedBox(height: 16),

                // ----- Biometric Button -----
                if (_biometricsAvailable && _isVaultInitialized)
                  SizedBox(
                    width: double.infinity,
                    height: 50,
                    child: OutlinedButton.icon(
                      onPressed: _isLockedOut ? null : _handleBiometricAuth,
                      icon: const Icon(Icons.fingerprint, size: 24),
                      label: const Text(
                        'Use Biometrics',
                        style: TextStyle(fontSize: 16),
                      ),
                      style: OutlinedButton.styleFrom(
                        foregroundColor: const Color(0xFF1A73E8),
                        side: const BorderSide(color: Color(0xFF1A73E8)),
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(12),
                        ),
                      ),
                    ),
                  ),
                const SizedBox(height: 32),

                // ----- Security Notice -----
                Text(
                  'Your data never leaves this device.\nAll encryption happens locally.',
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    color: Colors.white.withOpacity(0.3),
                    fontSize: 12,
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  /// Builds a styled, secure password text field.
  ///
  /// Uses obscureText: true to prevent shoulder-surfing.
  /// The field styling matches the dark minimalist theme.
  Widget _buildPasswordField({
    required TextEditingController controller,
    required String label,
    required String hint,
  }) {
    return TextField(
      controller: controller,
      obscureText: true,
      autocorrect: false, // Prevent autocorrect from caching password
      enableSuggestions: false, // Prevent keyboard from learning password
      enableIMEPersonalizedLearning: false, // Android: don't learn from input
      style: const TextStyle(color: Colors.white, fontSize: 16),
      decoration: InputDecoration(
        labelText: label,
        hintText: hint,
        labelStyle: const TextStyle(color: Colors.white54),
        hintStyle: const TextStyle(color: Colors.white24),
        filled: true,
        fillColor: const Color(0xFF161B22),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: BorderSide.none,
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: BorderSide(color: Colors.white.withOpacity(0.1)),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: Color(0xFF1A73E8)),
        ),
        prefixIcon: const Icon(Icons.lock_outline, color: Colors.white38),
        contentPadding: const EdgeInsets.symmetric(
          horizontal: 16,
          vertical: 16,
        ),
      ),
      onSubmitted: (_) => _handlePasswordSubmit(),
    );
  }
}
