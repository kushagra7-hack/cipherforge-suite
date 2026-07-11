// =============================================================================
// IntegrityCheck.kt — Android Native Security Checks
// =============================================================================
//
// This Kotlin file provides native Android security checks that cannot be
// performed effectively from the Dart side:
//
// 1. **FLAG_SECURE** — Prevents screenshots and screen recording.
// 2. **Frida Detection** — Checks for the Frida instrumentation framework.
// 3. **Xposed Detection** — Checks for the Xposed hooking framework.
// 4. **Root Detection** — Additional root checks beyond flutter_jailbreak_detection.
//
// INTEGRATION:
// - This is registered as a MethodChannel handler in the Flutter activity.
// - The Dart side calls these methods via MethodChannel('com.securevault/runtime_shield').
//
// IMPORTANT: This is a placeholder that demonstrates the detection patterns.
// In a production app, you would:
// - Obfuscate this code with ProGuard/R8 to prevent easy bypass.
// - Implement the checks in native C/C++ via JNI for harder reverse engineering.
// - Use Google Play Integrity API for server-side attestation.
// - Combine multiple detection methods for defense in depth.
//
// LIMITATIONS:
// - Magisk Hide / DenyList can bypass most root detection.
// - Frida can unhook its own detection before it's detected.
// - These are speed bumps, not absolute barriers.
// =============================================================================

package com.securevault

import android.os.Bundle
import android.view.WindowManager
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.Socket

/// Main Flutter Activity with integrated security checks.
///
/// Extends FlutterActivity to:
/// - Register the MethodChannel for Dart-to-native communication.
/// - Handle FLAG_SECURE for screenshot protection.
/// - Provide native integrity checking methods.
class MainActivity : FlutterActivity() {

    /// The MethodChannel name — must match the Dart side exactly.
    private val CHANNEL = "com.securevault/runtime_shield"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Enable FLAG_SECURE by default at activity creation.
        // This prevents screenshots even before Flutter renders the first frame.
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        // Register the MethodChannel handler.
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                handleMethodCall(call, result)
            }
    }

    /// Routes MethodChannel calls to the appropriate handler.
    private fun handleMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "enableScreenshotProtection" -> {
                enableScreenshotProtection()
                result.success(true)
            }
            "disableScreenshotProtection" -> {
                disableScreenshotProtection()
                result.success(true)
            }
            "checkIntegrity" -> {
                val isClean = performIntegrityChecks()
                result.success(isClean)
            }
            else -> {
                result.notImplemented()
            }
        }
    }

    // =========================================================================
    // FLAG_SECURE — Screenshot Protection
    // =========================================================================

    /// Enables FLAG_SECURE on the activity window.
    ///
    /// When FLAG_SECURE is set:
    /// - System screenshots are blocked (returns a black/blank image).
    /// - MediaProjection (screen recording) shows a black window.
    /// - The recent apps switcher shows a blank preview.
    /// - Cast/Miracast does not show the app content.
    ///
    /// This is the most effective screenshot protection available on Android.
    private fun enableScreenshotProtection() {
        runOnUiThread {
            window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE
            )
        }
    }

    /// Disables FLAG_SECURE (for testing only — not recommended in production).
    private fun disableScreenshotProtection() {
        runOnUiThread {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }

    // =========================================================================
    // INTEGRITY CHECKS
    // =========================================================================

    /// Performs all native integrity checks.
    ///
    /// Returns true if the environment appears clean (no threats detected).
    /// Returns false if any check fails (potential compromise).
    private fun performIntegrityChecks(): Boolean {
        val isFridaDetected = checkForFrida()
        val isXposedDetected = checkForXposed()
        val isRooted = checkForRoot()

        // Return true only if ALL checks pass (no threats).
        return !isFridaDetected && !isXposedDetected && !isRooted
    }

    // =========================================================================
    // FRIDA DETECTION
    // =========================================================================

    /// Checks for the Frida instrumentation framework.
    ///
    /// Frida is a powerful dynamic instrumentation toolkit that can:
    /// - Hook any function at runtime.
    /// - Read/write process memory.
    /// - Intercept network traffic.
    /// - Bypass all security checks.
    ///
    /// Detection methods:
    /// 1. Check if Frida's default port (27042) is listening.
    /// 2. Scan /proc/self/maps for frida-agent shared libraries.
    /// 3. Check for frida-server binary in common locations.
    ///
    /// LIMITATIONS:
    /// - Frida can be configured to use a non-default port.
    /// - Frida can be injected without frida-server (via ptrace or root).
    /// - Sophisticated attackers can patch these checks before they run.
    private fun checkForFrida(): Boolean {
        // Check 1: Frida default port
        if (isFridaPortOpen()) return true

        // Check 2: Frida agent in memory maps
        if (isFridaAgentLoaded()) return true

        // Check 3: Frida server binary
        if (isFridaServerPresent()) return true

        return false
    }

    /// Checks if Frida's default port (27042) is listening.
    ///
    /// Frida-server listens on port 27042 by default for incoming connections
    /// from the Frida client on the host machine.
    private fun isFridaPortOpen(): Boolean {
        return try {
            val socket = Socket("127.0.0.1", 27042)
            socket.close()
            true // Port is open — Frida likely running
        } catch (e: Exception) {
            false // Port closed — no Frida on default port
        }
    }

    /// Scans /proc/self/maps for Frida agent shared libraries.
    ///
    /// When Frida injects its agent into a process, it loads a shared library
    /// (typically named frida-agent-*.so) into the process's memory space.
    /// This appears in /proc/self/maps.
    private fun isFridaAgentLoaded(): Boolean {
        return try {
            val maps = File("/proc/self/maps").readText()
            maps.contains("frida") || maps.contains("gadget")
        } catch (e: Exception) {
            false // Can't read maps — assume clean
        }
    }

    /// Checks for frida-server binary in common locations.
    private fun isFridaServerPresent(): Boolean {
        val fridaPaths = listOf(
            "/data/local/tmp/frida-server",
            "/data/local/tmp/re.frida.server",
            "/sdcard/frida-server"
        )

        return fridaPaths.any { File(it).exists() }
    }

    // =========================================================================
    // XPOSED DETECTION
    // =========================================================================

    /// Checks for the Xposed Framework.
    ///
    /// Xposed allows modifying the behavior of any Android app without
    /// changing its APK. It works by:
    /// 1. Replacing /system/bin/app_process with a modified version.
    /// 2. Loading Xposed modules that hook into app methods.
    ///
    /// For a password manager, Xposed could:
    /// - Hook the decryption methods to capture plaintext passwords.
    /// - Hook the clipboard to intercept copied passwords.
    /// - Hook the biometric callback to bypass authentication.
    ///
    /// Detection methods:
    /// 1. Check for Xposed Installer package.
    /// 2. Check for the XposedBridge class in the class path.
    /// 3. Check for Xposed-related files in /system.
    private fun checkForXposed(): Boolean {
        // Check 1: Xposed Installer package
        val xposedPackages = listOf(
            "de.robv.android.xposed.installer",
            "org.meowcat.edxposed.manager",
            "org.lsposed.manager"
        )

        for (pkg in xposedPackages) {
            try {
                packageManager.getPackageInfo(pkg, 0)
                return true // Xposed manager found
            } catch (e: Exception) {
                // Package not found — continue checking
            }
        }

        // Check 2: XposedBridge class
        try {
            Class.forName("de.robv.android.xposed.XposedBridge")
            return true // Xposed framework loaded
        } catch (e: ClassNotFoundException) {
            // Not found — continue
        }

        // Check 3: Xposed-related system files
        val xposedFiles = listOf(
            "/system/framework/XposedBridge.jar",
            "/system/lib/libxposed_art.so",
            "/system/lib64/libxposed_art.so"
        )

        return xposedFiles.any { File(it).exists() }
    }

    // =========================================================================
    // ROOT DETECTION (supplementary)
    // =========================================================================

    /// Additional root detection checks beyond flutter_jailbreak_detection.
    ///
    /// These checks supplement the Dart-side detection with native checks
    /// that are harder to bypass from the Dart level.
    ///
    /// Detection methods:
    /// 1. Check for su binary in common locations.
    /// 2. Check for Magisk-specific files.
    /// 3. Check build tags for "test-keys" (custom ROM indicator).
    private fun checkForRoot(): Boolean {
        // Check 1: su binary
        val suPaths = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/data/local/bin/su",
            "/data/local/xbin/su"
        )

        if (suPaths.any { File(it).exists() }) return true

        // Check 2: Magisk files
        val magiskPaths = listOf(
            "/sbin/.magisk",
            "/data/adb/magisk",
            "/data/adb/magisk.db"
        )

        if (magiskPaths.any { File(it).exists() }) return true

        // Check 3: Build tags
        val buildTags = android.os.Build.TAGS
        if (buildTags != null && buildTags.contains("test-keys")) return true

        // Check 4: Try to execute su
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("which", "su"))
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val result = reader.readLine()
            result != null && result.isNotEmpty()
        } catch (e: Exception) {
            false
        }
    }
}
