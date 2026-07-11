// =============================================================================
// IntegrityCheck.swift — iOS Native Security Checks
// =============================================================================
//
// This Swift file provides native iOS security checks that complement the
// Dart-side environment integrity service:
//
// 1. **Screen Capture Detection** — Detects screen recording and mirroring.
// 2. **Frida Detection** — Checks for the Frida instrumentation framework.
// 3. **Jailbreak Detection** — Additional jailbreak checks beyond the
//    flutter_jailbreak_detection plugin.
//
// INTEGRATION:
// - This is registered as a FlutterMethodChannel handler in the AppDelegate.
// - The Dart side calls these methods via:
//   MethodChannel('com.securevault/runtime_shield')
//
// IMPORTANT: This is a placeholder demonstrating detection patterns.
// In a production app, you would:
// - Use Apple's App Attest API for server-side device integrity verification.
// - Implement checks in C/C++ for harder reverse engineering.
// - Obfuscate string constants used in detection.
// - Combine multiple detection methods for defense in depth.
//
// LIMITATIONS:
// - Sophisticated jailbreaks (e.g., checkra1n with rootless) can bypass
//   most detection methods.
// - Frida can patch its own detection before these checks execute.
// - These are deterrents, not guarantees.
// =============================================================================

import UIKit
import Flutter

// =============================================================================
// APP DELEGATE EXTENSION
// =============================================================================

/// Extension on AppDelegate to register the security MethodChannel.
///
/// In your AppDelegate.swift, add this call in didFinishLaunchingWithOptions:
///
/// ```swift
/// IntegrityCheckPlugin.register(with: controller)
/// ```
class IntegrityCheckPlugin {

    /// The MethodChannel name — must match the Dart side exactly.
    private static let channelName = "com.securevault/runtime_shield"

    /// Registers the MethodChannel handler with the Flutter engine.
    ///
    /// - Parameter controller: The root FlutterViewController.
    static func register(with controller: FlutterViewController) {
        let channel = FlutterMethodChannel(
            name: channelName,
            binaryMessenger: controller.binaryMessenger
        )

        channel.setMethodCallHandler { (call, result) in
            handleMethodCall(call: call, result: result, controller: controller)
        }
    }

    /// Routes MethodChannel calls to the appropriate handler.
    private static func handleMethodCall(
        call: FlutterMethodCall,
        result: @escaping FlutterResult,
        controller: FlutterViewController
    ) {
        switch call.method {
        case "enableScreenshotProtection":
            enableScreenshotProtection(controller: controller)
            result(true)

        case "disableScreenshotProtection":
            disableScreenshotProtection(controller: controller)
            result(true)

        case "checkIntegrity":
            let isClean = performIntegrityChecks()
            result(isClean)

        default:
            result(FlutterMethodNotImplemented)
        }
    }

    // =========================================================================
    // SCREENSHOT PROTECTION
    // =========================================================================

    /// Enables screenshot protection on iOS.
    ///
    /// Unlike Android's FLAG_SECURE, iOS does not have a direct equivalent.
    /// Instead, we use a combination of techniques:
    ///
    /// 1. **UITextField trick**: Adding a secure UITextField to the window
    ///    hierarchy can prevent screenshots (the content appears blank).
    ///    This exploits the same mechanism that prevents the password
    ///    dot characters from appearing in screenshots.
    ///
    /// 2. **Screen capture observation**: We observe UIScreen.isCaptured
    ///    to detect when screen recording or mirroring is active, and
    ///    overlay the content with a privacy screen.
    ///
    /// NOTE: iOS 17+ has improved screenshot APIs. The effectiveness of
    /// these techniques may vary across iOS versions.
    private static func enableScreenshotProtection(controller: FlutterViewController) {
        DispatchQueue.main.async {
            // Technique 1: Observe screen capture state.
            // When isCaptured becomes true, overlay the view.
            NotificationCenter.default.addObserver(
                forName: UIScreen.capturedDidChangeNotification,
                object: nil,
                queue: .main
            ) { _ in
                if UIScreen.main.isCaptured {
                    // Screen is being recorded/mirrored — show privacy overlay.
                    showPrivacyOverlay(on: controller)
                } else {
                    // Recording stopped — remove overlay.
                    hidePrivacyOverlay(on: controller)
                }
            }

            // Check current state in case recording is already active.
            if UIScreen.main.isCaptured {
                showPrivacyOverlay(on: controller)
            }

            // Technique 2: Add a secure text field to prevent screenshots.
            // This is a well-known trick — iOS blanks out secure text fields
            // in screenshots, and we can use this to protect the entire window.
            let secureField = UITextField()
            secureField.isSecureTextEntry = true
            secureField.isUserInteractionEnabled = false

            // Add it behind all other content.
            if let window = controller.view.window {
                window.addSubview(secureField)
                secureField.centerYAnchor.constraint(equalTo: window.centerYAnchor).isActive = true
                secureField.centerXAnchor.constraint(equalTo: window.centerXAnchor).isActive = true

                // Make the text field's layer the window's layer mask.
                // This causes the entire window to be treated as "secure content"
                // by the screenshot mechanism.
                window.layer.superlayer?.addSublayer(secureField.layer)
                secureField.layer.sublayers?.first?.addSublayer(window.layer)
            }
        }
    }

    /// Disables screenshot protection (for testing only).
    private static func disableScreenshotProtection(controller: FlutterViewController) {
        DispatchQueue.main.async {
            NotificationCenter.default.removeObserver(
                controller,
                name: UIScreen.capturedDidChangeNotification,
                object: nil
            )
            hidePrivacyOverlay(on: controller)
        }
    }

    /// Privacy overlay tag for identification.
    private static let privacyOverlayTag = 999

    /// Shows a privacy overlay when screen capture is detected.
    ///
    /// This covers the entire window with a blur effect and a message,
    /// preventing the recorded content from containing sensitive data.
    private static func showPrivacyOverlay(on controller: FlutterViewController) {
        guard controller.view.viewWithTag(privacyOverlayTag) == nil else { return }

        let overlay = UIView(frame: controller.view.bounds)
        overlay.tag = privacyOverlayTag
        overlay.backgroundColor = UIColor(red: 0.05, green: 0.07, blue: 0.09, alpha: 1.0)
        overlay.autoresizingMask = [.flexibleWidth, .flexibleHeight]

        let blurEffect = UIBlurEffect(style: .dark)
        let blurView = UIVisualEffectView(effect: blurEffect)
        blurView.frame = overlay.bounds
        blurView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        overlay.addSubview(blurView)

        let label = UILabel()
        label.text = "🔒 Content hidden for security"
        label.textColor = .white
        label.textAlignment = .center
        label.font = UIFont.systemFont(ofSize: 18, weight: .semibold)
        label.translatesAutoresizingMaskIntoConstraints = false
        overlay.addSubview(label)

        NSLayoutConstraint.activate([
            label.centerXAnchor.constraint(equalTo: overlay.centerXAnchor),
            label.centerYAnchor.constraint(equalTo: overlay.centerYAnchor)
        ])

        controller.view.addSubview(overlay)
    }

    /// Removes the privacy overlay when screen capture stops.
    private static func hidePrivacyOverlay(on controller: FlutterViewController) {
        controller.view.viewWithTag(privacyOverlayTag)?.removeFromSuperview()
    }

    // =========================================================================
    // INTEGRITY CHECKS
    // =========================================================================

    /// Performs all native integrity checks.
    ///
    /// Returns true if the environment appears clean.
    /// Returns false if any threat is detected.
    private static func performIntegrityChecks() -> Bool {
        let isFridaDetected = checkForFrida()
        let isJailbroken = checkForJailbreak()

        return !isFridaDetected && !isJailbroken
    }

    // =========================================================================
    // FRIDA DETECTION
    // =========================================================================

    /// Checks for the Frida instrumentation framework on iOS.
    ///
    /// Frida on iOS works by:
    /// 1. Injecting FridaGadget.dylib into the app process.
    /// 2. Or running frida-server on the device (requires jailbreak).
    ///
    /// Detection methods:
    /// 1. Check for Frida's default port (27042).
    /// 2. Scan loaded dylibs for Frida-related names.
    /// 3. Check for the FridaGadget environment variable.
    private static func checkForFrida() -> Bool {
        // Check 1: Frida default port
        if isFridaPortOpen() { return true }

        // Check 2: Frida dylibs in loaded images
        if isFridaDylibLoaded() { return true }

        // Check 3: Frida environment variables
        if isFridaEnvSet() { return true }

        return false
    }

    /// Checks if Frida's default port (27042) is listening.
    private static func isFridaPortOpen() -> Bool {
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(27042).bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")

        let sock = socket(AF_INET, SOCK_STREAM, 0)
        guard sock >= 0 else { return false }

        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        close(sock)
        return result == 0 // 0 = connection succeeded = port is open
    }

    /// Scans loaded dynamic libraries for Frida-related names.
    ///
    /// When Frida injects into an iOS process, it loads dylibs with
    /// recognizable names like "FridaGadget" or "frida-agent".
    private static func isFridaDylibLoaded() -> Bool {
        let imageCount = _dyld_image_count()

        for i in 0..<imageCount {
            guard let imageName = _dyld_get_image_name(i) else { continue }
            let name = String(cString: imageName).lowercased()

            if name.contains("frida") || name.contains("gadget") {
                return true
            }
        }

        return false
    }

    /// Checks for Frida-related environment variables.
    private static func isFridaEnvSet() -> Bool {
        let fridaEnvVars = [
            "FRIDA_AGENT_PATH",
            "FRIDA_GADGET_CONFIG"
        ]

        for envVar in fridaEnvVars {
            if ProcessInfo.processInfo.environment[envVar] != nil {
                return true
            }
        }

        return false
    }

    // =========================================================================
    // JAILBREAK DETECTION (supplementary)
    // =========================================================================

    /// Additional jailbreak detection checks.
    ///
    /// These supplement flutter_jailbreak_detection with native checks:
    /// 1. Check for common jailbreak files and directories.
    /// 2. Check for unauthorized URL schemes (Cydia, Sileo).
    /// 3. Check if the app can write outside its sandbox.
    /// 4. Check for symbolic links in system directories.
    ///
    /// IMPORTANT: These checks should be performed from native code
    /// because Dart-side checks can be more easily bypassed by hooking
    /// the method channel.
    private static func checkForJailbreak() -> Bool {
        // Check 1: Jailbreak-related files
        let jailbreakPaths = [
            "/Applications/Cydia.app",
            "/Applications/Sileo.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/usr/bin/ssh",
            "/private/var/lib/apt",
            "/private/var/lib/cydia",
            "/private/var/stash",
            "/var/cache/apt",
            "/var/lib/cydia",
            "/var/tmp/cydia.log",
            "/usr/libexec/cydia",
        ]

        for path in jailbreakPaths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }

        // Check 2: Cydia URL scheme
        if let url = URL(string: "cydia://package/com.example.package") {
            if UIApplication.shared.canOpenURL(url) {
                return true
            }
        }

        // Check 3: Write outside sandbox
        // On a non-jailbroken device, the app cannot write to /private.
        let testPath = "/private/jailbreak_test_\(UUID().uuidString)"
        do {
            try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
            // If we got here, writing succeeded — device is jailbroken.
            try? FileManager.default.removeItem(atPath: testPath)
            return true
        } catch {
            // Write failed — expected on non-jailbroken devices.
        }

        // Check 4: Fork detection
        // Non-jailbroken apps cannot fork processes.
        // Calling fork() returns -1 on a sandboxed app.
        #if !targetEnvironment(simulator)
        let forkResult = fork()
        if forkResult >= 0 {
            // Fork succeeded — device is jailbroken.
            if forkResult > 0 {
                // Parent process — kill the child.
                kill(forkResult, SIGTERM)
            }
            return true
        }
        #endif

        return false
    }
}
