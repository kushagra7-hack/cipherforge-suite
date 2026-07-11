Act as a senior cybersecurity software engineer. I am building a client-side only Next.js password generator. 

Write a comprehensive TypeScript utility file (`cryptoUtils.ts`) that handles:
1.  **Secure Random Generation:** A function to generate passwords using `crypto.getRandomValues`. It must accept parameters for length, uppercase, lowercase, numbers, and strict symbol sets. Ensure it guarantees at least one character from each selected pool.
2.  **Diceware Passphrases:** A function that takes a wordlist array and generates a passphrase separated by hyphens using secure random selection.
3.  **Shannon Entropy Calculation:** A function that calculates the actual bits of entropy of a given password string and categorizes it into 'Weak' (< 50 bits), 'Good' (50-70 bits), and 'Excellent' (> 70 bits).

Provide clean, heavily commented, production-ready TypeScript code. Do not use Math.random() anywhere.Now, add a breach-checking utility to our Next.js project (`breachCheck.ts`). 

Implement a function that checks if a password has been compromised using the 'Have I Been Pwned' API via the k-Anonymity model. 
1. The function should hash the plain text password using SHA-1 (using the Web Crypto API, not external libraries if possible).
2. Split the hash into a 5-character prefix and the remaining suffix.
3. Fetch the API (`https://api.pwnedpasswords.com/range/{prefix}`).
4. Parse the plain text response to see if the suffix exists in the returned list, and if so, extract the breach count.
5. Handle network errors and rate limiting gracefully.Using the `cryptoUtils.ts` and `breachCheck.ts` files from our previous steps, build the main Next.js user interface (`page.tsx`). 

Use Tailwind CSS to create a modern, dark-mode focused UI. Requirements:
1.  A large, prominent display for the generated password with a "Copy to Clipboard" button.
2.  Toggles for Uppercase, Lowercase, Numbers, and Symbols, plus a slider for Length (8 to 128).
3.  A toggle switch to change between "Password" mode and "Passphrase" (Diceware) mode.
4.  A dynamic progress bar that visually represents the Shannon entropy score (red for weak, yellow for good, green for excellent) calculated in real-time as settings change.
5.  A "Check if Breached" button that calls the k-Anonymity function and displays the result in a small alert banner.

Ensure all state is managed via React `useState` and `useEffect`. Add a footer banner clearly stating: "100% Client-Side. No data is transmitted or stored."Act as a senior mobile and desktop security engineer. I am building a local-first password manager in Flutter.

First, write the Dart cryptographic utility class (`security_engine.dart`). 
1. Use the `argon2` or `pointycastle` package to implement a key derivation function. It should take a user's Master Password and a generated Salt, returning a 256-bit key.
2. Use the `encrypt` package to create AES-256-GCM encryption and decryption functions. It must generate a secure IV (Initialization Vector) for every encryption operation and prepend it to the ciphertext.
3. Use `dart:math` `Random.secure()` to port the password generation and entropy calculation logic into Dart.Now, let's build the local storage architecture (`vault_repository.dart`).

1. Use `flutter_secure_storage` to securely store the user's random Salt and an authentication check hash (to verify the master password is correct without storing the password itself).
2. Outline a local SQLite implementation using `sqflite`. The database should have a table called `vault_items` with columns: `id`, `title`, `encrypted_data`, `created_at`, `updated_at`. 
3. Write the CRUD operations. The `encrypted_data` column will store a JSON string (containing username, URL, password, notes) that has been encrypted via the AES-256-GCM functions from `security_engine.dart`.Design the Flutter login screen (`auth_screen.dart`). 

Requirements:
1. A clean, minimalist UI where the user enters their Master Password to unlock the vault.
2. Integration with the `local_auth` package to allow FaceID / TouchID / Windows Hello to unlock the app (this should securely retrieve a stored master key from the Secure Enclave/Keystore if enabled).
3. If the user fails authentication 5 times, implement a 30-second lockout timer.Create the main Vault Dashboard (`vault_screen.dart`) for the Flutter app.

1. Implement a `ListView.builder` that displays the decrypted titles of the saved passwords. (Assume the database decryption happens in a background isolate or state management layer).
2. When a user taps an item, show a bottom sheet with the credentials.
3. **Critical Security Feature:** Implement a "Copy Password" button. When tapped, copy the password to the system clipboard, show a SnackBar confirming the copy, and start a timer using `Timer` from `dart:async` that automatically overwrites/clears the clipboard after 30 seconds to prevent clipboard snooping.Add a "Security Audit" screen to the Flutter application. 

Write the Dart logic and UI that iterates through all decrypted passwords in the vault and categorizes them:
1. **Reused Passwords:** Identify if the exact same password is used for multiple different entries.
2. **Weak Passwords:** Filter passwords that have a Shannon entropy score below 50.
3. **Breached Passwords:** Create an asynchronous batch process that runs the k-Anonymity SHA-1 check on the stored passwords and flags any that appear in data breaches. 

Display these metrics in a modern dashboard with pie charts (using `fl_chart`) and actionable lists so the user can easily update vulnerable credentials.Act as an enterprise mobile application penetration tester and Flutter security engineer. Write a Dart service (`environment_integrity_service.dart`) that establishes a baseline of trust before the application allows any cryptographic keys to be processed.

Implement the following checks utilizing packages like `flutter_jailbreak_detection` or platform channels:
1. Root/Jailbreak Detection: Check if the device has been rooted or jailbroken. If true, fail open-securely by wiping any cached temporary files and terminating execution.
2. Debugger/Emulator Detection: Detect if a debugger is attached or if the application is running on an unapproved emulator.
3. Hook Detection Safeguards: Provide native platform hooks (Kotlin for Android, Swift for iOS) placeholder logic to check for tampering frameworks like Frida or Xposed.
4. Fail-Fast Implementation: Expose a single `Future<bool> verifyIntegrity()` method that must return true before the UI renders the authentication screen.Act as a systems security architect. Write a state management provider in Dart (`secure_session_manager.dart`) using `flutter_bloc` or `riverpod` that enforces strict data minimization in memory.

Requirements:
1. Never store the master key as a plain string. Store it as an obfuscated byte array (`Uint8List`) or inside a localized secure memory block.
2. Implement an App Lifecycle Observer using `WidgetsBindingObserver`. The moment the application state changes to `AppLifecycleState.paused`, `AppLifecycleState.inactive`, or `AppLifecycleState.detached`, explicitly clear the byte array from memory by overwriting it with zeroes (`fillRange(0, length, 0)`), lock the vault, and route the user back to the authentication screen.
3. Implement item-level decryption: Do not decrypt the whole database array into a state object. Write a method `Future<String> decryptSingleField(String encryptedData)` that decrypts a specific entry on-demand when clicked, immediately disposing of the plaintext variable after the UI renders it.Write a Flutter security module (`hardware_vault_binder.dart`) that binds vault access directly to the device's hardware secure enclave or cryptographic coprocessor.

1. Use the `local_auth` package to enforce biometric authentication (Face ID, Touch ID, or biometric credentials).
2. Configure the authentication settings explicitly to require `biometricOnly: true` and set `stickyAuth: false` to ensure authentication drops immediately if interrupted.
3. Design a cryptographic flow where successful biometric authentication securely retrieves a high-entropy intermediate key from the OS Secure Keystore/Keychain (which was generated at first launch), which is then mixed with a user-entered PIN using SHA-256 to form the database decryption key. This ensures neither biometrics alone nor a stolen local database can compromise the vault.Implement a Flutter security utility (`runtime_shield.dart`) to prevent data leakage through the mobile operating system's built-in features.

Write native implementation instructions and Dart configurations for:
1. Screen Recording and Screenshot Blocking: Use native platform flags (e.g., `WindowManager.LayoutParams.FLAG_SECURE` in Android and an overlay window barrier in iOS) to completely block screenshots and prevent the app content from appearing in the system app switcher/recent apps preview pane.
2. Secure Keyboard Enforcement: Configure all password and credential text inputs with `obscureText: true`, `enableSuggestions: false`, and `autocorrect: false` to prevent third-party keyboards from caching sensitive inputs or broadcasting them to system clipboards.
3. Continuous Memory Wiping: Include a clean-up function that manually triggers garbage collection prompts or explicitly destroys sensitive temporary buffers after any generation or checking routine finishes.
