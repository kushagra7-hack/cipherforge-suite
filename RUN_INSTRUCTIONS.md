# How to Run CipherForge

This guide explains how to spin up the web and mobile applications for local development.

---

## 1. Web App (`cipherforge-web`)

The web application is built with React 19 and Next.js 15.

### Prerequisites
- Node.js (v18 or higher)
- npm (v9 or higher)

### Installation & Running

1. Navigate to the web directory:
   ```bash
   cd cipherforge-web
   ```
2. Install the necessary dependencies:
   ```bash
   npm install
   ```
3. Start the development server:
   ```bash
   npm run dev
   ```
4. Open your browser and navigate to `http://localhost:3000`.

*Note: The Next.js dev server uses Hot Module Replacement (HMR). A WebSocket runs on `ws://localhost:3000` during development, but is removed in production builds where HTTPS and HSTS are strictly enforced.*

---

## 2. Mobile Vault (`cipherforge-mobile`)

The mobile vault is built using the Flutter framework.

### Prerequisites
- Flutter SDK (latest stable release)
- Android Studio (for Android emulator) or Xcode (for iOS simulator)

### Installation & Running

1. Navigate to the mobile directory:
   ```bash
   cd cipherforge-mobile
   ```
2. Fetch the Flutter dependencies:
   ```bash
   flutter pub get
   ```
3. Run the application on your connected device or emulator:
   ```bash
   flutter run
   ```

### Security Notes for Emulators
- **Root/Jailbreak Detection:** The app includes root and jailbreak detection (via `environment_integrity_service.dart`). If you run this on a rooted emulator, the app will instantly lock and exit for security reasons. You must use a standard, non-rooted emulator.
- **Biometrics:** To test the biometric login feature on an emulator, use the emulator's extended controls to simulate a fingerprint touch or Face ID match.
