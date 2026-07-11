/**
 * ============================================================================
 * breachCheck.ts — Have I Been Pwned (HIBP) k-Anonymity Breach Checker
 * ============================================================================
 *
 * Checks if a password has appeared in known data breaches using the
 * HIBP Pwned Passwords API with the k-Anonymity model.
 *
 * HOW k-ANONYMITY WORKS:
 * 1. Hash the plaintext password with SHA-1
 * 2. Send ONLY the first 5 characters (prefix) to the API
 * 3. The API returns ~800 hash suffixes that match the prefix
 * 4. We check locally if our full suffix exists in the returned list
 *
 * PRIVACY GUARANTEE:
 * - The full hash is NEVER sent over the network
 * - Only 5 hex characters leave the browser — this matches ~800 hashes,
 *   making it impossible for the API to know which one is yours
 * - All comparison happens client-side
 *
 * @see https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange
 */

// ─── Type Definitions ───────────────────────────────────────────────────────

/** Result of a breach check operation */
export interface BreachCheckResult {
  /** Whether the password was found in any known data breach */
  breached: boolean;
  /** Number of times the password appeared in breaches (0 if not found) */
  count: number;
  /** Error message if the check failed (network error, rate limit, etc.) */
  error?: string;
}

// ─── SHA-1 Hashing via Web Crypto API ───────────────────────────────────────

/**
 * Computes the SHA-1 hash of a plaintext string using the Web Crypto API.
 *
 * NOTE: SHA-1 is used here ONLY because the HIBP API requires it.
 * SHA-1 is NOT cryptographically secure for general use — do NOT use
 * this function for password storage, signing, or integrity verification.
 *
 * @param plaintext - The string to hash
 * @returns Uppercase hexadecimal SHA-1 hash string (40 characters)
 */
async function sha1Hash(plaintext: string): Promise<string> {
  // Encode the plaintext string into a UTF-8 byte array
  const encoder = new TextEncoder();
  const data = encoder.encode(plaintext);

  // Compute SHA-1 digest using the Web Crypto API
  // This is hardware-accelerated in modern browsers
  const hashBuffer = await crypto.subtle.digest('SHA-1', data);

  // Convert the ArrayBuffer to a hexadecimal string
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');

  // HIBP expects uppercase hex
  return hashHex.toUpperCase();
}

// ─── HIBP API Integration ───────────────────────────────────────────────────

/** HIBP Pwned Passwords API base URL */
const HIBP_API_BASE = 'https://api.pwnedpasswords.com/range/';

/** Maximum time (ms) to wait for API response before timing out */
const REQUEST_TIMEOUT_MS = 10000;

/**
 * Checks if a password has been compromised in known data breaches
 * using the Have I Been Pwned (HIBP) Pwned Passwords API.
 *
 * Privacy model (k-Anonymity):
 * - Only the first 5 hex digits of the SHA-1 hash are sent to the API
 * - The remaining 35 hex digits are compared locally against returned data
 * - The API cannot determine which password is being checked
 *
 * @param password - The plaintext password to check
 * @returns Promise resolving to BreachCheckResult
 *
 * @example
 * const result = await checkBreach('password123');
 * // result = { breached: true, count: 247878 }
 */
export async function checkBreach(password: string): Promise<BreachCheckResult> {
  // ── Validate input ──
  if (!password || password.length === 0) {
    return { breached: false, count: 0, error: 'Empty password provided.' };
  }

  try {
    // ── Step 1: Hash the password with SHA-1 ──
    const hash = await sha1Hash(password);

    // ── Step 2: Split into prefix (5 chars) and suffix (35 chars) ──
    const prefix = hash.substring(0, 5);   // Sent to API
    const suffix = hash.substring(5);       // Compared locally — NEVER leaves browser

    // ── Step 3: Fetch matching hashes from HIBP API ──
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    const response = await fetch(`${HIBP_API_BASE}${prefix}`, {
      method: 'GET',
      headers: {
        // Add padding to prevent response-length fingerprinting
        'Add-Padding': 'true',
      },
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    // ── Handle HTTP error responses ──
    if (!response.ok) {
      // Rate limiting — HIBP allows ~1 request per 1500ms
      if (response.status === 429) {
        return {
          breached: false,
          count: 0,
          error: 'Rate limited by HIBP API. Please wait a moment and try again.',
        };
      }
      return {
        breached: false,
        count: 0,
        error: `HIBP API returned HTTP ${response.status}. Please try again later.`,
      };
    }

    // ── Step 4: Parse the plaintext response ──
    // Response format: each line is "SUFFIX:COUNT\r\n"
    // Example: "003D68EB55068C33ACE09247EE4C639306B:3"
    const responseText = await response.text();
    const lines = responseText.split('\n');

    for (const line of lines) {
      const trimmedLine = line.trim();
      if (!trimmedLine) continue;

      // Split each line into [hashSuffix, breachCount]
      const [hashSuffix, countStr] = trimmedLine.split(':');

      // ── Step 5: Compare our suffix with each returned suffix ──
      if (hashSuffix === suffix) {
        const count = parseInt(countStr, 10);
        return {
          breached: true,
          count: isNaN(count) ? 1 : count,
        };
      }
    }

    // Password hash suffix not found in any breach data
    return { breached: false, count: 0 };

  } catch (error: unknown) {
    // ── Handle network errors gracefully ──
    if (error instanceof DOMException && error.name === 'AbortError') {
      return {
        breached: false,
        count: 0,
        error: 'Request timed out. Check your internet connection.',
      };
    }

    if (error instanceof TypeError && error.message.includes('fetch')) {
      return {
        breached: false,
        count: 0,
        error: 'Network error. Unable to reach the breach database.',
      };
    }

    return {
      breached: false,
      count: 0,
      error: `Unexpected error: ${error instanceof Error ? error.message : 'Unknown error'}`,
    };
  }
}
