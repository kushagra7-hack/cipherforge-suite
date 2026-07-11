/**
 * ============================================================================
 * cryptoUtils.ts — Production-Ready Cryptographic Password Utilities
 * ============================================================================
 *
 * All randomness is derived from the Web Crypto API (crypto.getRandomValues).
 * Math.random() is NEVER used — it is not cryptographically secure.
 *
 * Features:
 *   1. Secure random password generation with configurable character pools
 *   2. Diceware passphrase generation using secure random word selection
 *   3. Shannon entropy calculation with strength categorization
 *
 * @author Security-First Password Generator
 * @license MIT
 */

// ─── Character Pool Definitions ─────────────────────────────────────────────

/** Uppercase ASCII letters A-Z */
const UPPERCASE_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

/** Lowercase ASCII letters a-z */
const LOWERCASE_CHARS = 'abcdefghijklmnopqrstuvwxyz';

/** Numeric digits 0-9 */
const NUMBER_CHARS = '0123456789';

/**
 * Strict symbol set — avoids ambiguous or encoding-problematic characters.
 * Excludes: backtick, pipe, backslash, quotes (single/double) to prevent
 * injection issues in various contexts (SQL, HTML, shell, URLs).
 */
const SYMBOL_CHARS = '!@#$%^&*()-_=+[]{}<>?,.:;~';

// ─── Type Definitions ───────────────────────────────────────────────────────

/** Configuration options for password generation */
export interface PasswordOptions {
  /** Desired password length (min: 4 when all pools enabled, max: 128) */
  length: number;
  /** Include uppercase letters (A-Z) */
  uppercase: boolean;
  /** Include lowercase letters (a-z) */
  lowercase: boolean;
  /** Include numeric digits (0-9) */
  numbers: boolean;
  /** Include symbols (!@#$%^&*...) */
  symbols: boolean;
}

/** Entropy strength categories */
export type EntropyCategory = 'Weak' | 'Good' | 'Excellent';

/** Result of entropy calculation */
export interface EntropyResult {
  /** Shannon entropy in bits */
  bits: number;
  /** Human-readable strength category */
  category: EntropyCategory;
  /** Percentage score (0-100, capped at 128 bits = 100%) */
  percentage: number;
}

// ─── Secure Random Number Generation ────────────────────────────────────────

/**
 * Generates a cryptographically secure random integer in [0, max).
 *
 * Uses rejection sampling to avoid modulo bias:
 * - Calculates the largest multiple of `max` that fits in 32 bits
 * - Rejects values >= that threshold and re-rolls
 * - This ensures perfectly uniform distribution
 *
 * @param max - Upper bound (exclusive). Must be > 0.
 * @returns A uniformly distributed random integer in [0, max)
 */
function secureRandomInt(max: number): number {
  if (max <= 0) throw new Error('secureRandomInt: max must be > 0');
  if (max === 1) return 0;

  // Create a typed array for one 32-bit unsigned integer
  const randomBuffer = new Uint32Array(1);

  // Calculate rejection threshold to eliminate modulo bias.
  // Any value >= threshold would cause non-uniform distribution.
  const threshold = (0x100000000 - max) % max; // 2^32 - max, mod max

  // Rejection sampling loop — statistically terminates in ~1-2 iterations
  let randomValue: number;
  do {
    crypto.getRandomValues(randomBuffer);
    randomValue = randomBuffer[0];
  } while (randomValue < threshold);

  return randomValue % max;
}

// ─── Fisher-Yates Secure Shuffle ────────────────────────────────────────────

/**
 * Shuffles an array in-place using the Fisher-Yates algorithm
 * with cryptographically secure random swaps.
 *
 * @param array - Array to shuffle (mutated in-place)
 * @returns The shuffled array (same reference)
 */
function secureShuffleArray<T>(array: T[]): T[] {
  // Traverse from the last element to the second
  for (let i = array.length - 1; i > 0; i--) {
    // Pick a random index in [0, i]
    const j = secureRandomInt(i + 1);
    // Swap elements at positions i and j
    [array[i], array[j]] = [array[j], array[i]];
  }
  return array;
}

// ─── Password Generation ────────────────────────────────────────────────────

/**
 * Generates a cryptographically secure random password.
 *
 * Security guarantees:
 * - Uses only crypto.getRandomValues() for randomness
 * - Guarantees at least one character from each enabled pool
 * - Uses Fisher-Yates shuffle to prevent positional bias
 * - Rejection sampling eliminates modulo bias
 *
 * @param options - Configuration for character pools and length
 * @returns Generated password string
 * @throws Error if no character pools are enabled or length is too short
 */
export function generatePassword(options: PasswordOptions): string {
  const { length, uppercase, lowercase, numbers, symbols } = options;

  // ── Build the combined character pool ──
  let pool = '';
  const requiredChars: string[] = []; // Guarantees at least one from each pool

  if (uppercase) {
    pool += UPPERCASE_CHARS;
    // Select one guaranteed character from this pool
    requiredChars.push(UPPERCASE_CHARS[secureRandomInt(UPPERCASE_CHARS.length)]);
  }
  if (lowercase) {
    pool += LOWERCASE_CHARS;
    requiredChars.push(LOWERCASE_CHARS[secureRandomInt(LOWERCASE_CHARS.length)]);
  }
  if (numbers) {
    pool += NUMBER_CHARS;
    requiredChars.push(NUMBER_CHARS[secureRandomInt(NUMBER_CHARS.length)]);
  }
  if (symbols) {
    pool += SYMBOL_CHARS;
    requiredChars.push(SYMBOL_CHARS[secureRandomInt(SYMBOL_CHARS.length)]);
  }

  // Validate: at least one pool must be enabled
  if (pool.length === 0) {
    throw new Error('At least one character pool must be enabled.');
  }

  // Validate: length must accommodate all required chars
  const minLength = requiredChars.length;
  const effectiveLength = Math.max(length, minLength);
  const clampedLength = Math.min(effectiveLength, 128);

  // ── Build password array ──
  const passwordChars: string[] = [...requiredChars];

  // Fill remaining slots with random characters from the combined pool
  const remainingSlots = clampedLength - requiredChars.length;
  for (let i = 0; i < remainingSlots; i++) {
    passwordChars.push(pool[secureRandomInt(pool.length)]);
  }

  // ── Shuffle to randomize positions ──
  // Without this, guaranteed chars would always be at the start
  secureShuffleArray(passwordChars);

  return passwordChars.join('');
}

// ─── Diceware Passphrase Generation ─────────────────────────────────────────

/**
 * Generates a Diceware-style passphrase using cryptographically secure
 * random word selection from the provided wordlist.
 *
 * Diceware passphrases offer excellent entropy with memorability:
 * - 5 words from a 7,776-word list ≈ 64.6 bits of entropy
 * - 6 words ≈ 77.5 bits
 * - 7 words ≈ 90.5 bits
 *
 * @param wordlist - Array of words to select from (typically EFF wordlist)
 * @param wordCount - Number of words to include (default: 6)
 * @param separator - Character(s) to separate words (default: '-')
 * @returns Generated passphrase string
 */
export function generatePassphrase(
  wordlist: string[],
  wordCount: number = 6,
  separator: string = '-'
): string {
  if (!wordlist || wordlist.length === 0) {
    throw new Error('Wordlist must contain at least one word.');
  }
  if (wordCount < 1) {
    throw new Error('Word count must be at least 1.');
  }

  const selectedWords: string[] = [];

  for (let i = 0; i < wordCount; i++) {
    // Select a random index into the wordlist using secure randomness
    const randomIndex = secureRandomInt(wordlist.length);
    selectedWords.push(wordlist[randomIndex]);
  }

  return selectedWords.join(separator);
}

// ─── Shannon Entropy Calculation ────────────────────────────────────────────

/**
 * Calculates the Shannon entropy of a password string.
 *
 * Shannon entropy measures the information content based on character
 * frequency distribution. It answers: "How many bits of information
 * does each character contribute on average?"
 *
 * Formula: H = -Σ (p_i × log2(p_i)) × length
 *
 * Where p_i is the probability (frequency ratio) of each unique character.
 *
 * Categorization thresholds:
 * - Weak:      < 50 bits  (easily brute-forced)
 * - Good:      50-70 bits (resistant to most attacks)
 * - Excellent: > 70 bits  (computationally infeasible to crack)
 *
 * @param password - The password string to analyze
 * @returns EntropyResult with bits, category, and percentage
 */
export function calculateEntropy(password: string): EntropyResult {
  // Edge case: empty string has zero entropy
  if (!password || password.length === 0) {
    return { bits: 0, category: 'Weak', percentage: 0 };
  }

  const len = password.length;

  // ── Step 1: Count frequency of each unique character ──
  const frequencyMap = new Map<string, number>();
  for (const char of password) {
    frequencyMap.set(char, (frequencyMap.get(char) || 0) + 1);
  }

  // ── Step 2: Calculate Shannon entropy per character ──
  // H = -Σ (p_i × log2(p_i))
  let entropyPerChar = 0;
  for (const count of frequencyMap.values()) {
    const probability = count / len; // p_i = frequency / total length
    if (probability > 0) {
      // Each unique character contributes: -p * log2(p)
      entropyPerChar -= probability * Math.log2(probability);
    }
  }

  // ── Step 3: Total entropy = per-character entropy × password length ──
  const totalBits = entropyPerChar * len;

  // ── Step 4: Categorize the strength ──
  let category: EntropyCategory;
  if (totalBits < 50) {
    category = 'Weak';
  } else if (totalBits <= 70) {
    category = 'Good';
  } else {
    category = 'Excellent';
  }

  // ── Step 5: Calculate percentage (capped at 128 bits = 100%) ──
  // 128 bits is considered the gold standard for symmetric key strength
  const percentage = Math.min((totalBits / 128) * 100, 100);

  return {
    bits: Math.round(totalBits * 100) / 100, // Round to 2 decimal places
    category,
    percentage: Math.round(percentage * 100) / 100,
  };
}
