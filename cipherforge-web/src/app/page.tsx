"use client";

/**
 * ============================================================================
 * page.tsx — CipherForge: Secure Password Generator UI
 * ============================================================================
 *
 * Dark OLED Luxury interface (frontend-design-pro skill) featuring:
 *   - Glassmorphic password display with copy-to-clipboard
 *   - Toggle controls for character pools + range slider
 *   - Password ↔ Passphrase mode switch
 *   - Real-time Shannon entropy visualization
 *   - HIBP k-Anonymity breach checking
 *   - 100% client-side — no data transmitted
 *
 * Security approach (web_security_scanner skill):
 *   - All randomness from crypto.getRandomValues
 *   - No localStorage/sessionStorage usage
 *   - No inline scripts or eval()
 *   - CSP-compliant rendering
 */

import { useState, useEffect, useCallback } from "react";
import {
  generatePassword,
  generatePassphrase,
  calculateEntropy,
  type PasswordOptions,
  type EntropyResult,
} from "../utils/cryptoUtils";
import { checkBreach, type BreachCheckResult } from "../utils/breachCheck";
import { DICEWARE_WORDLIST } from "../utils/wordlist";

// ─── Type Definitions ───────────────────────────────────────────────────────

type GenerationMode = "password" | "passphrase";

interface BreachState {
  status: "idle" | "loading" | "safe" | "breached" | "error";
  count: number;
  message: string;
}

// ─── Main Page Component ────────────────────────────────────────────────────

export default function HomePage() {
  // ── Password Configuration State ──
  const [mode, setMode] = useState<GenerationMode>("password");
  const [length, setLength] = useState<number>(20);
  const [uppercase, setUppercase] = useState<boolean>(true);
  const [lowercase, setLowercase] = useState<boolean>(true);
  const [numbers, setNumbers] = useState<boolean>(true);
  const [symbols, setSymbols] = useState<boolean>(true);
  const [wordCount, setWordCount] = useState<number>(6);

  // ── Output State ──
  const [password, setPassword] = useState<string>("");
  const [entropy, setEntropy] = useState<EntropyResult>({
    bits: 0,
    category: "Weak",
    percentage: 0,
  });
  const [copied, setCopied] = useState<boolean>(false);
  const [breach, setBreach] = useState<BreachState>({
    status: "idle",
    count: 0,
    message: "",
  });

  // ── Generate Password/Passphrase ──
  const handleGenerate = useCallback(() => {
    try {
      let newPassword: string;

      if (mode === "passphrase") {
        newPassword = generatePassphrase(DICEWARE_WORDLIST, wordCount);
      } else {
        // Ensure at least one pool is enabled
        const hasPool = uppercase || lowercase || numbers || symbols;
        if (!hasPool) {
          setPassword("Enable at least one character type");
          setEntropy({ bits: 0, category: "Weak", percentage: 0 });
          return;
        }

        const options: PasswordOptions = {
          length,
          uppercase,
          lowercase,
          numbers,
          symbols,
        };
        newPassword = generatePassword(options);
      }

      setPassword(newPassword);
      setEntropy(calculateEntropy(newPassword));
      setBreach({ status: "idle", count: 0, message: "" });
      setCopied(false);
    } catch (err) {
      console.error("Generation error:", err);
      setPassword("Error generating password");
    }
  }, [mode, length, uppercase, lowercase, numbers, symbols, wordCount]);

  // ── Auto-generate on settings change ──
  useEffect(() => {
    handleGenerate();
  }, [handleGenerate]);

  // ── Manual Input Handler ──
  const handleManualInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = e.target.value;
    setPassword(val);
    setEntropy(calculateEntropy(val));
    setBreach({ status: "idle", count: 0, message: "" });
    setCopied(false);
  };

  // ── Copy to Clipboard ──
  const handleCopy = async () => {
    if (!password || password === "Enable at least one character type") return;

    try {
      await navigator.clipboard.writeText(password);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback for older browsers
      const textarea = document.createElement("textarea");
      textarea.value = password;
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  // ── Check Breach (HIBP k-Anonymity) ──
  const handleBreachCheck = async () => {
    if (!password || password === "Enable at least one character type") return;

    setBreach({ status: "loading", count: 0, message: "Checking breach databases..." });

    const result: BreachCheckResult = await checkBreach(password);

    if (result.error) {
      setBreach({ status: "error", count: 0, message: result.error });
    } else if (result.breached) {
      setBreach({
        status: "breached",
        count: result.count,
        message: `⚠ Found in ${result.count.toLocaleString()} data breach${result.count > 1 ? "es" : ""}!`,
      });
    } else {
      setBreach({
        status: "safe",
        count: 0,
        message: "✓ Not found in any known data breaches.",
      });
    }
  };

  // ── Entropy bar color class ──
  const entropyClass =
    entropy.category === "Weak"
      ? "weak"
      : entropy.category === "Good"
      ? "good"
      : "excellent";

  // ── Entropy color for text ──
  const entropyColor =
    entropy.category === "Weak"
      ? "var(--accent-danger)"
      : entropy.category === "Good"
      ? "var(--accent-warning)"
      : "var(--accent-success)";

  // ════════════════════════════════════════════════════════════════════════════
  // RENDER
  // ════════════════════════════════════════════════════════════════════════════

  return (
    <div
      style={{
        minHeight: "100vh",
        display: "flex",
        flexDirection: "column",
        position: "relative",
      }}
    >
      {/* ── Ambient Background Glow ── */}
      <div className="ambient-glow" />

      {/* ── Main Content ── */}
      <main
        style={{
          flex: 1,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          padding: "clamp(24px, 5vw, 60px) clamp(16px, 4vw, 40px)",
          position: "relative",
          zIndex: 1,
          maxWidth: "720px",
          margin: "0 auto",
          width: "100%",
          gap: "32px",
        }}
      >
        {/* ── Header ── */}
        <header
          className="animate-in"
          style={{ textAlign: "center", marginBottom: "8px" }}
        >
          <h1
            style={{
              fontFamily: "var(--font-display)",
              fontSize: "clamp(2rem, 5vw, 3.2rem)",
              fontWeight: 800,
              letterSpacing: "-0.03em",
              background: "linear-gradient(135deg, var(--accent-primary), #88f0ff, var(--accent-primary))",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
              backgroundClip: "text",
              lineHeight: 1.1,
              marginBottom: "12px",
            }}
          >
            CipherForge
          </h1>
          <p
            style={{
              fontFamily: "var(--font-body)",
              fontSize: "clamp(0.875rem, 1.5vw, 1rem)",
              color: "var(--text-secondary)",
              fontWeight: 400,
            }}
          >
            Cryptographically secure password generation
          </p>
        </header>

        {/* ── Mode Toggle ── */}
        <div
          className="animate-in animate-in-delay-1"
          style={{ display: "flex", justifyContent: "center" }}
        >
          <div className="mode-toggle" id="mode-toggle">
            <button
              className={`mode-toggle-btn ${mode === "password" ? "active" : ""}`}
              onClick={() => setMode("password")}
              id="mode-password"
              aria-pressed={mode === "password"}
            >
              Password
            </button>
            <button
              className={`mode-toggle-btn ${mode === "passphrase" ? "active" : ""}`}
              onClick={() => setMode("passphrase")}
              id="mode-passphrase"
              aria-pressed={mode === "passphrase"}
            >
              Passphrase
            </button>
          </div>
        </div>

        {/* ── Controls Card ── */}
        <div
          className="glass-card animate-in animate-in-delay-2"
          style={{ width: "100%", padding: "28px" }}
          id="controls-card"
        >
          {mode === "password" ? (
            <>
              {/* ── Length Slider ── */}
              <div style={{ marginBottom: "28px" }}>
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    marginBottom: "14px",
                  }}
                >
                  <label
                    htmlFor="length-slider"
                    style={{
                      fontFamily: "var(--font-body)",
                      fontSize: "0.875rem",
                      color: "var(--text-secondary)",
                      fontWeight: 500,
                    }}
                  >
                    Length
                  </label>
                  <span
                    style={{
                      fontFamily: "var(--font-mono)",
                      fontSize: "1.1rem",
                      color: "var(--accent-primary)",
                      fontWeight: 600,
                      minWidth: "36px",
                      textAlign: "right",
                    }}
                    id="length-value"
                  >
                    {length}
                  </span>
                </div>
                <input
                  type="range"
                  id="length-slider"
                  className="range-slider"
                  min={8}
                  max={128}
                  value={length}
                  onChange={(e) => setLength(parseInt(e.target.value))}
                  aria-label={`Password length: ${length}`}
                />
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    marginTop: "6px",
                  }}
                >
                  <span
                    style={{
                      fontFamily: "var(--font-mono)",
                      fontSize: "0.7rem",
                      color: "var(--text-tertiary)",
                    }}
                  >
                    8
                  </span>
                  <span
                    style={{
                      fontFamily: "var(--font-mono)",
                      fontSize: "0.7rem",
                      color: "var(--text-tertiary)",
                    }}
                  >
                    128
                  </span>
                </div>
              </div>

              {/* ── Character Pool Toggles ── */}
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(2, 1fr)",
                  gap: "16px",
                }}
              >
                <ToggleControl
                  id="toggle-uppercase"
                  label="Uppercase"
                  sublabel="A-Z"
                  active={uppercase}
                  onToggle={() => setUppercase(!uppercase)}
                />
                <ToggleControl
                  id="toggle-lowercase"
                  label="Lowercase"
                  sublabel="a-z"
                  active={lowercase}
                  onToggle={() => setLowercase(!lowercase)}
                />
                <ToggleControl
                  id="toggle-numbers"
                  label="Numbers"
                  sublabel="0-9"
                  active={numbers}
                  onToggle={() => setNumbers(!numbers)}
                />
                <ToggleControl
                  id="toggle-symbols"
                  label="Symbols"
                  sublabel="!@#$%"
                  active={symbols}
                  onToggle={() => setSymbols(!symbols)}
                />
              </div>
            </>
          ) : (
            /* ── Passphrase Controls ── */
            <div>
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  marginBottom: "14px",
                }}
              >
                <label
                  htmlFor="wordcount-slider"
                  style={{
                    fontFamily: "var(--font-body)",
                    fontSize: "0.875rem",
                    color: "var(--text-secondary)",
                    fontWeight: 500,
                  }}
                >
                  Word Count
                </label>
                <span
                  style={{
                    fontFamily: "var(--font-mono)",
                    fontSize: "1.1rem",
                    color: "var(--accent-primary)",
                    fontWeight: 600,
                  }}
                  id="wordcount-value"
                >
                  {wordCount}
                </span>
              </div>
              <input
                type="range"
                id="wordcount-slider"
                className="range-slider"
                min={3}
                max={10}
                value={wordCount}
                onChange={(e) => setWordCount(parseInt(e.target.value))}
                aria-label={`Passphrase word count: ${wordCount}`}
              />
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  marginTop: "6px",
                }}
              >
                <span
                  style={{
                    fontFamily: "var(--font-mono)",
                    fontSize: "0.7rem",
                    color: "var(--text-tertiary)",
                  }}
                >
                  3
                </span>
                <span
                  style={{
                    fontFamily: "var(--font-mono)",
                    fontSize: "0.7rem",
                    color: "var(--text-tertiary)",
                  }}
                >
                  10
                </span>
              </div>
              <p
                style={{
                  fontFamily: "var(--font-body)",
                  fontSize: "0.8rem",
                  color: "var(--text-tertiary)",
                  marginTop: "16px",
                  lineHeight: 1.5,
                }}
              >
                Diceware passphrases are easier to remember and provide excellent entropy.
                Each word adds ~10.3 bits of randomness.
              </p>
            </div>
          )}
        </div>

        {/* ── Password Display Card ── */}
        <div
          className="glass-card animate-in animate-in-delay-3"
          style={{ width: "100%", padding: "28px 28px 20px" }}
          id="password-display-card"
        >
          {/* Password Text */}
          <div
            style={{
              display: "flex",
              alignItems: "flex-start",
              gap: "16px",
              marginBottom: "20px",
            }}
          >
            <input
              type="text"
              className="password-display"
              style={{
                flex: 1,
                minHeight: "60px",
                display: "flex",
                alignItems: "center",
                background: "transparent",
                border: "none",
                outline: "none",
                width: "100%",
                fontFamily: "var(--font-mono)",
                color: "var(--text-primary)",
              }}
              value={password}
              onChange={handleManualInput}
              id="password-output"
              aria-live="polite"
              aria-label="Generated password"
              placeholder="Enter password to check..."
            />

            {/* Copy Button */}
            <button
              className={`copy-btn ${copied ? "copied" : ""}`}
              onClick={handleCopy}
              aria-label="Copy password to clipboard"
              id="copy-button"
              style={{
                flexShrink: 0,
                width: "44px",
                height: "44px",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                background: "transparent",
                border: "1px solid var(--border-subtle)",
                borderRadius: "var(--radius-md)",
                color: copied ? "var(--accent-success)" : "var(--text-secondary)",
                cursor: "pointer",
                fontSize: "1.2rem",
                transition: "all var(--transition-smooth)",
              }}
            >
              {copied ? "✓" : "⎘"}
            </button>
          </div>

          {/* Entropy Bar */}
          <div style={{ marginBottom: "10px" }}>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginBottom: "8px",
              }}
            >
              <span
                style={{
                  fontFamily: "var(--font-body)",
                  fontSize: "0.75rem",
                  color: "var(--text-tertiary)",
                  textTransform: "uppercase",
                  letterSpacing: "0.08em",
                  fontWeight: 600,
                }}
              >
                Entropy
              </span>
              <span
                style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: "0.8rem",
                  color: entropyColor,
                  fontWeight: 600,
                }}
                id="entropy-display"
              >
                {entropy.bits} bits · {entropy.category}
              </span>
            </div>
            <div className="entropy-bar-container" role="progressbar" aria-valuenow={entropy.percentage} aria-valuemin={0} aria-valuemax={100}>
              <div
                className={`entropy-bar-fill ${entropyClass}`}
                style={{ width: `${entropy.percentage}%` }}
              />
            </div>
          </div>
        </div>

        {/* ── Action Buttons ── */}
        <div
          className="animate-in animate-in-delay-4"
          style={{
            width: "100%",
            display: "flex",
            gap: "12px",
            flexWrap: "wrap",
          }}
        >
          {/* Regenerate Button */}
          <button
            onClick={handleGenerate}
            id="regenerate-button"
            aria-label="Generate new password"
            style={{
              flex: 1,
              minWidth: "140px",
              padding: "14px 24px",
              fontFamily: "var(--font-body)",
              fontSize: "0.9rem",
              fontWeight: 600,
              color: "var(--bg-void)",
              background: "linear-gradient(135deg, var(--accent-primary), var(--accent-primary-dim))",
              border: "none",
              borderRadius: "var(--radius-md)",
              cursor: "pointer",
              transition: "all var(--transition-smooth)",
              boxShadow: "0 0 20px rgba(0, 240, 255, 0.2)",
              letterSpacing: "0.02em",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.boxShadow = "0 0 32px rgba(0, 240, 255, 0.4)";
              e.currentTarget.style.transform = "translateY(-2px)";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.boxShadow = "0 0 20px rgba(0, 240, 255, 0.2)";
              e.currentTarget.style.transform = "translateY(0)";
            }}
          >
            ⟳ Regenerate
          </button>

          {/* Breach Check Button */}
          <button
            onClick={handleBreachCheck}
            disabled={breach.status === "loading"}
            id="breach-check-button"
            aria-label="Check if password has been breached"
            style={{
              flex: 1,
              minWidth: "140px",
              padding: "14px 24px",
              fontFamily: "var(--font-body)",
              fontSize: "0.9rem",
              fontWeight: 600,
              color: "var(--text-primary)",
              background: "transparent",
              border: "1px solid var(--border-subtle)",
              borderRadius: "var(--radius-md)",
              cursor: breach.status === "loading" ? "wait" : "pointer",
              transition: "all var(--transition-smooth)",
              opacity: breach.status === "loading" ? 0.6 : 1,
              letterSpacing: "0.02em",
            }}
            onMouseEnter={(e) => {
              if (breach.status !== "loading") {
                e.currentTarget.style.borderColor = "var(--border-active)";
                e.currentTarget.style.boxShadow = "0 0 16px rgba(0, 240, 255, 0.1)";
              }
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.borderColor = "var(--border-subtle)";
              e.currentTarget.style.boxShadow = "none";
            }}
          >
            {breach.status === "loading" ? "Checking..." : "🛡 Check if Breached"}
          </button>
        </div>

        {/* ── Breach Alert Banner ── */}
        {breach.status !== "idle" && (
          <div
            className={`alert-banner ${breach.status}`}
            style={{ width: "100%" }}
            id="breach-alert"
            role="alert"
          >
            <span>{breach.message}</span>
          </div>
        )}
      </main>

      {/* ── Security Footer ── */}
      <footer
        className="security-footer animate-in"
        style={{
          padding: "16px 24px",
          textAlign: "center",
          position: "relative",
          zIndex: 1,
        }}
        id="security-footer"
      >
        <p
          style={{
            fontFamily: "var(--font-body)",
            fontSize: "0.8rem",
            color: "var(--text-tertiary)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: "8px",
            fontWeight: 500,
            letterSpacing: "0.03em",
          }}
        >
          <span style={{ fontSize: "1rem" }}>🔒</span>
          100% Client-Side. No data is transmitted or stored.
        </p>
      </footer>
    </div>
  );
}

// ─── Toggle Control Sub-Component ───────────────────────────────────────────

interface ToggleControlProps {
  id: string;
  label: string;
  sublabel: string;
  active: boolean;
  onToggle: () => void;
}

function ToggleControl({ id, label, sublabel, active, onToggle }: ToggleControlProps) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "12px 16px",
        background: "rgba(255, 255, 255, 0.02)",
        borderRadius: "var(--radius-md)",
        border: "1px solid var(--border-subtle)",
        cursor: "pointer",
        transition: "all var(--transition-smooth)",
      }}
      onClick={onToggle}
      role="switch"
      aria-checked={active}
      aria-label={`${label} characters: ${active ? "enabled" : "disabled"}`}
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onToggle();
        }
      }}
    >
      <div>
        <div
          style={{
            fontFamily: "var(--font-body)",
            fontSize: "0.875rem",
            color: active ? "var(--text-primary)" : "var(--text-tertiary)",
            fontWeight: 500,
            transition: "color var(--transition-smooth)",
          }}
        >
          {label}
        </div>
        <div
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: "0.7rem",
            color: "var(--text-tertiary)",
            marginTop: "2px",
          }}
        >
          {sublabel}
        </div>
      </div>
      <div className={`toggle-switch ${active ? "active" : ""}`} id={id} />
    </div>
  );
}
