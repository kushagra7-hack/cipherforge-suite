import type { Metadata } from "next";
import { Outfit, DM_Sans, JetBrains_Mono } from "next/font/google";
import "./globals.css";

/**
 * ============================================================================
 * Root Layout — Dark OLED Luxury Password Generator
 * ============================================================================
 *
 * Typography System (per frontend-design-pro skill):
 *   - Outfit: Bold, geometric display font for headings
 *   - DM Sans: Clean, readable body font
 *   - JetBrains Mono: Monospace for password display
 *
 * NEVER uses Inter, Roboto, Arial, or system-ui (skill rule #5).
 */

// ─── Font Configuration ─────────────────────────────────────────────────────

const outfit = Outfit({
  subsets: ["latin"],
  variable: "--font-display",
  display: "swap",
  weight: ["400", "500", "600", "700", "800"],
});

const dmSans = DM_Sans({
  subsets: ["latin"],
  variable: "--font-body",
  display: "swap",
  weight: ["400", "500", "600", "700"],
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
  display: "swap",
  weight: ["400", "500", "600"],
});

// ─── SEO Metadata ───────────────────────────────────────────────────────────

export const metadata: Metadata = {
  title: "CipherForge — Secure Password Generator",
  description:
    "Generate cryptographically secure passwords and passphrases entirely client-side. Features Shannon entropy analysis, breach checking via HIBP k-Anonymity, and Diceware passphrase generation. Zero data transmission — 100% private.",
  keywords: [
    "password generator",
    "secure password",
    "passphrase generator",
    "diceware",
    "entropy",
    "breach check",
    "client-side",
    "cybersecurity",
    "HIBP",
    "have i been pwned",
  ],
  authors: [{ name: "CipherForge" }],
  robots: "index, follow",
  openGraph: {
    title: "CipherForge — Secure Password Generator",
    description:
      "100% client-side password generation with breach checking and entropy analysis.",
    type: "website",
    locale: "en_US",
  },
};

// ─── Root Layout Component ──────────────────────────────────────────────────

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${outfit.variable} ${dmSans.variable} ${jetbrainsMono.variable}`}
    >
      <head>
        {/* Security-first: prevent caching of sensitive page content */}
        <meta httpEquiv="Cache-Control" content="no-store, no-cache" />
        <meta httpEquiv="Pragma" content="no-cache" />
      </head>
      <body className="antialiased">
        {children}
      </body>
    </html>
  );
}
