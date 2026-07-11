import type { NextConfig } from "next";

/**
 * ============================================================================
 * next.config.ts — Security-Hardened Configuration
 * ============================================================================
 *
 * Security headers applied per web_security_scanner skill principles:
 *   - Content Security Policy (CSP) — restricts script/style sources
 *   - X-Frame-Options — prevents clickjacking
 *   - X-Content-Type-Options — prevents MIME sniffing
 *   - Referrer-Policy — limits referrer information leakage
 *   - Permissions-Policy — disables unnecessary browser APIs
 *   - Strict-Transport-Security — enforces HTTPS
 */

const nextConfig: NextConfig = {
  // Security headers for all routes
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          {
            key: "Content-Security-Policy",
            value: [
              "default-src 'self'",
              // Allow Google Fonts for typography
              "font-src 'self' https://fonts.gstatic.com",
              "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
              // Allow HIBP API for breach checking
              "connect-src 'self' https://api.pwnedpasswords.com",
              // No eval(), no inline scripts (except Next.js hydration)
              "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
              "img-src 'self' data: blob:",
              "object-src 'none'",
              "base-uri 'self'",
              "form-action 'self'",
              "frame-ancestors 'none'",
            ].join("; "),
          },
          {
            // Prevent clickjacking — page cannot be embedded in iframes
            key: "X-Frame-Options",
            value: "DENY",
          },
          {
            // Prevent MIME type sniffing — browsers must respect Content-Type
            key: "X-Content-Type-Options",
            value: "nosniff",
          },
          {
            // Limit referrer information leaked to external sites
            key: "Referrer-Policy",
            value: "strict-origin-when-cross-origin",
          },
          {
            // Disable unnecessary browser APIs (camera, mic, geolocation, etc.)
            key: "Permissions-Policy",
            value:
              "camera=(), microphone=(), geolocation=(), interest-cohort=()",
          },
          {
            // Enforce HTTPS for 1 year (31536000 seconds)
            key: "Strict-Transport-Security",
            value: "max-age=31536000; includeSubDomains; preload",
          },
          {
            // Prevent DNS prefetching to reduce information leakage
            key: "X-DNS-Prefetch-Control",
            value: "off",
          },
        ],
      },
    ];
  },
};

export default nextConfig;
