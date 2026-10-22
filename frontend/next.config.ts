import type { NextConfig } from "next";

// The browser only ever talks to this origin; Next proxies /api/v1 to FastAPI.
// Rewrites are compiled at build time: in Docker this comes from the VIBEGUARD_API_URL build arg.
const API_URL = process.env.VIBEGUARD_API_URL ?? "http://localhost:8000";

const SECURITY_HEADERS = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
];

const config: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  output: "standalone", // self-contained server for the Docker image
  async rewrites() {
    return [{ source: "/api/v1/:path*", destination: `${API_URL}/api/v1/:path*` }];
  },
  async headers() {
    return [{ source: "/:path*", headers: SECURITY_HEADERS }];
  },
};

export default config;
