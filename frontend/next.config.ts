import type { NextConfig } from "next";

// The browser only ever talks to this origin; Next proxies /api/v1 to FastAPI.
const API_URL = process.env.VIBEGUARD_API_URL ?? "http://localhost:8000";

const config: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  async rewrites() {
    return [{ source: "/api/v1/:path*", destination: `${API_URL}/api/v1/:path*` }];
  },
};

export default config;
