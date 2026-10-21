import type { Metadata, Viewport } from "next";
import { Asap, Open_Sans } from "next/font/google";

import "./globals.css";

// design.md §4: exactly two families
const heading = Asap({ subsets: ["latin"], weight: ["700", "800"], variable: "--font-heading" });
const body = Open_Sans({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-body",
});

export const metadata: Metadata = {
  title: "VibeGuard",
  description: "Security hardening for vibe-coded web apps",
};

export const viewport: Viewport = { themeColor: "#09090B" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${heading.variable} ${body.variable}`}>
      <body>{children}</body>
    </html>
  );
}
