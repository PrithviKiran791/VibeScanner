import type { Config } from "tailwindcss";

// Minimalist Dark Brutalism — see markdown/design.md §7
const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    borderRadius: { none: "0px" }, // every rounded-* utility except rounded-none is gone
    extend: {
      fontFamily: {
        heading: ["var(--font-heading)", "sans-serif"],
        sans: ["var(--font-body)", "sans-serif"],
      },
      colors: {
        obsidian: "#09090B",
        carbon: "#121216",
        graphite: "#1E1E24",
        hairline: "#27272A",
        ash: "#A1A1AA",
        bone: "#FAFAFA",
        risk: { DEFAULT: "#EF4444", dark: "#991B1B" },
        secure: { DEFAULT: "#10B981", dark: "#059669" },
      },
      borderWidth: { "1.5": "1.5px", "2": "2px" },
      boxShadow: {
        hard: "4px 4px 0px #27272A",
        "hard-risk": "4px 4px 0px #EF4444",
        "hard-secure": "4px 4px 0px #059669",
        "hard-pressed": "2px 2px 0px #27272A",
        none: "none",
      },
      backgroundImage: {
        "grad-risk": "linear-gradient(135deg, rgba(239, 68, 68, 0.18) 0%, rgba(9, 9, 11, 0) 100%)",
        "grad-secure":
          "linear-gradient(135deg, rgba(16, 185, 129, 0.18) 0%, rgba(9, 9, 11, 0) 100%)",
      },
      height: { nav: "64px" },
      spacing: { nav: "64px" },
    },
  },
  plugins: [],
};

export default config;
