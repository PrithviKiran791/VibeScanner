# UI/UX Design Specification (VibeGuard) — Minimalist Dark Brutalism

> This document supersedes the earlier "calm minimalism / atmospheric gradients" spec. Where the two disagree, this version wins.

## 1. Core Design Philosophy
VibeGuard shows **only what is required to understand and fix a vulnerability in seconds**, rendered as a raw, exposed architectural grid.

*   **Zero Bloat:** Finding cards carry exactly 3 data points. No nested accordions, no multi-axis charts, no sidebars, drawers, or breadcrumbs.
*   **Exposed Structure:** Solid, visible borders divide the viewport. Depth comes from hard offset shadows, never blur.
*   **Top-Down Ergonomics:** A single fixed top navigation bar controls the whole experience.

---

## 2. Geometry & Structure

| Rule | Value |
| :--- | :--- |
| **Border radius** | `0px` on cards, panels, nav, badges and code blocks (`rounded-none`). **Inputs and buttons use `rounded-ctl` (`10px`)**, defined once in `tailwind.config.ts` and applied through `.btn`, `.field` and the shadcn `Button`. |
| **Structural border width** | `2px` for layout dividers and cards; `1.5px` allowed for dense inner rows. |
| **Border colors** | `#27272A` default · `#EF4444` active critical · `#10B981` patched / safe. |
| **Blur** | Forbidden. No `blur()`, no `backdrop-filter`, no soft `box-shadow`. |

### 2.1 Hard Offset Shadows
| State | Shadow |
| :--- | :--- |
| Neutral hover | `box-shadow: 4px 4px 0px #27272A;` |
| Critical / vulnerability focus | `box-shadow: 4px 4px 0px #EF4444;` |
| Hardened / remediation CTA | `box-shadow: 4px 4px 0px #059669;` |

### 2.2 Mechanical Micro-interactions
On `:active` (and for the selected finding card), elements physically press in: `transform: translate(2px, 2px)` while the shadow collapses to `2px 2px 0px` (buttons) or `0 0 0` (full press). Transition: `transform 60ms linear, box-shadow 60ms linear` — no easing curves.

---

## 3. Color & Gradient Discipline (Red, Black, Grey, Green only)
No blue, purple, cyan, or neon accents.

### 3.1 Base Tokens
| Token | Hex | Application |
| :--- | :--- | :--- |
| `obsidian` | `#09090B` | Primary canvas, top nav (solid, not translucent) |
| `carbon` | `#121216` | Structural blocks, cards |
| `graphite` | `#1E1E24` | Hover fill, inputs, secondary buttons |
| `hairline` | `#27272A` | Default structural borders and neutral shadow |
| `ash` | `#A1A1AA` | Secondary text, file paths |
| `bone` | `#FAFAFA` | Primary text |

> Tokens are deliberately *not* named `slate-*` to avoid overriding Tailwind's built-in (blue-tinted) slate scale.

### 3.2 Semantic Accents
| Token | Hex | Meaning |
| :--- | :--- | :--- |
| `risk` | `#EF4444` | Vulnerable / exploitable, deleted diff rows |
| `risk-dark` | `#991B1B` | Pressed state of risk elements |
| `secure` | `#10B981` | Hardened, patched, primary CTA |
| `secure-dark` | `#059669` | CTA shadow, pressed state |

### 3.3 Industrial Gradients
*   **Critical card / deleted diff row (`-`):** `linear-gradient(135deg, rgba(239, 68, 68, 0.18) 0%, rgba(9, 9, 11, 0) 100%)`
*   **Hardened card / added diff row (`+`), score 80–100:** `linear-gradient(135deg, rgba(16, 185, 129, 0.18) 0%, rgba(9, 9, 11, 0) 100%)`
*   **Primary CTA:** solid `#10B981` with `#09090B` text and the green hard shadow. No gradient on buttons.

### 3.4 Score Banding
| Hardening Index | Treatment |
| :--- | :--- |
| 80–100 | `secure` border + green gradient |
| 60–79 | `hairline` border, neutral |
| 0–59 | `risk` border + red gradient |

---

## 4. Typography (exactly two families)
| Family | Use | Weights |
| :--- | :--- | :--- |
| **Asap** (Google Fonts; stands in for "Asap Sharp") | Headings, scores, severity tags, buttons — always `uppercase`, `letter-spacing: 0.06em` | 700, 800 |
| **Open Sans** | Body copy, explanations, file paths, code diffs | 400, 500, 600 |

Loaded via `next/font/google` and exposed as CSS variables `--font-heading` / `--font-body`.

### 4.1 Scale
*   **Score display:** Asap 800, 40px, line-height 1.0, tabular-nums.
*   **Panel header:** Asap 700, 18px, uppercase.
*   **Card title:** Asap 700, 14px, uppercase.
*   **Severity badge:** Asap 800, 11px, uppercase, `letter-spacing: 0.1em`.
*   **Body:** Open Sans 400, 14px, line-height 1.6, `ash`.
*   **Code & paths:** Open Sans 500, 13px, line-height 1.5, tabular-nums.

---

## 5. Layout

```
┌──────────────────────────────────────────────────────────────────────────┐
│ VIBEGUARD │ acme/vibe-app ▾ │                     │ SCORE 74 │ [RE-SCAN] │ ◄ 64px, 2px bottom border
├══════════════════════════════╦═══════════════════════════════════════════┤
│ ISSUES (4)                   ║ BROKEN AUTH (IDOR)                        │
│ ┌──────────────────────────┐ ║ app/api/user/[id]/route.ts : 24           │
│ │[CRITICAL]                │ ║───────────────────────────────────────────│
│ │BROKEN AUTH (IDOR)        │ ║ WHY IT MATTERS                            │
│ │app/api/user/route.ts:24  │ ║ URL params are trusted without a session  │
│ └──────────────────────────┘ ║ check.                                    │
│ ┌──────────────────────────┐ ║───────────────────────────────────────────│
│ │[CRITICAL]                │ ║ - db.user.find(req.params.id)             │ ◄ red gradient row
│ │EXPOSED STRIPE KEY        │ ║ + if (session.id !== params.id) …         │ ◄ green gradient row
│ │lib/stripe.ts:3           │ ║───────────────────────────────────────────│
│ └──────────────────────────┘ ║ [APPLY FIX (PR)]  [COPY DIFF]   dismiss   │
│            38%               ║                  62%                      │
└──────────────────────────────╨───────────────────────────────────────────┘
```

*   **Top nav:** fixed `64px`, solid `obsidian`, `2px` bottom border `hairline`. Left: wordmark + repo selector. Right: score pill + Re-scan.
*   **Workspace:** full viewport width below the nav; **38% / 62%** split by a continuous `2px` vertical border. Each column scrolls independently.
*   No sidebars, drawers, breadcrumbs, or modals for primary flows.

---

## 6. Information Discipline

| Element | Shows | Never shows |
| :--- | :--- | :--- |
| **Finding card (left)** | 1. Severity badge 2. Title 3. `file_path:line` | CWE, description, timestamps, avatars, category |
| **Inspector (right)** | Title, location, CWE, 2-sentence "Why it matters", unified diff (±3 context lines), actions | Full-file viewers, AST trees, CVSS vectors, external doc links |
| **Actions** | Apply Fix (PR) — green CTA · Copy Diff — neutral · Dismiss — muted text link | Configuration modals, wizards |

---

## 7. Tailwind Theme (v3.4)

```typescript
import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{ts,tsx,mdx}"],
  theme: {
    borderRadius: { none: "0px", ctl: "10px" }, // only these two exist; ctl = inputs and buttons
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
      borderWidth: { 1.5: "1.5px", 2: "2px" },
      boxShadow: {
        hard: "4px 4px 0px #27272A",
        "hard-risk": "4px 4px 0px #EF4444",
        "hard-secure": "4px 4px 0px #059669",
        "hard-pressed": "2px 2px 0px #27272A",
        none: "none",
      },
      backgroundImage: {
        "grad-risk": "linear-gradient(135deg, rgba(239, 68, 68, 0.18) 0%, rgba(9, 9, 11, 0) 100%)",
        "grad-secure": "linear-gradient(135deg, rgba(16, 185, 129, 0.18) 0%, rgba(9, 9, 11, 0) 100%)",
      },
      height: { nav: "64px" },
    },
  },
  plugins: [],
};

export default config;
```
