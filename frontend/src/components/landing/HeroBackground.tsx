"use client";

import ShapeWaves from "@/components/ShapeWaves";

/** ShapeWaves tuned for the hero. A client component so it can report WebGPU failures
 *  (unsupported browser, lost device) instead of failing silently. */
export function HeroBackground() {
  return (
    <div aria-hidden className="pointer-events-none absolute inset-0 z-0">
      <ShapeWaves
        text="</>"
        fontFamily="var(--font-heading), sans-serif"
        fontWeight={800}
        textSize={0.6}
        shapes="mixed"
        cellSize={11}
        dotSize={0.8}
        color="#3f3f46"
        hoverColor="#10b981"
        backgroundColor="#09090b"
        speed={0.8}
        brightness={0.55}
        contrast={1.2}
        flow={0.15}
        direction={45}
        fade={0.3}
        interactive
        splashRadius={50}
        splashStrength={0.5}
        glow={0.35}
        intro
        introDuration={1.6}
        onError={(err) => {
          console.warn("[VibeGuard] hero animation unavailable:", err.message);
          document.documentElement.dataset.heroError = err.message.slice(0, 200);
        }}
      />
    </div>
  );
}
