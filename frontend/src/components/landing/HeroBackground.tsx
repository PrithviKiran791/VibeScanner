"use client";

import ShapeWaves from "@/components/ShapeWaves";
import { resolveFontFamily } from "@/lib/canvasFont";

/** The hero's animated </> emblem: a lit dot field with the symbol cut out of it, framed as a
 *  brutalist panel beside the headline. A client component so WebGPU failures are reported
 *  instead of failing silently; without WebGPU the frame is just a dark block. */
export function HeroBackground() {
  return (
    <div
      aria-hidden
      className="relative h-[300px] overflow-hidden border-2 border-hairline bg-obsidian sm:h-[380px] lg:h-auto lg:min-h-[520px]"
    >
      <ShapeWaves
        text="</>"
        fontFamily={resolveFontFamily("--font-heading")}
        fontWeight={800}
        textSize={0.9}
        shapes="mixed"
        cellSize={10}
        dotSize={0.8}
        color="#8a8a93"
        hoverColor="#10b981"
        backgroundColor="#09090b"
        speed={0.9}
        brightness={0.45}
        contrast={1}
        flow={0.1}
        direction={45}
        fade={0.25}
        interactive
        splashRadius={45}
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
