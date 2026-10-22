"use client";

import { TopNav } from "@/components/nav/TopNav";
import { LoginForm } from "@/components/login-form";
import ShapeWaves from "@/components/ShapeWaves";

export default function LoginPage() {
  return (
    <>
      <TopNav />
      <main className="relative mx-auto flex min-h-[calc(100vh-64px)] w-full items-center justify-center px-4 pb-16 pt-[calc(64px+40px)] sm:px-6 overflow-hidden">
        {/* Interactive ShapeWaves Background */}
        <div className="pointer-events-none absolute inset-0 z-0 opacity-50">
          <ShapeWaves
            text="</>"
            fontFamily="var(--font-heading), sans-serif"
            fontWeight={800}
            textSize={0.6}
            shapes="mixed"
            cellSize={11}
            dotSize={0.75}
            color="#27272a"
            hoverColor="#10b981"
            backgroundColor="#09090b"
            speed={0.8}
            scale={1}
            contrast={1.1}
            brightness={0.4}
            flow={0.15}
            direction={45}
            fade={0.25}
            interactive={true}
            splashRadius={45}
            splashStrength={0.45}
            glow={0.35}
            intro={true}
            introDuration={1.6}
            paused={false}
          />
        </div>

        {/* Foreground Login Card */}
        <div className="relative z-10 w-full max-w-md">
          <LoginForm />
        </div>
      </main>
    </>
  );
}
