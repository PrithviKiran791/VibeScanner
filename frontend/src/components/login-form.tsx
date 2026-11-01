"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import React, { useEffect, useState } from "react";

import { authErrorMessage, useAuth } from "@/components/auth/AuthProvider";
import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";
import { AppIcon } from "@/components/ui/AppIcon";
import { cn } from "@/lib/format";
import { safeNext } from "@/lib/session";

type Mode = "signin" | "signup" | "reset";

const COPY: Record<Mode, { title: string; subtitle: string; submit: string }> = {
  signin: {
    title: "Login to your account",
    subtitle: "Enter your email below to login to your account",
    submit: "Login",
  },
  signup: {
    title: "Create an account",
    subtitle: "We'll email you a link to verify the address",
    submit: "Sign up",
  },
  reset: {
    title: "Reset your password",
    subtitle: "We'll email you a link to choose a new one",
    submit: "Send reset link",
  },
};

/** Where to go after signing in: ?next=/scans/… (same-site paths only). */
function nextPath(): string {
  if (typeof window === "undefined") return "/scan";
  const next = safeNext(new URLSearchParams(window.location.search).get("next"));
  return next === "/" ? "/scan" : next; // "/" is the public landing page
}

export function LoginForm({ className, ...props }: React.ComponentProps<"div">) {
  const router = useRouter();
  const { status, signInWithEmail, signUpWithEmail, signInWithGitHub, signInWithGoogle, resetPassword } =
    useAuth();
  const [mode, setMode] = useState<Mode>("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState<"form" | "github" | "google" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // Signed in (or just signed up): RequireAuth on the destination handles verification
  useEffect(() => {
    if (status === "signed-in" || status === "unverified") router.replace(nextPath());
  }, [status, router]);

  function switchMode(next: Mode) {
    setMode(next);
    setError(null);
    setNotice(null);
  }

  async function run(kind: "form" | "github" | "google", fn: () => Promise<void>) {
    setBusy(kind);
    setError(null);
    setNotice(null);
    try {
      await fn();
    } catch (err) {
      setError(authErrorMessage(err));
    } finally {
      setBusy(null);
    }
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    void run("form", async () => {
      if (mode === "signin") await signInWithEmail(email, password);
      if (mode === "signup") {
        if (password.length < 8) throw { code: "auth/weak-password" };
        await signUpWithEmail(email, password);
      }
      if (mode === "reset") {
        await resetPassword(email);
        // Same message whether or not the account exists (no account enumeration)
        setNotice(`If an account exists for ${email}, a reset link is on its way.`);
        setMode("signin");
      }
    });
  };

  if (status === "disabled") {
    return (
      <div className={cn("flex flex-col gap-6", className)} {...props}>
        <div className="border-2 border-hairline bg-carbon p-6 shadow-hard sm:p-8">
          <div className="flex items-center gap-2.5">
            <AppIcon name="shield" size={22} alt="Security shield" />
            <h1 className="font-heading text-lg font-bold uppercase tracking-wider text-bone">
              Sign-in isn&apos;t configured
            </h1>
          </div>
          <p className="mt-3 text-[13px] leading-relaxed text-ash">
            No Firebase project is set (<code className="code text-bone">NEXT_PUBLIC_FIREBASE_*</code>),
            so the dashboard runs open against a local dev backend. See{" "}
            <Link href="/docs#authentication" className="text-secure underline-offset-4 hover:underline">
              Docs → Authentication
            </Link>{" "}
            to turn it on.
          </p>
          <Button className="mt-6 w-full" onClick={() => router.push("/scan")}>
            Continue to the dashboard
          </Button>
        </div>
      </div>
    );
  }

  const copy = COPY[mode];
  return (
    <div className={cn("flex flex-col gap-6", className)} {...props}>
      <div className="border-2 border-hairline bg-carbon p-6 sm:p-8 shadow-hard">
        <div className="mb-6 space-y-1.5">
          <div className="flex items-center gap-2.5">
            <AppIcon name="security" size={22} alt="Security" />
            <h1 className="font-heading text-lg font-bold uppercase tracking-wider text-bone">
              {copy.title}
            </h1>
          </div>
          <p className="text-[13px] text-ash">{copy.subtitle}</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4" noValidate>
          <div className="space-y-1.5">
            <label htmlFor="email" className="stamp block text-[11px] font-bold text-ash">
              Email
            </label>
            <input
              id="email"
              type="email"
              placeholder="m@example.com"
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className="field"
            />
          </div>

          {mode !== "reset" && (
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label htmlFor="password" className="stamp block text-[11px] font-bold text-ash">
                  Password
                </label>
                {mode === "signin" && (
                  <button
                    type="button"
                    onClick={() => switchMode("reset")}
                    className="text-[12px] text-ash underline-offset-4 hover:text-bone hover:underline"
                  >
                    Forgot your password?
                  </button>
                )}
              </div>
              <input
                id="password"
                type="password"
                autoComplete={mode === "signup" ? "new-password" : "current-password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                minLength={mode === "signup" ? 8 : undefined}
                className="field"
              />
            </div>
          )}

          {error && (
            <p role="alert" className="border-2 border-risk/60 px-3 py-2 text-[13px] text-risk">
              {error}
            </p>
          )}
          {notice && (
            <p role="status" className="border-2 border-secure/60 px-3 py-2 text-[13px] text-secure">
              {notice}
            </p>
          )}

          <Button type="submit" variant="default" className="w-full mt-2" disabled={busy !== null}>
            {busy === "form" && <Spinner className="size-4" />}
            {copy.submit}
          </Button>

          {mode !== "reset" && (
            <button
              type="button"
              className="btn h-10 w-full border-secure bg-obsidian text-bone hover:shadow-hard-secure flex items-center justify-center gap-2"
              disabled={busy !== null}
              onClick={() => run("github", signInWithGitHub)}
            >
              {busy === "github" ? <Spinner className="size-4 text-secure" /> : <AppIcon name="github" size={18} alt="GitHub" />}
              Login with GitHub
            </button>
          )}

          {mode !== "reset" && (
            <Button
              type="button"
              variant="neutral"
              className="w-full flex items-center justify-center gap-2"
              disabled={busy !== null}
              onClick={() => run("google", signInWithGoogle)}
            >
              {busy === "google" ? (
                <Spinner className="size-4" />
              ) : (
                <AppIcon name="social" size={18} alt="Google" />
              )}
              Login with Google
            </Button>
          )}

          <div className="pt-2 text-center text-[12px] text-ash">
            {mode === "signin" ? (
              <>
                Don&apos;t have an account?{" "}
                <button
                  type="button"
                  onClick={() => switchMode("signup")}
                  className="font-semibold text-bone underline-offset-4 hover:underline"
                >
                  Sign up
                </button>
              </>
            ) : (
              <>
                {mode === "signup" ? "Already have an account? " : "Remembered it? "}
                <button
                  type="button"
                  onClick={() => switchMode("signin")}
                  className="font-semibold text-bone underline-offset-4 hover:underline"
                >
                  Sign in
                </button>
              </>
            )}
          </div>
        </form>
      </div>
    </div>
  );
}
