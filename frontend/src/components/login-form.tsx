"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import React, { useEffect, useState } from "react";

import { authErrorMessage, useAuth } from "@/components/auth/AuthProvider";
import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";
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
  if (typeof window === "undefined") return "/";
  return safeNext(new URLSearchParams(window.location.search).get("next"));
}

export function LoginForm({ className, ...props }: React.ComponentProps<"div">) {
  const router = useRouter();
  const { status, signInWithEmail, signUpWithEmail, signInWithGoogle, resetPassword } = useAuth();
  const [mode, setMode] = useState<Mode>("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState<"form" | "google" | null>(null);
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

  async function run(kind: "form" | "google", fn: () => Promise<void>) {
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
          <h1 className="font-heading text-lg font-bold uppercase tracking-wider text-bone">
            Sign-in isn&apos;t configured
          </h1>
          <p className="mt-3 text-[13px] leading-relaxed text-ash">
            No Firebase project is set (<code className="code text-bone">NEXT_PUBLIC_FIREBASE_*</code>),
            so the dashboard runs open against a local dev backend. See{" "}
            <Link href="/docs#authentication" className="text-secure underline-offset-4 hover:underline">
              Docs → Authentication
            </Link>{" "}
            to turn it on.
          </p>
          <Button className="mt-6 w-full" onClick={() => router.push("/")}>
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
          <div className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 bg-secure" />
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
                <svg className="h-4 w-4" aria-hidden="true" viewBox="0 0 24 24">
                  <path
                    d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                    fill="#4285F4"
                  />
                  <path
                    d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                    fill="#34A853"
                  />
                  <path
                    d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                    fill="#FBBC05"
                  />
                  <path
                    d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                    fill="#EA4335"
                  />
                </svg>
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
