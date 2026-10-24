"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { AuthModal } from "@/components/auth/AuthModal";
import { useAuth } from "@/components/auth/AuthProvider";
import { cn } from "@/lib/format";
import { savePendingScan, takePendingScan } from "@/lib/pendingScan";
import { normalizeTarget } from "@/lib/target";

/**
 * The hook: paste a repo and it starts scanning in the dashboard. Signed-out visitors get the
 * sign-in modal first; the repo waits in sessionStorage and /scan starts it after sign-in.
 */
export function HeroScan() {
  const router = useRouter();
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [gate, setGate] = useState<string | null>(null);
  const { status } = useAuth();

  function submit(e: React.FormEvent) {
    e.preventDefault();
    const target = normalizeTarget(value);
    if (!target || !("repo_url" in target)) {
      setError("Paste a GitHub repository, e.g. https://github.com/username/my-vibe-project");
      return;
    }
    savePendingScan(target.repo_url);
    // "disabled" = no Firebase (local dev): the dashboard runs open
    if (status === "signed-in" || status === "unverified" || status === "disabled") router.push("/scan");
    else setGate(target.repo_url);
  }

  return (
    <form onSubmit={submit} noValidate className="w-full max-w-[820px]">
      <AuthModal
        open={gate !== null}
        repo={gate}
        onClose={() => {
          // Dismissed without signing in: don't start it behind their back later
          takePendingScan();
          setGate(null);
        }}
        onSignedIn={() => router.push("/scan")}
      />
      <label htmlFor="repo" className="sr-only">
        GitHub repository URL
      </label>
      <div
        className={cn(
          "flex flex-col overflow-hidden rounded-ctl border-2 bg-carbon transition-[box-shadow,border-color] duration-[60ms] ease-linear sm:flex-row",
          "focus-within:border-bone focus-within:shadow-hard-secure",
          error ? "border-risk" : "border-hairline",
        )}
      >
        <input
          id="repo"
          value={value}
          onChange={(e) => {
            setValue(e.target.value);
            setError(null);
          }}
          placeholder="https://github.com/username/my-vibe-project"
          autoComplete="off"
          spellCheck={false}
          aria-invalid={Boolean(error)}
          aria-describedby={error ? "repo-error" : "repo-hint"}
          className="h-14 min-w-0 flex-1 bg-transparent px-4 font-mono text-[14px] text-bone outline-none placeholder:text-ash/60 sm:h-16"
        />
        <button
          type="submit"
          className="btn btn-primary h-14 shrink-0 !rounded-none border-0 border-t-2 border-t-hairline px-6 text-[14px] sm:h-auto sm:border-l-2 sm:border-t-0 sm:border-l-hairline"
        >
          Scan repository <span aria-hidden>→</span>
        </button>
      </div>
      {error ? (
        <p id="repo-error" role="alert" className="mt-3 text-[13px] text-risk">
          {error}
        </p>
      ) : (
        <p id="repo-hint" className="mt-3 text-[12px] text-ash">
          Free for public repos <Dot /> Route code only reaches the LLM <Dot /> Re-parsed AST fixes
        </p>
      )}
    </form>
  );
}

function Dot() {
  return (
    <span aria-hidden className="mx-1.5 text-hairline">
      •
    </span>
  );
}
