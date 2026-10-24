"use client";

import { X } from "lucide-react";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";

import { authErrorMessage, useAuth } from "@/components/auth/AuthProvider";
import { GitHubMark } from "@/components/auth/GitHubMark";
import { Spinner } from "@/components/ui/spinner";

/**
 * Shown when a signed-out visitor tries to start a scan. The repo they entered is already
 * saved (lib/pendingScan); signing in here hands control back via `onSignedIn`, and /scan
 * picks the repo up and starts it.
 */
export function AuthModal(props: {
  open: boolean;
  repo: string | null;
  onClose: () => void;
  onSignedIn: () => void;
}) {
  const { open, repo, onClose, onSignedIn } = props;
  const { signInWithGitHub } = useAuth();
  const ref = useRef<HTMLDialogElement>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Native <dialog>: focus trap, Esc to close and inert background for free
  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);

  async function github() {
    setBusy(true);
    setError(null);
    try {
      await signInWithGitHub();
      onSignedIn();
    } catch (err) {
      setError(authErrorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <dialog
      ref={ref}
      aria-labelledby="auth-title"
      aria-describedby="auth-desc"
      onClose={() => {
        setError(null);
        onClose();
      }}
      // Click on the backdrop (the dialog element itself, outside the panel) closes it
      onClick={(e) => e.target === e.currentTarget && ref.current?.close()}
      className="m-auto w-[min(480px,calc(100vw-32px))] border-2 border-hairline bg-obsidian p-0 text-bone shadow-hard backdrop:bg-black/85"
    >
      <div className="relative p-6 sm:p-8">
        <button
          type="button"
          onClick={() => ref.current?.close()}
          aria-label="Close"
          className="absolute right-3 top-3 grid size-9 place-items-center text-ash hover:text-bone"
        >
          <X size={18} />
        </button>

        <div className="flex items-center gap-2">
          <span aria-hidden className="h-2.5 w-2.5 bg-risk" />
          <h2 id="auth-title" className="stamp text-[20px] font-extrabold">
            Authentication required
          </h2>
        </div>
        <p id="auth-desc" className="mt-3 text-[14px] leading-relaxed text-ash">
          Sign in with GitHub to scan repositories, track audit history, and dispatch PR fixes.
        </p>

        {repo && (
          <p className="mt-5 border-2 border-hairline bg-carbon px-3 py-2 text-[13px]">
            <span className="stamp mr-2 text-[11px] text-ash">Queued</span>
            <span className="font-mono text-bone">{repo.replace("https://github.com/", "")}</span>
          </p>
        )}

        {error && (
          <p role="alert" className="mt-5 border-2 border-risk px-3 py-2 text-[13px] text-risk shadow-hard-risk">
            {error}
          </p>
        )}

        <button
          type="button"
          onClick={github}
          disabled={busy}
          className="btn mt-6 h-12 w-full border-2 border-secure bg-obsidian text-[14px] text-bone shadow-hard-secure hover:bg-carbon"
        >
          {busy ? <Spinner className="size-4 text-secure" /> : <GitHubMark className="size-4" />}
          Continue with GitHub
        </button>

        <p className="mt-5 text-center text-[12px] text-ash">
          Prefer Google or email?{" "}
          <Link href="/login?next=/scan" className="font-semibold text-bone underline-offset-4 hover:underline">
            Other sign-in options
          </Link>
        </p>
      </div>
    </dialog>
  );
}
