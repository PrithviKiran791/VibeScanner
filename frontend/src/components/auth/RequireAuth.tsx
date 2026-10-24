"use client";

import { MailCheck, ShieldX } from "lucide-react";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { authErrorMessage, useAuth } from "@/components/auth/AuthProvider";
import { TopNav } from "@/components/nav/TopNav";
import { Spinner } from "@/components/ui/spinner";

/**
 * Pages that show scan data render only for a signed-in user the API accepts. Rules and Docs
 * stay public. With Firebase unconfigured (local dev) this is a pass-through.
 */
export function RequireAuth({ children }: { children: React.ReactNode }) {
  const { status, access } = useAuth();
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    if (status === "signed-out") router.replace(`/login?next=${encodeURIComponent(pathname)}`);
  }, [status, pathname, router]);

  if (status === "disabled") return <>{children}</>;
  if (status === "unverified") return <WithNav><VerifyEmail /></WithNav>;
  if (status === "signed-in" && access.state === "ok") return <>{children}</>;
  if (status === "signed-in" && (access.state === "denied" || access.state === "error")) {
    return (
      <WithNav>
        <AccessProblem denied={access.state === "denied"} message={access.message} />
      </WithNav>
    );
  }
  return (
    <WithNav>
      <div className="flex items-center justify-center gap-3 pt-[calc(64px+64px)] text-[14px] text-ash">
        <Spinner className="size-4 text-secure" />
        {status === "signed-out" ? "Redirecting to sign in…" : "Checking your session…"}
      </div>
    </WithNav>
  );
}

function WithNav({ children }: { children: React.ReactNode }) {
  return (
    <>
      <TopNav />
      {children}
    </>
  );
}

function Card({ children, tone }: { children: React.ReactNode; tone: "secure" | "risk" }) {
  return (
    <div className="mx-auto max-w-[520px] px-4 pt-[calc(64px+64px)]">
      <div
        className={
          tone === "risk"
            ? "border-2 border-risk bg-grad-risk p-6 sm:p-8"
            : "border-2 border-secure/70 bg-grad-secure p-6 sm:p-8"
        }
      >
        {children}
      </div>
    </div>
  );
}

function VerifyEmail() {
  const { user, resendVerification, confirmVerified, signOut } = useAuth();
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function run(fn: () => Promise<void>) {
    setBusy(true);
    setNote(null);
    try {
      await fn();
    } catch (err) {
      setNote(authErrorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card tone="secure">
      <MailCheck className="text-secure" size={28} aria-hidden />
      <h1 className="stamp mt-4 text-[22px]">Verify your email</h1>
      <p className="mt-3 text-[14px] leading-relaxed text-bone/85">
        We sent a link to <b className="text-bone">{user?.email}</b>. VibeGuard only accepts verified
        addresses, so nobody can sign up as you. Click the link, then come back here.
      </p>
      {note && (
        <p role="status" className="mt-4 text-[13px] text-ash">
          {note}
        </p>
      )}
      <div className="mt-6 flex flex-wrap gap-3">
        <button
          type="button"
          className="btn btn-primary"
          disabled={busy}
          onClick={() =>
            run(async () => {
              if (!(await confirmVerified())) setNote("Not verified yet. Check your inbox (and spam).");
            })
          }
        >
          I&apos;ve verified
        </button>
        <button
          type="button"
          className="btn btn-neutral"
          disabled={busy}
          onClick={() => run(async () => {
            await resendVerification();
            setNote("Sent another link.");
          })}
        >
          Resend link
        </button>
        <button type="button" className="ml-auto text-[13px] text-ash hover:text-bone" onClick={signOut}>
          Sign out
        </button>
      </div>
    </Card>
  );
}

function AccessProblem({ denied, message }: { denied: boolean; message: string }) {
  const { signOut } = useAuth();
  return (
    <Card tone="risk">
      <ShieldX className="text-risk" size={28} aria-hidden />
      <h1 className="stamp mt-4 text-[22px]">{denied ? "Access not granted" : "Can't reach VibeGuard"}</h1>
      <p className="mt-3 text-[14px] leading-relaxed text-bone/85">{message}</p>
      {denied && (
        <p className="mt-3 text-[13px] leading-relaxed text-ash">
          {message.startsWith("GitHub account") ? (
            <>
              Ask the person who runs this VibeGuard to add that account id to{" "}
              <code className="code text-bone">VIBEGUARD_AUTH_ALLOWED_GITHUB_IDS</code>.
            </>
          ) : (
            <>
              Ask the person who runs this VibeGuard to add your email to{" "}
              <code className="code text-bone">VIBEGUARD_AUTH_ALLOWED_EMAILS</code>.
            </>
          )}
        </p>
      )}
      <button type="button" className="btn btn-neutral mt-6" onClick={signOut}>
        Sign out
      </button>
    </Card>
  );
}
