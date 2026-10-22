"use client";

import { LogIn, LogOut } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

import { useAuth } from "@/components/auth/AuthProvider";
import { cn } from "@/lib/format";

/** Right edge of the top nav: "Sign In" when signed out, the account + sign out when signed in. */
export function AccountControl() {
  const { status, user, signOut } = useAuth();
  const path = usePathname();
  const onLogin = path.startsWith("/login");

  // No Firebase (local dev) or still restoring the session: nothing to show yet
  if (status === "disabled" || status === "loading") return null;

  if (status === "signed-out") {
    return (
      <Link
        href="/login"
        aria-label="Sign in"
        aria-current={onLogin ? "page" : undefined}
        className={cn(
          "stamp flex items-center gap-2 border-l-2 border-hairline px-4 text-[12px] font-bold tracking-wider transition-colors sm:px-5",
          onLogin ? "border-b-2 border-b-bone bg-carbon text-bone" : "text-ash hover:bg-carbon hover:text-bone",
        )}
      >
        <LogIn className="h-3.5 w-3.5 text-secure" />
        <span className="hidden sm:inline">Sign In</span>
      </Link>
    );
  }

  const label = user?.displayName || user?.email || "Account";
  const initial = (user?.displayName || user?.email || "?").trim().charAt(0).toUpperCase();
  return (
    <div className="flex items-stretch border-l-2 border-hairline">
      <div className="hidden items-center gap-2.5 px-4 md:flex" title={user?.email ?? undefined}>
        <span
          aria-hidden
          className="grid h-7 w-7 place-items-center border-2 border-secure bg-grad-secure font-heading text-[12px] font-extrabold text-secure"
        >
          {initial}
        </span>
        <span className="max-w-[180px] truncate text-[13px] font-medium text-bone">{label}</span>
      </div>
      <button
        type="button"
        onClick={() => void signOut()}
        aria-label="Sign out"
        title="Sign out"
        className="stamp flex items-center gap-2 border-l-2 border-hairline px-4 text-[12px] text-ash transition-colors hover:bg-carbon hover:text-bone md:border-l-0"
      >
        <LogOut className="h-3.5 w-3.5" />
        <span className="hidden lg:inline">Sign out</span>
      </button>
    </div>
  );
}
