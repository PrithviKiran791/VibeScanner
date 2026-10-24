"use client";

import {
  createUserWithEmailAndPassword,
  GithubAuthProvider,
  GoogleAuthProvider,
  onIdTokenChanged,
  reload,
  sendEmailVerification,
  sendPasswordResetEmail,
  signInWithEmailAndPassword,
  signInWithPopup,
  signOut as firebaseSignOut,
  type User,
} from "firebase/auth";
import { useRouter } from "next/navigation";
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";

import { ApiError, api } from "@/lib/api";
import { firebaseAuth, firebaseEnabled } from "@/lib/firebase";
import { setAuthFailureHandler, setTokenProvider } from "@/lib/session";

export type AuthStatus = "disabled" | "loading" | "signed-out" | "unverified" | "signed-in";

/** What the API thinks of this user (checked once per sign-in via GET /me). */
export type Access =
  | { state: "unknown" | "ok" }
  | { state: "denied" | "error"; message: string };

interface AuthContextValue {
  status: AuthStatus;
  user: User | null;
  access: Access;
  signInWithGitHub(): Promise<void>;
  signInWithGoogle(): Promise<void>;
  signInWithEmail(email: string, password: string): Promise<void>;
  signUpWithEmail(email: string, password: string): Promise<void>;
  resetPassword(email: string): Promise<void>;
  resendVerification(): Promise<void>;
  /** After clicking the email link: reload the user and pick up email_verified. */
  confirmVerified(): Promise<boolean>;
  signOut(): Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [ready, setReady] = useState(!firebaseEnabled);
  const [emailVerified, setEmailVerified] = useState(false);
  const [access, setAccess] = useState<Access>({ state: "unknown" });
  const checkedFor = useRef<string | null>(null);

  // Session: Firebase keeps it (refreshing ID tokens hourly); we mirror it into React state
  useEffect(() => {
    if (!firebaseEnabled) return;
    const auth = firebaseAuth();
    setTokenProvider(async (force) => (auth.currentUser ? auth.currentUser.getIdToken(force) : null));
    const unsubscribe = onIdTokenChanged(auth, (u) => {
      setUser(u);
      setEmailVerified(isTrusted(u));
      setReady(true);
      if (!u) {
        checkedFor.current = null;
        setAccess({ state: "unknown" });
      }
    });
    return () => {
      unsubscribe();
      setTokenProvider(null);
    };
  }, []);

  const status: AuthStatus = !firebaseEnabled
    ? "disabled"
    : !ready
      ? "loading"
      : !user
        ? "signed-out"
        : emailVerified
          ? "signed-in"
          : "unverified";

  // Ask the API whether it accepts this user: surfaces "not allowlisted" right after sign-in
  useEffect(() => {
    if (status !== "signed-in" || !user || checkedFor.current === user.uid) return;
    checkedFor.current = user.uid;
    // Until this resolves, access stays "unknown" and RequireAuth shows a spinner
    api
      .me()
      .then(() => setAccess({ state: "ok" }))
      .catch((err: unknown) => {
        const message = err instanceof Error ? err.message : "Could not reach the API";
        setAccess({
          state: err instanceof ApiError && err.status === 403 ? "denied" : "error",
          message,
        });
      });
  }, [status, user]);

  const signOut = useCallback(async () => {
    if (firebaseEnabled) await firebaseSignOut(firebaseAuth());
    router.replace("/login");
  }, [router]);

  // The API rejected even a freshly minted token. Firebase still holds a valid session (it would
  // have signed us out otherwise), so this is a server-side mismatch: signing out here only sent
  // people round the account picker again and again. Explain it instead.
  useEffect(() => {
    setAuthFailureHandler(() => {
      if (!firebaseEnabled || !firebaseAuth().currentUser) return;
      setAccess({
        state: "error",
        message:
          "The API rejected your sign-in. Check that the backend's VIBEGUARD_FIREBASE_PROJECT_ID " +
          "matches NEXT_PUBLIC_FIREBASE_PROJECT_ID, then reload.",
      });
    });
    return () => setAuthFailureHandler(null);
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      status,
      user,
      access,
      async signInWithGitHub() {
        // Identity only (read:user, user:email). PRs use the server's token, so no `repo` scope
        const provider = new GithubAuthProvider();
        provider.addScope("user:email");
        await signInWithPopup(firebaseAuth(), provider);
      },
      async signInWithGoogle() {
        // No forced `prompt: select_account`: Google shows its picker only when it has to
        await signInWithPopup(firebaseAuth(), new GoogleAuthProvider());
      },
      async signInWithEmail(email, password) {
        await signInWithEmailAndPassword(firebaseAuth(), email.trim(), password);
      },
      async signUpWithEmail(email, password) {
        const cred = await createUserWithEmailAndPassword(firebaseAuth(), email.trim(), password);
        await sendEmailVerification(cred.user);
      },
      async resetPassword(email) {
        await sendPasswordResetEmail(firebaseAuth(), email.trim());
      },
      async resendVerification() {
        const u = firebaseAuth().currentUser;
        if (u) await sendEmailVerification(u);
      },
      async confirmVerified() {
        const u = firebaseAuth().currentUser;
        if (!u) return false;
        await reload(u);
        if (!u.emailVerified) return false;
        await u.getIdToken(true); // new token carries email_verified: true for the API
        setEmailVerified(true);
        return true;
      },
      signOut,
    }),
    [status, user, access, signOut],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

/** Firebase never marks GitHub emails verified; the API allowlists GitHub users by account id. */
function isTrusted(u: User | null): boolean {
  return Boolean(u && (u.emailVerified || u.providerData.some((p) => p.providerId === "github.com")));
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}

/** Firebase error codes -> something a person can act on. */
export function authErrorMessage(err: unknown): string {
  const code = (err as { code?: string } | null)?.code ?? "";
  const messages: Record<string, string> = {
    "auth/invalid-credential": "Wrong email or password.",
    "auth/invalid-login-credentials": "Wrong email or password.",
    "auth/wrong-password": "Wrong email or password.",
    "auth/user-not-found": "Wrong email or password.",
    "auth/invalid-email": "That doesn't look like an email address.",
    "auth/email-already-in-use": "An account with this email already exists. Sign in instead.",
    "auth/weak-password": "Use a password of at least 8 characters.",
    "auth/missing-password": "Enter your password.",
    "auth/too-many-requests": "Too many attempts. Wait a minute and try again.",
    "auth/network-request-failed": "Network error. Check your connection.",
    "auth/account-exists-with-different-credential":
      "This email already signs in another way (Google or password). Use that method instead.",
    "auth/popup-blocked": "The browser blocked the sign-in popup. Allow popups for this site.",
    "auth/popup-closed-by-user": "Sign-in was cancelled.",
    "auth/cancelled-popup-request": "Sign-in was cancelled.",
    "auth/operation-not-allowed":
      "This sign-in method isn't enabled for the Firebase project (Authentication → Sign-in method).",
    "auth/unauthorized-domain":
      "This domain isn't authorized in Firebase (Authentication → Settings → Authorized domains).",
    "auth/invalid-api-key": "The Firebase API key is invalid. Check NEXT_PUBLIC_FIREBASE_API_KEY.",
  };
  if (code.startsWith("auth/api-key-not-valid")) return messages["auth/invalid-api-key"]!;
  return messages[code] ?? "Sign-in failed. Please try again.";
}
