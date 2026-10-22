// Firebase web config. These values are public by design (they identify the project; they don't
// grant access): the API verifies each ID token's signature, audience and issuer, and checks
// the allowlist. NEXT_PUBLIC_* values are inlined at build time.

import { type FirebaseApp, getApps, initializeApp } from "firebase/app";
import { type Auth, getAuth } from "firebase/auth";

const config = {
  apiKey: process.env.NEXT_PUBLIC_FIREBASE_API_KEY,
  authDomain: process.env.NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN,
  projectId: process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID,
  appId: process.env.NEXT_PUBLIC_FIREBASE_APP_ID,
};

/** False in local dev without a Firebase project: the dashboard then runs without sign-in,
 *  which only works against a backend started with auth disabled (the devserver). */
export const firebaseEnabled = Boolean(config.apiKey && config.authDomain && config.projectId);

let auth: Auth | null = null;

export function firebaseAuth(): Auth {
  if (!firebaseEnabled) throw new Error("Firebase is not configured");
  if (!auth) {
    const app: FirebaseApp = getApps()[0] ?? initializeApp(config);
    auth = getAuth(app);
  }
  return auth;
}
