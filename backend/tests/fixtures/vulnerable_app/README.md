# vulnerable_app — intentionally insecure demo

A tiny Next.js app full of the mistakes AI assistants make. **Every credential here is fake**
and every bug is deliberate.

Secret-shaped values are not committed (GitHub push protection would reject them). Files ending
in `.tmpl` hold placeholders; build a scannable copy with:

    cd backend && python -m tests.fixtures.materialize ../demo_app

The test suite does the same automatically (`demo_app` fixture in `tests/conftest.py`).

| File | Planted issue |
| --- | --- |
| `lib/stripe.ts.tmpl` | Hardcoded Stripe live key (assembled at build time) |
| `.env.local` | Committed env file, service-role key behind `NEXT_PUBLIC_` |
| `package.json` | Hallucinated package `react-secure-auth-helpers-pro` |
| `app/api/search/route.ts` | SQL built with a template string |
| `components/Comment.tsx` | Unsanitized `dangerouslySetInnerHTML` |
| `app/api/convert/route.ts` | Shell command injection |
| `app/api/user/[id]/route.ts` | IDOR: no session check (LLM pass) |
| `app/actions.ts` | Unauthenticated server action (LLM pass) |
