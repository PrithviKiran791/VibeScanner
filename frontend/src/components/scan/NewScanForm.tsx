"use client";

import { ArrowRight } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { ApiError, api } from "@/lib/api";
import { cn } from "@/lib/format";
import { normalizeTarget } from "@/lib/target";
import type { ScanOptions } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";

export function NewScanForm() {
  const router = useRouter();
  const [value, setValue] = useState("");
  const [options, setOptions] = useState<ScanOptions>({ llm: true, registry: true });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    const target = normalizeTarget(value);
    if (!target) {
      setError("Enter a GitHub repository like acme/vibe-app or https://github.com/acme/vibe-app");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const scan = await api.createScan(target, options);
      router.push(`/scans/${scan.id}`);
    } catch (err) {
      if (err instanceof ApiError && err.conflictingScanId) {
        router.push(`/scans/${err.conflictingScanId}`);
        return;
      }
      setError(err instanceof Error ? err.message : "Could not start the scan");
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="border-2 border-hairline bg-carbon" noValidate>
      <div className="border-b-2 border-hairline px-5 py-4 sm:px-6">
        <h2 className="stamp text-[18px]">New Scan</h2>
      </div>
      <div className="space-y-5 p-5 sm:p-6">
        <div>
          <label htmlFor="target" className="stamp mb-2 block text-[12px] text-ash">
            GitHub Repository
          </label>
          <div className="flex flex-col gap-3 sm:flex-row">
            <input
              id="target"
              className={cn("field", error && "border-risk")}
              placeholder="acme/vibe-app"
              autoComplete="off"
              spellCheck={false}
              value={value}
              onChange={(e) => setValue(e.target.value)}
              aria-invalid={Boolean(error)}
              aria-describedby={error ? "target-error" : undefined}
            />
            <Button type="submit" variant="default" size="lg" className="h-12 shrink-0 px-6" disabled={busy}>
              {busy ? (
                <>
                  <Spinner className="size-4" />
                  <span>Queuing</span>
                </>
              ) : (
                <>
                  <span>Scan</span>
                  <ArrowRight size={16} strokeWidth={2.5} aria-hidden />
                </>
              )}
            </Button>
          </div>
          {error && (
            <p id="target-error" role="alert" className="mt-3 text-[13px] text-risk">
              {error}
            </p>
          )}
        </div>

        <fieldset className="grid gap-3 sm:grid-cols-2">
          <legend className="sr-only">Scan options</legend>
          <Toggle
            checked={options.llm}
            onChange={(llm) => setOptions((o) => ({ ...o, llm }))}
            label="Semantic Review"
            hint="LLM checks auth and logic on extracted routes"
          />
          <Toggle
            checked={options.registry}
            onChange={(registry) => setOptions((o) => ({ ...o, registry }))}
            label="Registry Check"
            hint="Verify every dependency exists on npm / PyPI"
          />
        </fieldset>
      </div>
    </form>
  );
}

function Toggle(props: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
  hint: string;
}) {
  return (
    <label
      className={cn(
        "flex cursor-pointer items-start gap-3 border-2 p-3 transition-colors",
        props.checked ? "border-secure/60 bg-grad-secure" : "border-hairline",
      )}
    >
      <input
        type="checkbox"
        className="peer sr-only"
        checked={props.checked}
        onChange={(e) => props.onChange(e.target.checked)}
      />
      <span
        aria-hidden
        className={cn(
          "mt-0.5 grid h-4 w-4 shrink-0 place-items-center border-2 peer-focus-visible:outline peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-bone",
          props.checked ? "border-secure bg-secure" : "border-ash",
        )}
      >
        {props.checked && <span className="h-1.5 w-1.5 bg-obsidian" />}
      </span>
      <span>
        <span className="stamp block text-[12px]">{props.label}</span>
        <span className="mt-1 block text-[13px] leading-snug text-ash">{props.hint}</span>
      </span>
    </label>
  );
}
