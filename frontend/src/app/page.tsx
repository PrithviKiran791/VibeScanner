import { TopNav } from "@/components/nav/TopNav";
import { NewScanForm } from "@/components/scan/NewScanForm";
import { ScanTable } from "@/components/scan/ScanTable";

export default function Home() {
  return (
    <>
      <TopNav />
      <main className="mx-auto max-w-[1080px] px-4 pb-16 pt-[calc(64px+40px)] sm:px-6">
        <div className="mb-10 border-l-[6px] border-secure pl-5">
          <h1 className="stamp text-[34px] font-extrabold leading-none sm:text-[44px]">
            Harden What You Shipped
          </h1>
          <p className="mt-3 max-w-[60ch] text-[15px] leading-relaxed text-ash">
            Static analysis finds secrets, injection sinks and made-up packages. A targeted LLM review
            checks every route and server action for missing auth. Each finding comes with a patch.
          </p>
        </div>
        <div className="grid gap-8">
          <NewScanForm />
          <ScanTable limit={8} title="Recent Scans" />
        </div>
      </main>
    </>
  );
}
