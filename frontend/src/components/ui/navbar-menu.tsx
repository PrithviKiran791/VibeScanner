"use client";

// Aceternity "navbar-menu" (hover menu with a morphing dropdown), adapted to VibeGuard's
// brutalist system: square corners, 2px borders, hard offset shadows, no blur. Beyond the
// original it supports keyboard (Enter/Space/Arrow/Escape), touch (tap to toggle, tap outside
// to close) and prefers-reduced-motion.

import { ArrowUpRight } from "lucide-react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import Link from "next/link";
import { createContext, useCallback, useContext, useEffect, useRef } from "react";

import { cn } from "@/lib/utils";

const SPRING = { type: "spring", mass: 0.5, damping: 11.5, stiffness: 100, restDelta: 0.001, restSpeed: 0.001 } as const;

const MenuContext = createContext<{ close: () => void }>({ close: () => {} });

export function Menu({
  setActive,
  active,
  className,
  children,
  ...props
}: {
  setActive: (item: string | null) => void;
  active: string | null;
  className?: string;
  children: React.ReactNode;
} & Omit<React.ComponentProps<"nav">, "children">) {
  const ref = useRef<HTMLElement>(null);
  const close = useCallback(() => setActive(null), [setActive]);

  // Tap outside closes (touch has no mouse-leave); Escape closes from the keyboard
  useEffect(() => {
    if (active === null) return;
    const onPointerDown = (e: PointerEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) close();
    };
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") close();
    };
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [active, close]);

  return (
    <MenuContext.Provider value={{ close }}>
      <nav
        ref={ref}
        onPointerLeave={(e) => e.pointerType === "mouse" && close()}
        className={cn("flex items-stretch", className)}
        {...props}
      >
        {children}
      </nav>
    </MenuContext.Provider>
  );
}

export function MenuItem({
  setActive,
  active,
  item,
  label,
  icon,
  current,
  panelClassName,
  children,
}: {
  setActive: (item: string | null) => void;
  active: string | null;
  item: string;
  label: string;
  icon?: React.ReactNode;
  /** The page the user is on belongs to this section. */
  current?: boolean;
  panelClassName?: string;
  children: React.ReactNode;
}) {
  const open = active === item;
  const reduce = useReducedMotion();
  const transition = reduce ? { duration: 0 } : SPRING;

  return (
    <div
      className="relative flex items-stretch"
      // Mouse only: touch fires pointerenter then click, which would open and instantly re-close
      onPointerEnter={(e) => e.pointerType === "mouse" && setActive(item)}
    >
      <button
        type="button"
        aria-expanded={open}
        aria-haspopup="true"
        onClick={(e) => {
          // A mouse click follows the hover that already opened this panel: keep it open.
          // Touch and keyboard have no hover, so there a click toggles.
          const pointer = (e.nativeEvent as PointerEvent).pointerType;
          setActive(pointer === "mouse" || !open ? item : null);
        }}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") {
            e.preventDefault();
            setActive(item);
          }
        }}
        className={cn(
          "stamp relative flex items-center gap-1.5 px-3 text-[12px] transition-colors duration-100 sm:px-5",
          "outline-none focus-visible:bg-graphite focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-bone",
          open || current ? "bg-carbon text-bone" : "text-ash hover:text-bone",
        )}
      >
        {icon}
        {label}
        {current && (
          <motion.span
            layoutId="nav-current"
            aria-hidden
            transition={transition}
            className="absolute inset-x-0 bottom-0 h-[3px] bg-secure"
          />
        )}
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: 10 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 10 }}
            transition={transition}
            // Below xl the panel is centered under the whole bar (a trigger-anchored 540px panel
            // would run off the screen); on wide screens it hangs from its own trigger.
            // top-[62px] = the header's content height, so the pointer never crosses a gap.
            className="pointer-events-none fixed inset-x-0 top-[62px] z-50 flex justify-center px-2 xl:absolute xl:inset-x-auto xl:left-0 xl:top-full xl:block xl:px-0"
          >
            {/* Shared layoutId: moving between items morphs one panel instead of swapping two */}
            <motion.div
              layoutId="nav-panel"
              transition={transition}
              className={cn(
                "pointer-events-auto w-full overflow-hidden border-2 border-hairline bg-carbon shadow-hard",
                "max-h-[calc(100dvh-72px)] overflow-y-auto sm:w-max sm:max-w-[min(94vw,560px)]",
                panelClassName,
              )}
            >
              <motion.div layout className="p-3">
                {children}
              </motion.div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

/** A rich entry: icon tile, title, one-line description. The brutalist take on ProductItem. */
export function FeatureItem({
  title,
  description,
  href,
  icon,
  meta,
  external,
}: {
  title: string;
  description: string;
  href: string;
  icon: React.ReactNode;
  meta?: string;
  external?: boolean;
}) {
  const { close } = useContext(MenuContext);
  const props = external
    ? { target: "_blank", rel: "noopener noreferrer" }
    : {};
  return (
    <Link
      href={href}
      onClick={close}
      {...props}
      className={cn(
        "group flex items-start gap-3 border-2 border-transparent p-2.5 outline-none",
        "transition-[transform,box-shadow,border-color] duration-[60ms] ease-linear",
        "hover:border-hairline hover:bg-graphite hover:shadow-hard focus-visible:border-bone",
        "active:translate-x-[2px] active:translate-y-[2px] active:shadow-none",
      )}
    >
      <span
        aria-hidden
        className="grid h-9 w-9 shrink-0 place-items-center border-2 border-hairline bg-obsidian text-bone transition-colors group-hover:border-secure group-hover:text-secure"
      >
        {icon}
      </span>
      <span className="min-w-0">
        <span className="stamp flex items-center gap-2 text-[13px] text-bone">
          {title}
          {meta && (
            <span className="border border-hairline px-1.5 py-px text-[10px] font-bold text-ash">{meta}</span>
          )}
          {external && <ArrowUpRight size={12} aria-hidden className="text-ash" />}
        </span>
        <span className="mt-0.5 block max-w-[34ch] text-[12.5px] leading-snug text-ash">{description}</span>
      </span>
    </Link>
  );
}

/** A compact text link (Aceternity's HoveredLink). */
export function MenuLink({ href, className, children }: { href: string; className?: string; children: React.ReactNode }) {
  const { close } = useContext(MenuContext);
  return (
    <Link
      href={href}
      onClick={close}
      className={cn(
        "stamp flex items-center justify-between gap-6 border-t-2 border-hairline px-2.5 py-2.5 text-[11px] text-ash outline-none transition-colors hover:text-secure focus-visible:text-secure",
        className,
      )}
    >
      {children}
    </Link>
  );
}
