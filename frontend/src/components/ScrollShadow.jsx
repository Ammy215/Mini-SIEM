import { useCallback, useEffect, useRef, useState } from "react";
import { cn } from "@/lib/utils";

/**
 * A horizontally scrolling region that says so.
 *
 * Content wider than its container just gets cut off at the edge, with nothing
 * to suggest there is more — the MITRE matrix loses a whole tactic column that
 * way. This fades whichever edge still has content beyond it, so the clipping
 * reads as "scroll" rather than "end".
 */
export function ScrollShadow({ children, className, contentClassName, label }) {
  const ref = useRef(null);
  const [edges, setEdges] = useState({ left: false, right: false });

  const measure = useCallback(() => {
    const el = ref.current;
    if (!el) return;
    const max = el.scrollWidth - el.clientWidth;
    setEdges({
      left: el.scrollLeft > 2,
      // 2px of slack: sub-pixel layout can leave scrollLeft a hair short of max
      right: max > 2 && el.scrollLeft < max - 2,
    });
  }, []);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    measure();
    el.addEventListener("scroll", measure, { passive: true });
    const observer = new ResizeObserver(measure);
    observer.observe(el);
    for (const child of el.children) observer.observe(child);
    return () => {
      el.removeEventListener("scroll", measure);
      observer.disconnect();
    };
  }, [measure]);

  return (
    <div className={cn("relative", className)}>
      {/* Focusable so the content beyond the edge can be reached with the arrow
          keys — a mouse wheel or a trackpad is not the only way people scroll. */}
      <div
        ref={ref}
        tabIndex={0}
        role="group"
        aria-label={label}
        className={cn("overflow-x-auto", contentClassName)}
      >
        {children}
      </div>

      <div
        aria-hidden="true"
        className={cn(
          "pointer-events-none absolute inset-y-0 left-0 w-10 bg-gradient-to-r from-card to-transparent transition-opacity duration-200",
          edges.left ? "opacity-100" : "opacity-0",
        )}
      />
      <div
        aria-hidden="true"
        className={cn(
          "pointer-events-none absolute inset-y-0 right-0 w-12 bg-gradient-to-l from-card to-transparent transition-opacity duration-200",
          edges.right ? "opacity-100" : "opacity-0",
        )}
      />
      {edges.right && (
        <span className="pointer-events-none absolute right-1 top-1/2 -translate-y-1/2 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
          →
        </span>
      )}
    </div>
  );
}
