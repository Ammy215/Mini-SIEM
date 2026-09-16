import { useEffect, useRef } from "react";

/**
 * The quiet telemetry field behind the sign-in panel.
 *
 * Canvas rather than SVG: the points move every frame, and hand-authored path
 * data for a few hundred of them would be both bigger and slower. Everything is
 * drawn from the theme's own accent colours at low alpha, so it reads as depth
 * behind the type rather than as decoration competing with it.
 */

const NODE_COUNT = 46;
const LINK_DISTANCE = 148;
const PING_EVERY_MS = 2600;

export function AmbientField({ className }) {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    let width = 0;
    let height = 0;
    let dpr = Math.min(window.devicePixelRatio || 1, 2);

    const nodes = Array.from({ length: NODE_COUNT }, () => ({
      x: Math.random(),
      y: Math.random(),
      vx: (Math.random() - 0.5) * 0.00013,
      vy: (Math.random() - 0.5) * 0.00013,
      r: 0.6 + Math.random() * 1.5,
      // A few nodes read as "hot" — the ones a SIEM would be watching.
      hot: Math.random() < 0.18,
    }));
    const pings = [];

    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      width = rect.width;
      height = rect.height;
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    resize();
    const observer = new ResizeObserver(resize);
    observer.observe(canvas);

    let raf = 0;
    let lastPing = 0;
    let start = performance.now();

    const draw = (now) => {
      const elapsed = now - start;
      ctx.clearRect(0, 0, width, height);

      if (!reduced) {
        for (const n of nodes) {
          n.x += n.vx;
          n.y += n.vy;
          if (n.x < 0 || n.x > 1) n.vx *= -1;
          if (n.y < 0 || n.y > 1) n.vy *= -1;
        }
        if (now - lastPing > PING_EVERY_MS) {
          lastPing = now;
          const source = nodes[Math.floor(Math.random() * nodes.length)];
          pings.push({ x: source.x, y: source.y, born: now, hot: source.hot });
          if (pings.length > 4) pings.shift();
        }
      }

      // links between nearby nodes — the faint mesh of a network under watch
      ctx.lineWidth = 1;
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const ax = nodes[i].x * width;
          const ay = nodes[i].y * height;
          const bx = nodes[j].x * width;
          const by = nodes[j].y * height;
          const d = Math.hypot(ax - bx, ay - by);
          if (d > LINK_DISTANCE) continue;
          const alpha = (1 - d / LINK_DISTANCE) * 0.16;
          ctx.strokeStyle = `rgba(0, 212, 255, ${alpha})`;
          ctx.beginPath();
          ctx.moveTo(ax, ay);
          ctx.lineTo(bx, by);
          ctx.stroke();
        }
      }

      // the nodes themselves
      for (const n of nodes) {
        const x = n.x * width;
        const y = n.y * height;
        const breathe = reduced ? 1 : 0.75 + Math.sin(elapsed / 1400 + n.x * 12) * 0.25;
        ctx.beginPath();
        ctx.arc(x, y, n.r * breathe, 0, Math.PI * 2);
        ctx.fillStyle = n.hot
          ? `rgba(255, 51, 102, ${0.5 * breathe})`
          : `rgba(0, 212, 255, ${0.42 * breathe})`;
        ctx.fill();
      }

      // expanding rings, the way a console shows something arriving
      for (const p of pings) {
        const age = (now - p.born) / 2400;
        if (age > 1) continue;
        const radius = 6 + age * 90;
        ctx.beginPath();
        ctx.arc(p.x * width, p.y * height, radius, 0, Math.PI * 2);
        ctx.strokeStyle = p.hot
          ? `rgba(255, 51, 102, ${0.32 * (1 - age)})`
          : `rgba(0, 212, 255, ${0.28 * (1 - age)})`;
        ctx.lineWidth = 1.2;
        ctx.stroke();
      }

      raf = requestAnimationFrame(draw);
    };

    raf = requestAnimationFrame(draw);
    return () => {
      cancelAnimationFrame(raf);
      observer.disconnect();
    };
  }, []);

  return <canvas ref={canvasRef} aria-hidden="true" className={className} />;
}
