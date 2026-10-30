import { useEffect, useRef } from "react";

// The anti-phishing word as moving noise — the same effect as the separate-desktop window.
// Two noise fields drift in opposite directions: the background to the left, the inside of the
// letters to the right. Every single frame is uniform noise, so a still screen capture shows no
// word; in motion the letters read easily. Drawn on a canvas: not in the accessibility tree.

const GREYS = [30, 105, 180, 255];
const CELL = 2; // CSS pixels per noise cell
const FRAME_MS = 40;

/** The word in capitals at cell resolution, as large as fits, centred, strokes thickened. */
function textMask(word: string, w: number, h: number): Uint8Array | null {
  const scratch = document.createElement("canvas");
  scratch.width = w;
  scratch.height = h * 2;
  const ctx = scratch.getContext("2d", { willReadFrequently: true });
  if (!ctx) return null;
  const text = word.toUpperCase();
  let size = Math.floor(h * 1.3);
  let ink: { x0: number; y0: number; bw: number; bh: number } | null = null;
  let data = new Uint8ClampedArray(0);
  for (let i = 0; i < 12; i++) {
    ctx.clearRect(0, 0, w, h * 2);
    ctx.fillStyle = "#fff";
    ctx.font = `900 ${size}px 'Segoe UI', system-ui, sans-serif`;
    ctx.letterSpacing = "2px";
    ctx.textBaseline = "top";
    ctx.fillText(text, 2, 0);
    data = ctx.getImageData(0, 0, w, h * 2).data;
    let [x0, y0, x1, y1] = [w, h * 2, -1, -1];
    for (let y = 0; y < h * 2; y++) {
      for (let x = 0; x < w; x++) {
        if (data[(y * w + x) * 4 + 3] > 128) {
          x0 = Math.min(x0, x);
          y0 = Math.min(y0, y);
          x1 = Math.max(x1, x);
          y1 = Math.max(y1, y);
        }
      }
    }
    if (x1 < 0) return null;
    const [bw, bh] = [x1 - x0 + 1, y1 - y0 + 1];
    // Room for the thickening; a word touching the right edge was cut off.
    if (bw + 4 <= w && bh + 4 <= h && x1 + 1 < w) {
      ink = { x0, y0, bw, bh };
      break;
    }
    size = Math.max(6, Math.floor(Math.min((size * (w - 6)) / bw, (size * (h - 6)) / bh, size * 0.9)));
  }
  if (!ink) return null;
  const thin = new Uint8Array(w * h);
  const [ox, oy] = [Math.floor((w - ink.bw) / 2), Math.floor((h - ink.bh) / 2)];
  for (let y = 0; y < ink.bh; y++) {
    for (let x = 0; x < ink.bw; x++) {
      thin[(oy + y) * w + ox + x] = data[((ink.y0 + y) * w + ink.x0 + x) * 4 + 3] > 128 ? 1 : 0;
    }
  }
  // One cell thicker on every side: thin strokes get lost in the noise.
  const at = (x: number, y: number) => x >= 0 && y >= 0 && x < w && y < h && thin[y * w + x] === 1;
  const mask = new Uint8Array(w * h);
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      mask[y * w + x] = at(x, y) || at(x - 1, y) || at(x + 1, y) || at(x, y - 1) || at(x, y + 1) ? 1 : 0;
    }
  }
  return mask;
}

export function NoiseWord({ word, height = 64 }: { word: string; height?: number }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const c = ref.current;
    if (!c || !word) return;
    const ctx = c.getContext("2d");
    if (!ctx) return;
    const cssW = c.parentElement?.clientWidth ?? 360;
    const [w, h] = [Math.floor(cssW / CELL), Math.floor(height / CELL)];
    // One canvas pixel per cell, scaled up without smoothing.
    c.width = w;
    c.height = h;
    c.style.width = `${w * CELL}px`;
    c.style.height = `${h * CELL}px`;
    const mask = textMask(word, w, h);
    if (!mask) return;
    const back = Float32Array.from({ length: w * h }, Math.random);
    const letters = Float32Array.from({ length: w * h }, Math.random);
    const img = ctx.createImageData(w, h);
    let t = 0;
    let last = 0;
    let raf = 0;
    const draw = () => {
      // 1.5 cells per frame: fast enough to pick the letters out at a glance.
      const shift = Math.floor((t * 3) / 2) % w;
      for (let y = 0; y < h; y++) {
        for (let x = 0; x < w; x++) {
          const i = y * w + x;
          const v = mask[i] ? letters[y * w + ((x + w - shift) % w)] : back[y * w + ((x + shift) % w)];
          const g = GREYS[Math.min(3, Math.floor(v * 4))];
          img.data[i * 4] = g;
          img.data[i * 4 + 1] = g;
          img.data[i * 4 + 2] = g;
          img.data[i * 4 + 3] = 255;
        }
      }
      ctx.putImageData(img, 0, 0);
    };
    const tick = (now: number) => {
      if (now - last >= FRAME_MS) {
        last = now;
        t++;
        draw();
      }
      raf = requestAnimationFrame(tick);
    };
    draw();
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [word, height]);
  return <canvas ref={ref} aria-hidden="true" style={{ display: "block", imageRendering: "pixelated", borderRadius: 8 }} />;
}

/** Moving noise is unreadable without motion; the plain word is shown then. */
export function reducedMotion(): boolean {
  return typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;
}
