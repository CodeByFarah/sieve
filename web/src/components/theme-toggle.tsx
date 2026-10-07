"use client";

export function ThemeToggle() {
  function toggle() {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try {
      localStorage.setItem("sieve-theme", next);
    } catch {
      /* private mode: the choice lasts for this page only */
    }
  }
  return (
    <button type="button" onClick={toggle} className="rounded px-2 py-1 text-sm text-muted hover:text-text" aria-label="Switch colour theme">
      Theme
    </button>
  );
}
