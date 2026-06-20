/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // Apple-Passwords-ish dark surfaces.
        canvas: "#161617",
        sidebar: "#1f1f21",
        panel: "#1c1c1e",
        hairline: "#2e2e30",
        accent: "#0a84ff",
      },
      fontFamily: {
        sans: [
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "Inter",
          "system-ui",
          "sans-serif",
        ],
      },
    },
  },
  plugins: [],
};
