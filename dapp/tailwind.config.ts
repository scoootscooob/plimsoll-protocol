import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        plimsoll: {
          50: "#f0f7ff",
          100: "#e0eefe",
          200: "#b9ddfe",
          300: "#7cc3fd",
          400: "#36a5fa",
          500: "#0c89eb",
          600: "#006cc9",
          700: "#0156a3",
          800: "#064a86",
          900: "#0b3f6f",
          950: "#07284a",
        },
      },
    },
  },
  plugins: [],
};
export default config;
