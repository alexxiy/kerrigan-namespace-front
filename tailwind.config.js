/** @type {import('tailwindcss').Config} */
module.exports = {
  // IMPORTANT: js/app.js must be scanned as well as index.html. Many utility classes exist
  // only inside JS template literals (marketplace cards, my-names cards, transaction rows,
  // pagination buttons, toasts); omitting it would purge those classes and silently break
  // the styling of every dynamically rendered view.
  content: [
    // app.html, not index.html: index.html is the landing page (which uses landing.css and
    // no Tailwind at all), so scanning it purges every class the app needs.
    './app.html',
    './js/app.js',
    // Translated strings carry markup with utility classes on it (price highlight, status
    // countdown). They live only in these files, so they must be scanned too.
    './lang/*.json',
  ],
  theme: {
    extend: {
      colors: {
        // Kerrigan's palette in place of Tailwind's purple, so the class names stay those of
        // PIVX Name (whose fixes then merge as they are) while every purple-* is Kerrigan's.
        // 600 is the logo's purple and 400 the light purple of Kerrigan Core's Qt theme
        // (src/qt/res/css/kerrigan.css); the other steps are tints and shades of them.
        // Keep in step with css/style.css, css/landing.css and images/README.md.
        purple: {
          50: '#f6f1fe',
          100: '#ede3fd',
          200: '#dccafc',
          300: '#cba8fb',
          400: '#bd81fb',
          500: '#a05ff4',
          600: '#8341ed',
          700: '#6c2fd0',
          800: '#5824a8',
          900: '#461d86',
          950: '#2a0f57',
        },
        // The logo's green. Only this step is replaced; the rest of green stays Tailwind's.
        green: {
          400: '#43de78',
        },
      },
    },
  },
  plugins: [],
};
