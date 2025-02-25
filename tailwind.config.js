module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
    "./public/index.html",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        'truefa-dark': '#1a1a1a',
        'truefa-light': '#f5f5f5',
        'truefa-blue': '#0077cc',
        'truefa-navy': '#005599',
        'truefa-gray': '#4a5568',
      },
    },
  },
  plugins: [],
} 