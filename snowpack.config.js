module.exports = {
  mount: {
    "./client/scripts": "/",
    "./client/styles": "/",
  },
  devOptions: {
    tailwindConfig: "./tailwind.config.js",
  },
  plugins: ["@snowpack/plugin-postcss"],
};
