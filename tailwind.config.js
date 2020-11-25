module.exports = {
  future: {
    removeDeprecatedGapUtilities: true,
    purgeLayersByDefault: true,
  },
  purge: ["./client/views/*.ejs", "./client/scripts/*.js"],
  theme: {
    extend: {},
  },
  variants: {},
  plugins: [],
};
