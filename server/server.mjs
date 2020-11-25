import express from "express";
import compression from "compression";

const app = express();

app.use(compression());

app.use(express.static("./public"));
app.use(express.static("./dist"));

app.set("view-engine", "ejs", );
app.set('views', './client/views')
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.get("/", (req, res) => {
  res.render("index.ejs", { user: req.user });
});

app.listen(3000, () => {
  console.log("Server ready");
});
