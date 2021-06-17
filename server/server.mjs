import express from "express";
import compression from "compression";
import { urlAlphabet, customAlphabet } from "nanoid";
import passport from "passport";
import session from "express-session";
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import base64url from "base64url";

import { Users } from "./db/users.mjs";
import initializePassport from "./passport-config.mjs";

const nanoid = customAlphabet(urlAlphabet, 25);

const rpName = "Petsgramm";
const rpID = process.env.HOST_NAME;
const origin = `https://${rpID}`;

const users = new Users();

initializePassport(
  passport,
  (email) => users.getByEmail(email),
  (id) => users.getById(id)
);

const app = express();

app.use(compression());

app.use(express.static("./public"));
app.use(express.static("./build"));

app.set("view-engine", "ejs");
app.set("views", "./client/views");
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(
  session({
    secret: "secret",
    resave: false,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
  res.render("index.ejs", { user: req.user });
});

app.get("/profile", checkAuthenticated, (req, res) => {
  res.render("profile.ejs", { user: req.user });
});

app.get("/signin", checkNotAuthenticated, (req, res) => {
  res.render("signin.ejs");
});

app.get("/signup", checkNotAuthenticated, (req, res) => {
  res.render("signup.ejs");
});

app.get("/forgot-password", checkNotAuthenticated, (req, res) => {
  res.render("forgot-password.ejs");
});

app.get("/new-password", checkNotAuthenticated, (req, res) => {
  res.render("new-password.ejs");
});

app.get("/signin-2step", checkAuthenticated, (req, res) => {
  res.render("signin-2step.ejs");
});

app.get("/signup-2step", checkAuthenticated, async (req, res) => {
  res.render("add-key.ejs");
});

app.get("/add-key", checkAuthenticated, async (req, res) => {
  res.render("add-key.ejs");
});

app.post("/add-key/challenge", checkAuthenticated, (req, res) => {
  const user = req.user;

  const options = generateRegistrationOptions({
    rpName,
    rpID,
    userID: user.webAuthnId,
    userName: user.name,
    userID: user.id,
    attestationType: "none",
    excludeCredentials: user.devices.map((dev) => ({
      id: dev.credentialID,
      type: "public-key",
    })),
  });

  // Save challenge
  req.session.challenge = options.challenge;

  res.json({ options });
});

app.post("/add-key/verify", checkAuthenticated, async (req, res) => {
  const user = req.user;
  const expectedChallenge = req.session.challenge;

  try {
    const verification = await verifyRegistrationResponse({
      credential: req.body.options,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    const { verified, registrationInfo } = verification;

    const { credentialPublicKey, credentialID, counter } = registrationInfo;

    const newAuthenticator = {
      name: req.body.nick,
      credentialID,
      credentialPublicKey,
      counter,
    };

    users.addDevice(user.id, newAuthenticator);

    res.json({ success: verified });
  } catch (error) {
    res.json({ error: error.message });
  }
});

app.post("/key/challenge", checkAuthenticated, (req, res) => {
  const user = req.user;

  const options = generateAuthenticationOptions({
    allowCredentials: user.devices.map((dev) => ({
      id: dev.credentialID,
      type: "public-key",
    })),
    userVerification: "preferred",
  });

  req.session.challenge = options.challenge;

  res.json({ options });
});

app.post("/key/verify", checkAuthenticated, async (req, res) => {
  const user = req.user;
  const expectedChallenge = req.session.challenge;

  try {
    const bodyCredIDBuffer = base64url.toBuffer(req.body.id);

    const authenticator = user.devices.find((device) =>
      device.credentialID.equals(bodyCredIDBuffer)
    );

    if (!authenticator) {
      throw new Error(`Could not find authenticator`);
    }

    const verification = await verifyAuthenticationResponse({
      credential: req.body,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator,
    });

    const { verified } = verification;

    res.json({ success: verified });
  } catch (error) {
    res.json({ error: error.message });
  }
});

const magicLinks = [];
app.post("/forgot-password", checkNotAuthenticated, (req, res) => {
  const { email } = req.body;

  const magic = {
    id: nanoid(),
    userId: users.getByEmail(email)?.id,
  };
  magicLinks.push(magic);

  res.json({ link: "/new-password?magic=" + magic.id });
});

app.post("/new-password", checkNotAuthenticated, async (req, res) => {
  const { password } = req.body;
  const id = req.headers.referer.split("?magic=")[1];
  const link = magicLinks.find((link) => link.id === id);

  await users.setNewPassword(link.userId, password);

  const user = users.getById(link.userId);

  await login(req, user);

  res.json({
    success: true,
  });
});

app.post("/signin", checkNotAuthenticated, function (req, res, next) {
  passport.authenticate("local", function (err, user, info) {
    if (err) {
      return next(err);
    }
    if (!user) {
      return res.json({ error: info.message });
    }
    req.logIn(user, function (err) {
      if (err) {
        return next(err);
      }
      return res.json({ success: true });
    });
  })(req, res, next);
});

app.post("/signup", checkNotAuthenticated, async (req, res) => {
  const { password, name, email } = req.body;
  try {
    const user = await users.add({ password, name, email });

    await login(req, user);

    return res.json({
      success: true,
    });
  } catch (e) {
    return res.json({
      success: false,
      error: e.message,
    });
  }
});

app.post("/logout", (req, res) => {
  req.logOut();
  res.redirect("/signin");
});

function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  res.redirect("/signin");
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect("/");
  }
  next();
}

function login(req, user) {
  return new Promise((resolve, reject) => {
    req.login(user, function (err) {
      if (err) {
        reject(err);
      }
      resolve();
    });
  });
}

app.listen(3000, () => {
  console.log("Server ready");
});
