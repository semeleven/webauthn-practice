import Strategy from "./passport-strategy.mjs";

function initialize(passport, getUserById, getByCredentialID, checkChallenge) {
  const authenticateUser = async (
    optionsForCheck,
    expectedChallenge,
    done
  ) => {
    const user = getByCredentialID(optionsForCheck.id);
    if (user == null) {
      return done(null, false, { message: "No user with that key" });
    }

    try {
      if (await checkChallenge(user, optionsForCheck, expectedChallenge)) {
        return done(null, user);
      } else {
        return done(null, false, { message: "Key not verified" });
      }
    } catch (e) {
      return done(e);
    }
  };

  passport.use(new Strategy(authenticateUser));
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser((id, done) => {
    return done(null, getUserById(id));
  });
}

export default initialize;
