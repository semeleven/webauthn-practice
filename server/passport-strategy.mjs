import passport from "passport-strategy";
import util from "util";

function Strategy(verify) {
  if (!verify) {
    throw new TypeError("LocalStrategy requires a verify callback");
  }

  passport.Strategy.call(this);
  this.name = "local";
  this._verify = verify;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function (req, options) {
  options = options || {};
  const optionsForCheck = req.body;
  const expectedChallenge = req.session.challenge;

  if (!optionsForCheck || !expectedChallenge) {
    return this.fail(
      { message: options.badRequestMessage || "Missing credentials" },
      400
    );
  }

  const verified = (err, user, info) => {
    if (err) {
      return this.error(err);
    }
    if (!user) {
      return this.fail(info);
    }
    this.success(user, info);
  };

  try {
    this._verify(optionsForCheck, expectedChallenge, verified);
  } catch (ex) {
    return self.error(ex);
  }
};

/**
 * Expose `Strategy`.
 */
export default Strategy;
