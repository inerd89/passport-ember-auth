/**
 * Module dependencies.
 */
var passport = require('passport')
  , util = require('util');


/**
 * `Strategy` constructor.
 *
 * The Ember-Auth strategy is based on the ember-auth authentication framework
 * for ember.js. More info: https://github.com/heartsentwined/ember-auth
 *
 * The Ember-Auth authentication strategy authenticates requests based on
 * an authentication token contained in the `Authorization` header field, `auth_token`
 * body parameter, or `auth_token` query parameter. An alternative token key can be
 * specified in the `options` object.
 *
 * Applications must supply a `verify` callback which accepts a `token`, and
 * then calls the `done` callback supplying a `user`, which should be set to
 * `false` if the token is not valid.  Additional token `info` can optionally be
 * passed as a third argument, which will be set by Passport at `req.authInfo`,
 * where it can be used by later middleware for access control.
 *
 * Options:
 *   - `tokenKey`  token key, defaults to "auth_token"
 *   - `passReqToCallback`  set to `true` if you want to pass the req to your `verify` callback
 *
 * Examples:
 *
 *     passport.use(new EmberAuthStrategy(
 *       function(token, done) {
 *         User.findByToken({ token: token }, function (err, user) {
 *           if (err) { return done(err); }
 *           if (!user) { return done(null, false); }
 *           return done(null, user);
 *         });
 *       }
 *     ));
 *
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) throw new Error('EmberAuth authentication strategy requires a verify function');
  
  passport.Strategy.call(this);
  this.name = 'EmberAuth';
  this._verify = verify;
  this._tokenKey = options.tokenKey || 'auth_token';
  this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of an authorization
 * header, body parameter, or query parameter.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req) {
  var token = undefined;
  
  if (req.headers && req.headers['authorization']) {
    var parts = req.headers['authorization'].split(' ');
    if (parts.length == 2) {
      var key = parts[0]
        , credentials = parts[1];
      
      var pattern = new RegExp(this._tokenKey, "i");

      if (pattern.test(key)) {
        token = credentials;
      }
    } else {
      return this.fail(400);
    }
  }


  if (req.body && req.body[this._tokenKey]) {
    if (token) { return this.fail(400); }
    token = req.body[this._tokenKey];
  }

  if (req.query && req.query[this._tokenKey]) {
    if (token) { return this.fail(400); }
    token = req.query[this._tokenKey];
  }
  
  if (!token) { return this.fail(400); }
  
  var self = this;
  
  function verified(err, user, info) {
    if (err) { return self.error(err); }
    if (!user) { return self.fail(401); }
    self.success(user, info);
  } 
  
  if (self._passReqToCallback) {
    this._verify(req, token, verified);
  } else {
    this._verify(token, verified);
  }  
 
}

/**
 * Expose `Strategy`.
 */ 
module.exports = Strategy;
