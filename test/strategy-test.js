var vows = require('vows');
var assert = require('assert');
var util = require('util');
var EmberAuth = require('passport-ember-auth');
var EmberAuthStrategy = require('passport-ember-auth/strategy');


vows.describe('EmberAuthStrategy').addBatch({

  'strategy': {
    topic: function() {
      return new EmberAuthStrategy(function() {});
    },

    'should be named EmberAuth': function (strategy) {
      assert.equal(strategy.name, 'EmberAuth');
    },
  },

  'strategy handling a valid request with authorization header': {
    topic: function() {
      var strategy = new EmberAuthStrategy(function(token, done) {
        done(null, { token: token });
      });
      return strategy;
    },

    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(null, user);
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }

        req.headers = {};
        req.headers.authorization = 'AUTH_TOKEN vF9dft4qmT';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },

      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.token, 'vF9dft4qmT');
      }
    },
  },

  'strategy handling a valid request with form-encoded body': {
    topic: function() {
      var strategy = new EmberAuthStrategy(function(token, done) {
        done(null, { token: token });
      });
      return strategy;
    },

    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(null, user);
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }

        req.body = {};
        req.body.auth_token = 'vF9dft4qmT';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },

      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.token, 'vF9dft4qmT');
      },
    },
  },

  'strategy handling a valid request with URI query': {
    topic: function() {
      var strategy = new EmberAuthStrategy(function(token, done) {
        done(null, { token: token });
      });
      return strategy;
    },

    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(null, user);
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }

        req.query = {};
        req.query.auth_token = 'vF9dft4qmT';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },

      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.token, 'vF9dft4qmT');
      },
    },
  },

  'strategy handling a valid request with a custom token key in an authorization header': {
    topic: function() {
      var strategy = new EmberAuthStrategy({tokenKey: 'custom_key'}, function(token, done) {
        done(null, { token: token });
      });
      return strategy;
    },

    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(null, user);
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }

        req.headers = {};
        req.headers.authorization = 'CUSTOM_KEY vF9dft4qmT';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },

      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.token, 'vF9dft4qmT');
      }
    },
  },

  'strategy handling a valid request with a custom token key in a form-encoded body': {
    topic: function() {
      var strategy = new EmberAuthStrategy({tokenKey: 'custom_key'}, function(token, done) {
        done(null, { token: token });
      });
      return strategy;
    },

    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(null, user);
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }

        req.body = {};
        req.body.custom_key = 'vF9dft4qmT';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },

      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.token, 'vF9dft4qmT');
      },
    },
  },

  'strategy handling a valid request with a custom token key in a URI query': {
    topic: function() {
      var strategy = new EmberAuthStrategy({tokenKey: 'custom_key'}, function(token, done) {
        done(null, { token: token });
      });
      return strategy;
    },

    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(null, user);
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }

        req.query = {};
        req.query.custom_key = 'vF9dft4qmT';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },

      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.token, 'vF9dft4qmT');
      },
    },
  },

  'strategy handling a valid request and passing additional info': {
    topic: function() {
      var strategy = new EmberAuthStrategy(function(token, done) {
        done(null, { token: token }, { foo: 'bar' });
      });
      return strategy;
    },

    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user, info) {
          self.callback(null, user, info);
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }

        req.headers = {};
        req.headers.authorization = 'AUTH_TOKEN vF9dft4qmT';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },

      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.token, 'vF9dft4qmT');
      },
      'should pass auth info' : function(err, user, info) {
        assert.equal(info.foo, 'bar');
      }
    },
  },

  'strategy handling a valid request with authorization header with req argument to callback': {
    topic: function() {
      var strategy = new EmberAuthStrategy({passReqToCallback: true}, function(req, token, done) {
        done(null, { token: token, foo: req.foo });
      });
      return strategy;
    },

    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(null, user);
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }

        req.headers = {};
        req.headers.authorization = 'AUTH_TOKEN vF9dft4qmT';
        req.foo = 'bar';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },

      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.token, 'vF9dft4qmT');
      },
      'should have request details' : function(err, user) {
        assert.equal(user.foo, 'bar');
      },
    },
  },

  'strategy handling a request that is not validated': {
    topic: function() {
      var strategy = new EmberAuthStrategy(function(token, done) {
        done(null, false);
      });
      return strategy;
    },

    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(status) {
          self.callback(null, status);
        }

        req.headers = {};
        req.headers.authorization = 'AUTH_TOKEN vF9dft4qmT';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },

      'should fail authentication with 401 Unauthorized' : function(err, status) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(status, 401);
      },
    },
  },

  'strategy handling a request that encounters an error during verification': {
    topic: function() {
      var strategy = new EmberAuthStrategy(function(token, done) {
        done(new Error('something went wrong'));
      });
      return strategy;
    },

    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(new Error('should not be called'));
        }
        strategy.error = function(err) {
          self.callback(null, err);
        }

        req.headers = {};
        req.headers.authorization = 'AUTH_TOKEN vF9dft4qmT';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },

      'should not call success or fail' : function(err, e) {
        assert.isNull(err);
      },
      'should call error' : function(err, e) {
        assert.instanceOf(e, Error);
      },
    },
  },

  'strategy handling a request without authorization credentials': {
    topic: function() {
      var strategy = new EmberAuthStrategy(function(token, done) {
        done(null, { token: token });
      });
      return strategy;
    },

    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(status) {
          self.callback(null, status);
        }

        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },

      'should fail authentication with 400 Bad Request' : function(err, status) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(status, 400);
      },
    },
  },

  'strategy handling a request with malformed authorization header': {
    topic: function() {
      var strategy = new EmberAuthStrategy(function(token, done) {
        done(null, { token: token });
      });
      return strategy;
    },

    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(status) {
          self.callback(null, status);
        }

        req.headers = {};
        req.headers.authorization = 'AUTH_TOKEN';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },

      'should fail authentication with 400 Bad Request' : function(err, status) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(status, 400);
      },
    },
  },

  'strategy handling a valid request with token key in lowercase letters': {
    topic: function() {
      var strategy = new EmberAuthStrategy(function(token, done) {
        done(null, { token: token });
      });
      return strategy;
    },

    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(null, user);
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }

        req.headers = {};
        req.headers.authorization = 'auth_token vF9dft4qmT';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },

      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.token, 'vF9dft4qmT');
      },
    },
  },

  'strategy constructed without a validate callback': {
    'should throw an error': function (strategy) {
      assert.throws(function() { new EmberAuthStrategy() });
    },
  },

  'strategy getting token via multiple methods': {
    topic: function() {
      var strategy = new EmberAuthStrategy(function(token, done) {
        assert.ok(false);
      });
      var self = this;
      var req = {};
      req.headers = {};
      req.headers.authorization = 'AUTH_TOKEN vF9dft4qmT';
      req.query = {};
      req.query.auth_token = "vF9dft4qmT";
      strategy.success = function(user) {
        self.callback(new Error("should not be called"));
      };
      strategy.fail = function(status) {
        self.callback(null, status);
      }
      process.nextTick(function() {
        strategy.authenticate(req);
      });
    },
    'should fail authentication with error 400': function(err, status) {
      assert.isNull(err);
      assert.equal(status, 400);
    }
  }

}).export(module);
