var vows = require('vows');
var assert = require('assert');
var util = require('util');
var bearer = require('passport-ember-auth');


vows.describe('passport-ember-auth').addBatch({

  'module': {
    'should report a version': function (x) {
      assert.isString(bearer.version);
    },
  },

}).export(module);
