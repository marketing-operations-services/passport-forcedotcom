/*jshint node:true*/
'use strict';
var util = require('util');
var OAuth2Strategy = require('passport-oauth2').Strategy;
var url = require('url');
var sf = require('node-salesforce');
var sfService = {};
var getPermissions;

function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://login.salesforce.com/services/oauth2/authorize';
  options.tokenURL = options.tokenURL || 'https://login.salesforce.com/services/oauth2/token';
  options.scopeSeparator = options.scopeSeparator || ' ';
  sfService.serviceUsername = options.serviceUsername;
  sfService.servicePassword = options.servicePassword;
  sfService.serviceLoginUrl = options.serviceLoginUrl;
  sfService.permissionIds = options.permissionIds;

  OAuth2Strategy.call(this, options, verify);
  this.name = 'forcedotcom';

  this._skipPhoto = options.skipPhoto || false;
  getPermissions = options.getPermissions || true;

  // salesforce uses the "Authorization: Bearer" header:
  this._oauth2.useAuthorizationHeaderforGET(true);

  // Override getOAuthAccessToken so we can capture the OAuth2 params and
  // attach them to the accessToken for use in userProfile().
  var origGetToken = this._oauth2.getOAuthAccessToken;
  this._oauth2.getOAuthAccessToken = function() {
    var args = Array.prototype.slice.call(arguments);
    var cb = args.pop();

    args.push(function attachParams(err, accessToken, refreshToken, params) {
      if (accessToken && params) {
        accessToken = new AccessTokenWithParams(params);
      }
      cb(err, accessToken, refreshToken, params);
    });

    origGetToken.apply(this, args);
  };
}
util.inherits(Strategy, OAuth2Strategy);
module.exports = Strategy;

/**
 * Wrap OAuth2 parameters while pretending to be the access token string.
 */
function AccessTokenWithParams(params) {
  this.params = params;
}

AccessTokenWithParams.prototype.toString = function() {
  return this.params.access_token;
};

/**
 * Override the OAuth2Strategy method.
 */
Strategy.prototype.authorizationParams = function(options) {

  var params = {};

  if (options.display)
    params.display = options.display;
    
  if (options.prompt)
    params.prompt = options.prompt;
    
  if (options.login_hint)
    params.login_hint = options.login_hint;

  return params;
};

/**
 * Override the OAuth2Strategy method.
 */
Strategy.prototype.userProfile = function(accessToken, cb) {
  var self = this;
  var params = accessToken.params;
  if (!params) {
    return cb(new Error('AccessToken did not have attached OAuth2 params'));
  }

  var baseUrl = url.parse(params.instance_url);
  var idUrl = url.parse(params.id);
  idUrl.host = baseUrl.host;

  self.getJSON(idUrl, accessToken, function(err, rawProfile) {
    if (err) {
      return cb(err);
    }

    var profile = {
      _raw: rawProfile,
    };

    if (self._skipPhoto) {
      return cb(null, self.coerceProfile(profile));
    }

    profile._raw._photo = rawProfile.photos || null;

    if(!getPermissions) {
      cb(null, self.coerceProfile(profile));
    }

    self.getPermissions(rawProfile, function(err, permissions) {
      if(err) {
        return cb(err);
      }
      profile._raw._permissions = permissions;
      cb(null, self.coerceProfile(profile));
    })
    
  });
};

// gets the permission set assignments for the oauthed user
Strategy.prototype.getPermissions = function(profile, cb) {
  var conn = new sf.Connection({
    loginUrl : sfService.serviceLoginUrl 
  });
  conn.login(sfService.serviceUsername, sfService.servicePassword, function(err, userInfo) {
    if (err) { cb(err); }
    var records = [];
    var queryString = "SELECT AssigneeId, PermissionSetId FROM PermissionSetAssignment WHERE ";
    for(var i = 0; i < sfService.permissionIds.length; i++) {
      queryString += ((i != 0) ? " OR " : "") 
        + "(AssigneeId = '" + profile.user_id + "' AND PermissionSetId = '" + sfService.permissionIds[i] + "')";
    }
    conn.query(queryString, function(err, result) {
      if (err) { cb(err); }
      cb(null, result.records);
    });
  });
}

/**
 * Wrapper for getting JSON with the specified access token.
 */
Strategy.prototype.getJSON = function(theUrl, token, cb) {
  if (typeof theUrl !== 'string') {
    theUrl = url.format(theUrl);
  }

  this._oauth2.get(theUrl, token, function(err, body) {
    if (err) {
      return cb(err);
    }

    var parsed;
    try {
      parsed = JSON.parse(body);
    } catch(e) {
      return cb(e);
    }

    cb(null, parsed);
  });
};

/**
 * Coerce a profile to the standard Passport format.
 */
Strategy.prototype.coerceProfile = function(profile) {
  var raw = profile._raw;
  var photoInfo = raw._photo;
  var permissions = raw._permissions;

  profile.provider = this.name;
  profile.id = raw.organization_id + '/' + raw.user_id;
  profile.displayName = raw.display_name;
  profile.name = {
    familyName: raw.last_name,
    givenName: raw.first_name
  };
  profile.emails = [
    { value: raw.email }
  ];

  if (photoInfo) {
    profile.photos = photoInfo ;
  }

  if(permissions) {
    profile.permissions = permissions;
  }

  return profile;
};
