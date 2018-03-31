/**
 * Satellizer Node.js Example
 * (c) 2015 Sahat Yalkabov
 * License: MIT
 */

var path = require('path');
var qs = require('querystring');

var bodyParser = require('body-parser');
var cors = require('cors');
var express = require('express');
var jwt = require('jwt-simple');
var moment = require('moment');
var request = require('request');
var UserRepository = require("./user-repository.js")

var config = require('./config');

var app = express();

app.set('port', process.env.NODE_PORT || 3000);
app.set('host', process.env.NODE_IP || 'localhost');
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Force HTTPS on Heroku
if (app.get('env') === 'production') {
  app.use(function(req, res, next) {
    var protocol = req.get('x-forwarded-proto');
    protocol == 'https' ? next() : res.redirect('https://' + req.hostname + req.url);
  });
}
app.use(express.static(path.join(__dirname, '../../client')));

/*
 |--------------------------------------------------------------------------
 | Login Required Middleware
 |--------------------------------------------------------------------------
 */
function ensureAuthenticated(req, res, next) {
  if (!req.header('Authorization')) {
    return res.status(401).send({ message: 'Please make sure your request has an Authorization header' });
  }
  var token = req.header('Authorization').split(' ')[1];

  var payload = null;
  try {
    payload = jwt.decode(token, config.JWT_SECRET);
  }
  catch (err) {
    return res.status(401).send({ message: err.message });
  }

  if (payload.exp <= moment().unix()) {
    return res.status(401).send({ message: 'Token has expired' });
  }
  req.user = payload.sub;
  next();
}

function makePassword(length) {
  var text = "";
  var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  for (var i = 0; i < length; i++)
    text += possible.charAt(Math.floor(Math.random() * possible.length));

  return text;
}

/*
 |--------------------------------------------------------------------------
 | Generate JSON Web Token
 |--------------------------------------------------------------------------
 */
function createJWT(user) {
  var payload = {
    sub: user.id,
    iat: moment().unix(),
    exp: moment().add(14, 'days').unix()
  };
  return jwt.encode(payload, config.JWT_SECRET);
}

/*
 |--------------------------------------------------------------------------
 | GET /api/me
 |--------------------------------------------------------------------------
 */
app.get('/api/me', ensureAuthenticated, function(req, res) {
  UserRepository.findById(req.user).then(user => {
    res.send(user);
  });
});

/*
 |--------------------------------------------------------------------------
 | PUT /api/me
 |--------------------------------------------------------------------------
 */
app.put('/api/me', ensureAuthenticated, function(req, res) {
  User.findById(req.user).then(user => {
    if (!user) {
      return res.status(400).send({ message: 'User not found' });
    }
    user.displayName = req.body.displayName || user.displayName;
    user.email = req.body.email || user.email;
    UserRepository.save(user).then(() => {
      res.status(200).end();
    });
  });
});

/*
 |--------------------------------------------------------------------------
 | Log in with Email
 |--------------------------------------------------------------------------
 */
app.post('/auth/login', function(req, res) {
  UserRepository.findOne({ email: req.body.email }).then(user => {
    if (!user) {
      return res.status(401).send({ message: 'Invalid email and/or password' });
    }
    user.comparePassword(req.body.password).then(isMatch => {
      if (!isMatch) {
        return res.status(401).send({ message: 'Invalid email and/or password' });
      }
      res.send({ token: createJWT(user) });
    });
  });
});

/*
 |--------------------------------------------------------------------------
 | Login with GitHub
 |--------------------------------------------------------------------------
 */
app.post('/auth/github', function(req, res) {
  var accessTokenUrl = 'https://github.com/login/oauth/access_token';
  var userApiUrl = 'https://api.github.com/user';
  var params = {
    code: req.body.code,
    client_id: req.body.clientId,
    client_secret: config.GITHUB_SECRET,
    redirect_uri: req.body.redirectUri
  };

  // Step 1. Exchange authorization code for access token.
  request.get({ url: accessTokenUrl, qs: params }, function(err, response, accessToken) {
    accessToken = qs.parse(accessToken);
    var headers = { 'User-Agent': 'Satellizer' };

    // Step 2. Retrieve profile information about the current user.
    request.get({ url: userApiUrl, qs: accessToken, headers: headers, json: true }, function(err, response, profile) {

      // Step 3a. Link user accounts.
      if (req.header('Authorization')) {
        UserRepository.findOne({ github: profile.id }).then(existingUser => {
          if (existingUser) {
            return res.status(409).send({ message: 'There is already a GitHub account that belongs to you' });
          }
          var token = req.header('Authorization').split(' ')[1];
          var payload = jwt.decode(token, config.JWT_SECRET);
          UserRepository.findById(payload.sub).then(user => {
            if (!user) {
              return res.status(400).send({ message: 'User not found' });
            }
            user.github = profile.id;
            user.picture = user.picture || profile.avatar_url;
            user.displayName = user.displayName || profile.name;
            UserRepository.save(user).then(() => {
              var token = createJWT(user);
              res.send({ token: token });
            });
          });
        });
      } else {
        // Step 3b. Create a new user account or return an existing one.
        UserRepository.findOne({ github: profile.id }).then(existingUser => {
          if (existingUser) {
            var token = createJWT(existingUser);
            return res.send({ token: token });
          }
          
          const temporaryPassword = makePassword(6)
          var user = UserRepository.create(profile.email, temporaryPassword);
          user.github = profile.id;
          user.picture = profile.avatar_url;
          user.displayName = profile.name;
          user.temporaryPassword = temporaryPassword

          UserRepository.save(user).then(() => {
            var token = createJWT(user);
            res.send({ token: token });
          });
        });
      }
    });
  });
});

/*
 |--------------------------------------------------------------------------
 | Unlink Provider
 |--------------------------------------------------------------------------
 */
app.post('/auth/unlink', ensureAuthenticated, function(req, res) {
  var provider = req.body.provider;
  var providers = ['github'];

  if (providers.indexOf(provider) === -1) {
    return res.status(400).send({ message: 'Unknown OAuth Provider' });
  }

  UserRepository.findById(req.user).then(user => {
    if (!user) {
      return res.status(400).send({ message: 'User Not Found' });
    }
    user[provider] = undefined;
    UserRepository.save(user).then(() => {
      res.status(200).end();
    });
  });
});

/*
 |--------------------------------------------------------------------------
 | Start the Server
 |--------------------------------------------------------------------------
 */
require("./init-user-repository.js").then(() => {
  app.listen(app.get('port'), app.get('host'), function() {
    console.log('Express server listening on port ' + app.get('port'));
  });  
})