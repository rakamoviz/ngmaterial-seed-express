/**
 * Satellizer Node.js Example
 * (c) 2015 Sahat Yalkabov
 * License: MIT
 */

const path = require('path');
const qs = require('querystring');

const bodyParser = require('body-parser');
const cors = require('cors');
const express = require('express');
const jwt = require('jwt-simple');
const moment = require('moment');
const request = require('request');
const UserRepository = require("./user-repository.js")

const config = require('./config');

const app = express();

app.set('port', process.env.NODE_PORT || 3000);
app.set('host', process.env.NODE_IP || 'localhost');
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Force HTTPS on Heroku
if (app.get('env') === 'production') {
  app.use((req, res, next) => {
    const protocol = req.get('x-forwarded-proto');
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
  const token = req.header('Authorization').split(' ')[1];
  let payload = null;
  try {
    payload = jwt.decode(token, config.JWT_SECRET);
  }
  catch (err) {
    return res.status(401).send({ message: err.message });
  }

  if (payload.exp <= moment().unix()) {
    return res.status(401).send({ message: 'Token has expired' });
  }

  req.userId = payload.sub;
  next();
}

function makePassword(length) {
  let text = "";
  const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  for (let i = 0; i < length; i++)
    text += possible.charAt(Math.floor(Math.random() * possible.length));

  return text;
}

/*
 |--------------------------------------------------------------------------
 | Generate JSON Web Token
 |--------------------------------------------------------------------------
 */
function createJWT(user) {
  const payload = {
    sub: user._id,
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
app.get('/api/me', ensureAuthenticated, (req, res) => {
  UserRepository.findById(req.userId).then(user => {
    res.send(user);
  });
});

/*
 |--------------------------------------------------------------------------
 | PUT /api/me
 |--------------------------------------------------------------------------
 */
app.put('/api/me', ensureAuthenticated, (req, res) => {
  User.findById(req.userId).then(user => {
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
app.post('/auth/login', (req, res) => {
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
app.post('/auth/github', (req, res) => {
  const accessTokenUrl = 'https://github.com/login/oauth/access_token';
  const userApiUrl = 'https://api.github.com/user';
  const params = {
    code: req.body.code,
    client_id: req.body.clientId,
    client_secret: config.GITHUB_SECRET,
    redirect_uri: req.body.redirectUri
  };

  // Step 1. Exchange authorization code for access token.
  request.get({ url: accessTokenUrl, qs: params }, (err, response, accessToken) => {
    accessToken = qs.parse(accessToken);
    const headers = { 'User-Agent': 'Satellizer' };

    // Step 2. Retrieve profile information about the current user.
    request.get({ 
      url: userApiUrl, qs: accessToken, headers: headers, json: true 
    }, (err, response, profile) => {
      // Step 3a. Link user accounts.

      if (req.header('Authorization')) {
        // This is for the case when user logs-in with email first, and then later decides to link with github
        UserRepository.findOne({github: {profile: {id: profile.id }}}).then(existingUser => {
          if (existingUser) {
            return res.status(409).send({ message: 'There is already a GitHub account that belongs to you' });
          }
          const token = req.header('Authorization').split(' ')[1];
          const payload = jwt.decode(token, config.JWT_SECRET);
          const userId = payload.sub

          UserRepository.findById(userId).then(user => {
            if (!user) {
              return res.status(400).send({ message: 'User not found' });
            }

            user.github = {
              profile: {
                id: profile.id,
                picture: profile.avatar_url,
                displayName: profile.name
              },
              pass: accessToken
            }
            UserRepository.save(user).then(() => {
              const token = createJWT(user);
              res.send({ token: token });
            });
          });
        });
      } else {
        // This is for the case when user logs-in directly using his github account
        // Step 3b. Create a new user account or return an existing one.
        UserRepository.findOne({ github: {profile: {id: profile.id}} }).then(existingUser => {
          if (existingUser) {
            existingUser.github.pass = accessToken 
            UserRepository.save(existingUser).then(() => {
              const token = createJWT(existingUser);
              res.send({ token: token });
            });
          } else {
            const temporaryPassword = makePassword(6)
            UserRepository.create(profile.email, temporaryPassword).then(user => {
              user.github = {
                profile: {
                  id: profile.id,
                  picture: profile.avatar_url,
                  displayName: profile.name
                },
                pass: accessToken
              }
              user.temporaryPassword = temporaryPassword
    
              UserRepository.save(user).then(() => {
                const token = createJWT(user);
                res.send({ token: token });
              });
            });
          }
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
app.post('/auth/unlink', ensureAuthenticated, (req, res) => {
  const provider = req.body.provider;
  const providers = ['github'];

  if (providers.indexOf(provider) === -1) {
    return res.status(400).send({ message: 'Unknown OAuth Provider' });
  }

  UserRepository.findById(req.userId).then(user => {
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
  app.listen(app.get('port'), app.get('host'), () => {
    console.log('Express server listening on port ' + app.get('port'));
  });  
})