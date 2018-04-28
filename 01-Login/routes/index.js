const express = require('express');
const passport = require('passport');
const router = express.Router();

const env = {
  AUTH0_CLIENT_ID: process.env.AUTH0_CLIENT_ID,
  AUTH0_DOMAIN: process.env.AUTH0_DOMAIN,
  AUTH0_CALLBACK_URL:
    process.env.AUTH0_CALLBACK_URL || 'http://localhost:3000/callback'
};

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index');
});

router.get('/login', passport.authenticate('auth0', {
  clientID: env.AUTH0_CLIENT_ID,
  domain: env.AUTH0_DOMAIN,
  session: false,
  responseType: 'code',
  audience: 'https://' + env.AUTH0_DOMAIN + '/userinfo',
  scope: 'openid profile'}),
  function(req, res) {
    console.log('login continue after auth call');
    res.redirect("/");
});

router.get('/logout', function(req, res) {
  res.clearCookie('jwtToken');
  res.redirect('/');
});

router.get('/callback',
  passport.authenticate('auth0', {
    session: false,
  }),
  function(req, res) {
    console.log('callback continue after auth call', req.user.tokenExpirationDate);
    req.user.profile = req.user.payload.Profile;
    res.cookie('jwtToken', req.user.jwtToken, { expires: req.user.tokenExpirationDate, httpOnly: true })
    res.redirect('/user');
  }
);

router.get('/failure', function(req, res) {
  var error = req.flash("error");
  var error_description = req.flash("error_description");
  req.logout();
  res.render('failure', {
    error: error[0],
    error_description: error_description[0],
  });
});

module.exports = router;
