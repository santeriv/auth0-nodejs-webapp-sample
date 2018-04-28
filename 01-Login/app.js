const express = require('express');
const path = require('path');
const favicon = require('serve-favicon');
const logger = require('morgan');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const passport = require('passport');
const Auth0Strategy = require('passport-auth0');
const flash = require('connect-flash');
const jwt = require('jsonwebtoken');

dotenv.load();

const routes = require('./routes/index');
const user = require('./routes/user');

// This will configure Passport to use Auth0
const strategy = new Auth0Strategy(
  {
    domain: process.env.AUTH0_DOMAIN,
    clientID: process.env.AUTH0_CLIENT_ID,
    clientSecret: process.env.AUTH0_CLIENT_SECRET,
    callbackURL:
      process.env.AUTH0_CALLBACK_URL || 'http://localhost:3000/callback'
  },
  function(accessToken, refreshToken, extraParams, payload, done) {
    // accessToken is the token to call Auth0 API (not needed in the most cases)
    // extraParams.id_token has the JSON Web Token
    // profile has all the information from the user
    console.log('strategy callback');
    const jwtToken = extraParams.id_token;
    let tokenExpirationDate;
    try {
      const jwtPayload = jwt.verify(jwtToken, process.env.AUTH0_CLIENT_SECRET);
      console.log('jwt.verify(jwtToken) HS256', jwtPayload);
      tokenExpirationDate = new Date(jwtPayload.exp*1000);
    }
    catch (e) {
      // Most likely invalid signature (wrong key, or hack attempt)
      console.error(e);
      return done(null, false);
    }
    return done(null, { payload, jwtToken, tokenExpirationDate });
  }
);

passport.use(strategy);

const app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(passport.initialize());
app.use(express.static(path.join(__dirname, 'public')));

app.use(flash());

// Handle auth failure error messages
app.use(function(req, res, next) {
 if (req && req.query && req.query.error) {
   req.flash("error", req.query.error);
 }
 if (req && req.query && req.query.error_description) {
   req.flash("error_description", req.query.error_description);
 }
 next();
});

// Check logged in
app.use(function(req, res, next) {
  res.locals.loggedIn = false;
  console.log('check logged in jwtToken', req.cookies.jwtToken);
  if (req.cookies.jwtToken) {
    try {
      const jwtPayload = jwt.verify(req.cookies.jwtToken, process.env.AUTH0_CLIENT_SECRET);
      res.locals.loggedIn = true;
      res.locals.user = jwtPayload;
    }
    catch (e) {
      // Most likely invalid signature (wrong key, or hack attempt)
      console.error(e);
    }
  }
  next();
});

app.use('/', routes);
app.use('/user', user);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  const err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
  app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
      message: err.message,
      error: err
    });
  });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
  res.status(err.status || 500);
  res.render('error', {
    message: err.message,
    error: {}
  });
});

module.exports = app;
