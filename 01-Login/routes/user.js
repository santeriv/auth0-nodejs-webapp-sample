const express = require('express');
const passport = require('passport');
const router = express.Router();

/* GET user profile. */
router.get('/', function(req, res, next) {
  console.log('/user--> req.user is not set', req.user);
  console.log('/user--> res.locals is set', res.locals);
  res.render('user');
});

module.exports = router;
