var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var jwt = require('jsonwebtoken');
var passportJWT = require("passport-jwt");
//var ExtractJwt = passportJWT.ExtractJwt;
const ExtractJwt = require('passport-jwt').ExtractJwt;
var JwtStrategy = passportJWT.Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;

var User = require('../user');
var config = require('./config');
var configAuth = require('./auth');


module.exports = function(passport) {


    passport.use('local-login', new LocalStrategy(
        function(username, password, done) {
            console.log(username, password);
            process.nextTick(function() {
                User.findOne({ 'local.username': username }, function(err, user) {
                    console.log(user)
                    if (err) {

                        return done(err);
                    }

                    if (!user) {
                        console.log(user);
                        return done(null, false, { message: 'Authentication failed. User not found.' });

                    } else {
                        User.comparePasswords(password, user.local.password, function(err, isMatch) {
                            console.log(isMatch, err);

                            if (isMatch && !err) {

                                return done(null, user);

                            } else {
                                return done(null, false, { message: 'Authentication failed. Wrong password.' });
                            }
                        });
                    }
                });
            });
        }
    ));

    // JWT passport strategy

    var opts = {

        secretOrKey: config.secret,
        jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken()
    };

    passport.use('jwt', new JwtStrategy(opts, function(payload, done) {


        User.findOne({ _id: payload.id }, function(err, user) {

            if (err) {

                return done(err, false);
            }
            if (user) {

                done(null, user);
            } else {

                done(null, false);
            }
        });
    }));

    passport.use(new FacebookStrategy({
            clientID: configAuth.facebookAuth.clientID,
            clientSecret: configAuth.facebookAuth.clientSecret,
            callbackURL: configAuth.facebookAuth.callbackURL
        },
        function(accessToken, refreshToken, profile, done) {
            process.nextTick(function() {

                //user is not logged in yet

                if (!req.user) {
                    console.log(user);
                    User.findOne({ 'facebook.id': profile.id }, function(err, user) {
                        if (err)
                            return done(err);
                        if (user)
                            return done(null, user);
                        else {
                            var newUser = new User();
                            newUser.facebook.id = profile.id;
                            newUser.facebook.token = accessToken;
                            newUser.facebook.name = profile.name.givenName + ' ' + profile.name.familyName;
                            newUser.facebook.email = profile.emails[0].value;

                            newUser.save(function(err) {
                                if (err)
                                    throw err;
                                return done(null, newUser);
                            })
                        }
                    });
                }

                //user is logged in already, and needs to be merged
                else {
                    var user = req.user;
                    user.facebook.id = profile.id;
                    user.facebook.token = accessToken;
                    user.facebook.name = profile.name.givenName + ' ' + profile.name.familyName;
                    user.facebook.email = profile.emails[0].value;

                    user.save(function(err) {
                        if (err)
                            throw err
                        return done(null, user);
                    })
                }

            });
        }
    ));

    passport.use(new GoogleStrategy({
            clientID: configAuth.googleAuth.clientID,
            clientSecret: configAuth.googleAuth.clientSecret,
            callbackURL: configAuth.googleAuth.callbackURL,
            passReqToCallback: true
        },
        function(req, accessToken, refreshToken, profile, done) {
            process.nextTick(function() {

                if (!req.user) {
                    User.findOne({ 'google.id': profile.id }, function(err, user) {
                        if (err)
                            return done(err);
                        if (user)
                            return done(null, user);
                        else {
                            var newUser = new User();
                            newUser.google.id = profile.id;
                            newUser.google.token = accessToken;
                            newUser.google.name = profile.displayName;
                            newUser.google.email = profile.emails[0].value;

                            newUser.save(function(err) {
                                if (err)
                                    throw err;
                                return done(null, newUser);
                            })
                        }
                    });
                } else {
                    var user = req.user;
                    user.google.id = profile.id;
                    user.google.token = accessToken;
                    user.google.name = profile.displayName;
                    user.google.email = profile.emails[0].value;

                    user.save(function(err) {
                        if (err)
                            throw err;
                        return done(null, user);
                    });
                }
            });
        }

    ));

};