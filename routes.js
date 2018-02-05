var express = require('express');
var mongoose = require('mongoose');
var jwt = require('jsonwebtoken');
var User = require('./user');
var config = require('./config/config');
var passport = require('passport');
var async = require('async');
var crypto = require('crypto');
var nodemailer = require('nodemailer');
var app = express();
var routes = express.Router();
var port = process.env.PORT || 3000;



// unprotected routes

routes.get('/', function(req, res) {
    res.send('Hello! Please proceed to http://localhost:' + port + '/login');
});

// create a new user, unprotected route 

routes.post('/register', function(req, res) {

    console.log(req.body);
    if (!req.body.username || !req.body.password) {
        res.json({ success: false, msg: 'Please pass username and password.' });
    } else {
        var newUser = new User({

            local: {

                username: req.body.username,
                password: req.body.password,
                firstName: req.body.firstName,
                lastName: req.body.lastName,
                email_address: req.body.email_address

            },

        });

        // save the new user

        User.createUser(newUser, function(err, user) {
            console.log(user);
            console.log(err);
            if (err) {
                res.json({ success: false, msg: 'That username or email address already exist.' });
            } else {

                res.json({
                    success: true,
                    message: 'Successfully created new user',

                });
            }
        });
    }
});

// //login route

routes.post('/login', passport.authenticate('local-login', { session: false }), function(req, res) {
    //console.log(res.req.user.id);
    var payload = { id: res.req.user.id };
    var token = jwt.sign(payload, config.secret);
    res.json({ success: true, msg: "You are logged in", token: token });
});

// facebook login

routes.get('/auth/facebook', passport.authenticate('facebook'));

routes.get('/auth/facebook/callback',
    passport.authenticate('facebook', {
        successRedirect: '/profile',
        failureRedirect: '/login'
    }));

//google login

routes.get('/auth/google', passport.authenticate('google'));

routes.get('/auth/google/callback',
    passport.authenticate('google', {
        successRedirect: '/profile',
        failureRedirect: '/login'
    }));

routes.get('/logout', function(req, res) {
    console.log('Logging out');
    req.logout();
    res.json({ success: true, message: 'You logged out successfully', token: null });
});

routes.get('/profile', passport.authenticate('jwt', { session: false }), function(req, res, next) {
    res.status(200).send(req.user);
});

// route for password reset

routes.post('/forgot_password', function(req, res, next) {
    async.waterfall([
        function(done) {
            crypto.randomBytes(20, function(err, buf) {
                var token = buf.toString('hex');
                done(err, token);
            });
        },
        function(token, done) {
            console.log(req.body.email_address);
            User.findOne({ "local.email_address": req.body.email_address }, function(err, user) {
                console.log(user);
                if (!user) {
                    res.json({ success: false, msg: 'No account with that email address exists.' });
                } else {

                    user.local.resetPasswordToken = token;
                    user.local.resetPasswordExpires = Date.now() + 3600000; // 1 hour

                    user.save(function(err) {
                        done(err, token, user);
                    });
                }
            });
        },
        function(token, user, done) {
            var smtpTransport = nodemailer.createTransport({
                service: process.env.MAILER_SERVICE_PROVIDER,
                auth: {
                    user: process.env.MAILER_EMAIL_ID,
                    pass: process.env.MAILER_PASSWORD
                }
            });
            var mailOptions = {
                to: user.local.email_address,
                from: process.env.MAILER_EMAIL_ID,
                subject: 'Node.js Password Reset',
                text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
                    'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
                    'http://' + req.headers.host + '/reset/' + token + '\n\n' +
                    'If you did not request this, please ignore this email and your password will remain unchanged.\n'
            };
            smtpTransport.sendMail(mailOptions, function(err) {
                console.log('email sent');
                res.json({ msg: 'An e-mail has been sent to ' + user.local.email_address + ' with further instructions.' });
                done(err, 'done');
            });
        }
    ], function(err) {
        if (err) return next(err);
    });

});

routes.post('/reset/:token', function(req, res) {
    async.waterfall([
        function(done) {
            User.findOne({ 'local.resetPasswordToken': req.params.token, 'local.resetPasswordExpires': { $gt: Date.now() } }, function(err, user) {
                console.log(user);
                if (!user) {
                    res.json({ success: false, msg: 'Password reset token is invalid or has expired.' });
                }
                user.local.password = req.body.password;
                User.updateUser(user, function(err, user) {
                    console.log('user updated');
                    console.log(user);
                    if (err) {
                        res.json({ success: false, msg: "Couldn't update the user" })
                    } else {
                        res.json({ success: true, msg: 'Password reset ok' });
                    }

                });
                done(err, user);
            });
        },
        function(user, done) {
            var smtpTransport = nodemailer.createTransport({
                service: process.env.MAILER_SERVICE_PROVIDER,
                auth: {
                    user: process.env.MAILER_EMAIL_ID,
                    pass: process.env.MAILER_PASSWORD
                }
            });
            var mailOptions = {
                to: user.local.email_address,
                from: process.env.MAILER_EMAIL_ID,
                subject: 'Your password has been changed',
                text: 'Hello,\n\n' +
                    'This is a confirmation that the password for your account ' + user.local.email_address + ' has just been changed.\n'
            };
            smtpTransport.sendMail(mailOptions, function(err) {
                console.log('javio sam ti za reset');
                res.json({ success: true, msg: 'Success! Your password has been changed.' });
                done(err);
            });
        }
    ], function(err) {
        if (err) return next(err);
    });
});


module.exports = routes;