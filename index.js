var express = require('express');
var app = express();
var bodyParser = require('body-parser');
var morgan = require('morgan');
var mongoose = require('mongoose');
var jwt = require('jsonwebtoken');
//var passport = require("passport");
//var passportJWT = require("passport-jwt");
var bcrypt = require('bcryptjs');
var config = require('./config');
var User = require('./user');

//configuration

const url = 'mongodb://localhost/testPassport';
var port = process.env.PORT || 3000;
app.set('superSecret', config.secret);

//connection with the database

mongoose.connect(url, { useMongoClient: true });
var db = mongoose.connection;

db.on('error', function(err) {
    if (err) throw err;
});

db.once('open', function callback() {
    console.info('Mongo db connected successfully on ', url);
});

// use body parser so we can get info from POST and/or URL parameters

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// use morgan to log requests to the console

app.use(morgan('dev'));

// unprotected routes

app.get('/', function(req, res) {
    res.send('Hello! Please proceed to http://localhost:' + port + '/home');
});

app.get('/home', function(req, res) {
    res.send('Please register at http://localhost:' + port + '/home/register' + ' or login at http://localhost:' + port + '/home/login');
});

//create a new user, unprotected route 

app.post('/home/register', function(req, res) {

    console.log(req.body);
    if (!req.body.username || !req.body.password) {
        res.json({ success: false, msg: 'Please pass username and password.' });
    } else {
        var newUser = new User({
            username: req.body.username,
            password: req.body.password
        });

        // save the new user

        User.createUser(newUser, function(err, user) {
            if (err) {
                res.json({ success: false, msg: 'Username already exists.' });
            } else {
            res.json({ success: true, msg: 'Successfully created new user.' });
            }
        });
    }
});

// create a router

var routes = express.Router();

routes.post('/home/login', function(req, res) {

    // find the user, if they exist issue a token

    User.findOne({
        username: req.body.username
    }, function(err, user) {

        if (err) throw err;
        console.log(user);
        if (!user) {
            console.log(user)
            res.json({ success: false, message: 'Authentication failed. User not found.' });
        } else if (user) {

            if (bcrypt.compareSync(req.body.password, user.password)) {

                const payload = {
                    admin: user.admin
                };

                var token = jwt.sign(payload, app.get('superSecret'), {
                    expiresIn: 60 * 60 * 24

                });

                res.json({
                    success: true,
                    token: token
                });

            } else {
                res.json({ success: false, message: 'Authentication failed. Wrong password.' });
            }

        };
    });
});
// route middleware to verify a token

routes.use(function(req, res, next) {

    // check header or url parameters or post parameters for token
    var token = req.body.token || req.query.token || req.headers['x-access-token'];

    // decode token
    if (token) {
        // verifies secret and checks exp
        jwt.verify(token, app.get('superSecret'), function(err, decoded) {
            if (err) {
                return res.json({ success: false, message: 'Failed to authenticate token.' });
            } else {
                // if everything is good, save to request for use in other routes
                req.decoded = decoded;
                next();
            }
        });
    } else {
        return res.status(403).send({
            success: false,
            message: 'No token provided.'
        });
    }
});

//protected route, access with token only

routes.get('/home/login/secret', function(req, res) {
    res.json({ message: 'Congrats, you sucesfully used your token' });
});

app.use('/', routes);

//start the server

app.listen(port);
console.log('Server is running on http://localhost:' + port);
