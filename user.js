// get an instance of mongoose and mongoose.Schema
var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var bcrypt = require('bcryptjs');
var async = require('async');
var crypto = require('crypto');

// set up a mongoose model and pass it using module.exports
module.exports = mongoose.model('User', new Schema({

    local: {
        username: { type: String, unique: true, required: true },
        password: { type: String, required: true },
        firstName: String,
        lastName: String,
        email_address: { type: String, unique: true, required: true },
        admin: Boolean,
        resetPasswordToken: String,
        resetPasswordExpires: Date
    },

    facebook: {
        id: String,
        token: String,
        email: String,
        name: String
    },

    google: {
        id: String,
        token: String,
        email: String,
        name: String
    }

}));

module.exports.createUser = function(newUser, callback) {
    bcrypt.genSalt(10, function(err, salt) {
        bcrypt.hash(newUser.local.password, salt, function(err, hash) {
            // Store hash in your password DB
            console.log(newUser.local.password);
            newUser.local.password = hash;
            newUser.save(callback);
        });
    });
};

module.exports.comparePasswords = function(password, hash, callback) {
    bcrypt.compare(password, hash, function(err, isMatch) {
        if (err) throw err;
        callback(null, isMatch);
    });
};

module.exports.updateUser = function(user, callback) {

    bcrypt.genSalt(10, function(err, salt) {
        bcrypt.hash(user.local.password, salt, function(err, hash) {

            // Store hash in your password DB
            user.local.password = hash;
            user.local.resetPasswordToken = undefined;
            user.local.resetPasswordExpires = undefined;
            user.save(callback);
        });
    });
};