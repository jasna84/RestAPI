// get an instance of mongoose and mongoose.Schema
var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var bcrypt = require('bcryptjs');

// set up a mongoose model and pass it using module.exports
module.exports = mongoose.model('User', new Schema({
    username: { type: String, unique: true, required: true },
    password: String,
    admin: Boolean
}));

module.exports.createUser = function(newUser, callback) {
    bcrypt.genSalt(10, function(err, salt) {
        bcrypt.hash(newUser.password, salt, function(err, hash) {
            // Store hash in your password DB
            newUser.password = hash;
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