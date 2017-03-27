// get an instance of mongoose and mongoose.Schema
var mongoose = require('mongoose');
var Schema = mongoose.Schema;

// set up a mongoose model and pass it using module.exports
module.exports = mongoose.model('FileMeta', new Schema({
    name: String,
    users: [ String ],
    instances: Number,
    hash: String,
    size: Number,
    type: String,
    added: Date
}));
