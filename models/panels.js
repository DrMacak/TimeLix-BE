// get an instance of mongoose and mongoose.Schema
var mongoose = require('mongoose');
var Schema = mongoose.Schema;

// set up a mongoose model and pass it using module.exports
module.exports = mongoose.model('Panel', new Schema({
    owner: String,
    uuid: String,
    type: String,
    options: String, // Strigyfied options of panel
    added: Date
}));
