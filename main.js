var express = require('express');
var app = express();
var router = express.Router();

var path = require('path');
var fs = require('fs');

var formidable = require('formidable');

var crypto = require('crypto');
var security = require('./security');

var jwt    = require('jsonwebtoken'); // used to create, sign, and verify tokens

var config   = require('./config'); // get our config file

var mongoose = require('mongoose');

var User     = require('./models/user'); // get our mongoose model
var File     = require('./models/meta');
var Panels   = require('./models/panels');
var Segments = require('./models/segments');

// var MongoClient = require('mongodb').MongoClient;
// var assert = require('assert');
// var ObjectId = require('mongodb').ObjectID;

// const url = 'mongodb://localhost:27017/test';


mongoose.connect(config.database);

var bodyParser = require('body-parser');

app.use( bodyParser.json() );

// CORS enabled
app.use(function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
  res.header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE, PUT");


  // intercepts OPTIONS method
  if ('OPTIONS' === req.method) {
    //respond with 200
    res.sendStatus(200);
    res.end();
  }
  else {
  //move on
    next();
  }
  // next();
});

// basic response
app.get('/', function(req, res){
  res.end('Timelix BackEND');
});

// Serving uploaded Files
app.get('/uploads/:fileName', function(req, res){
	  	res.sendFile( path.join(__dirname, 'uploads/' + req.params.fileName) );
});

// Login
app.post('/login', function( req, res ){

  console.log("Login called");

  const userName = req.body.name;
  const password = req.body.pwd;
  const now = new Date();

  // Login data recieved check if the username is in DB
  User.findOne({
    name: req.body.name
    }, function(err, user) {

      if (err) throw err;

      // If user is not found create new one
      if (!user) {
        return res.status(401).send({
          success: false,
        });
      }

      // Check is password is valid
      if ( !security.isPasswordOK( password, user.password ) ) {
        return res.status(401).send({
          success: false,
        });
      }

      // If pwd is valid provide token.
      const token = jwt.sign( { username: user.name }, config.secret, {
        algorithm: config.tokenCrypto,
        expiresIn: "1d" // expires in 24 hours
      });

      res.json({ success: true, token });

    });

});

app.post('/createUser', function(req, res){

  console.log("Create user called");

  const userName = req.body.name;

  const now = new Date();

  User.findOne({
    name: req.body.name
    }, function(err, user) {

      if (err) throw err;

      // check if the username is not alrady taken 409
      if ( user ) {
        return res.status(409).send({
          success: false,
          data: { success: false, message: "Username already taken." }
        });

      }

      // If user is not found create new one
      const newUser = new User({
        name: req.body.user,
        password: security.hashedPassword( req.body.pwd ),
        lastLogin: now,
        admin: false
      });

      // save the sample user
      newUser.save( function(err) {

        if ( err ) throw err;

        // console.log('User '+ req.body.name +' saved successfully to DB');

        var token = jwt.sign( { username: newUser.name }, config.secret, {
          expiresIn: "1d" // expires in 24 hours
        });

        res.json({ success: true, token });

      });
  });
});


//////////////////////////////////////////////////////////////////
// API - Login protected part
//
///////////////////////////////////////////////////////////////////

app.use('/api', router);

// route middleware to verify a token JWT

router.use( function( req, res, next ) {

  // check header or url parameters or post parameters for token
  var token = req.headers['authorization'];

  // decode token
  if ( !token ) {
    // if there is no token
    return res.status(401).send({ success: false, message: 'No token provided.' });
  }

  // verifies secret and checks hash. Also checks for correct crypto
  jwt.verify( token, config.secret, { algorithms: [config.tokenCrypto] }, function( err, decoded ) {

    if ( err ) {
      return res.json({ success: false, message: 'Failed to authenticate token.' });
    }

    // if everything is good, save to request for use in other routes
    req.decoded = decoded;

    console.log( "Token valid ");

    next();
  });

});

// UPLOADING FILE
// Upload file
router.post('/uploads', function(req, res){

  // create an incoming form object
  var form = new formidable.IncomingForm();
  var fileName = "";
  const userName = req.decoded.username;

  // specify that we want to allow the user to upload multiple files in a single request
  form.multiples = true;

  // store all uploads in the /uploads directory
  form.uploadDir = path.join(__dirname, '/uploads');

  // every time a file has been uploaded successfully,
  form.on('file', function(field, file) {

    const fileType = file.name.substr(file.name.indexOf("."));


    //md5 to avoid duplicating files. Not sec so md5 is enought?
    var hash = crypto.createHash('md5'),
    stream = fs.createReadStream( file.path );

    stream.on('data', function (data) {
      hash.update(data, 'utf8');
    })

    stream.on('end', function () {

      var fileHash = hash.digest('hex');

      File.findOne({
        hash: fileHash
      }, function( err, fileDB ) {

          if ( err ) throw err;

          // If file already uploaded. just update record in DB
          if ( fileDB ) {

            fileDB.instances += 1;

            // If the user is already in users.
            if ( fileDB.users.indexOf( userName ) >= 0 ) {

              fileDB.save(function (err, updatedFile) {

                if ( err ) throw err;

                res.json({
                  success : true,
                  message : fileHash + fileType
                });

              });
              return;
            }

            fileDB.users.push( userName );

            fileDB.save(function (err, updatedFile) {

              if ( err ) throw err;

              res.json({
                success : true,
                message : fileHash + fileType
              });

            });

            return;
          }

          // If file is not uploaded yet. Create record in DB
          if ( !fileDB ) {
            var now = new Date();

            const newFile = new File({
              name: file.name,
              users: [ userName ],
              instances: 1,
              hash: fileHash,
              size: file.size,
              type: file.type,
              added: now
            });

            newFile.save( function(err) { if ( err ) throw err; });

            fs.rename( file.path, path.join( form.uploadDir, fileHash + fileType ) );

            res.json({
              success : true,
              message : fileHash + fileType
            });

            return;
          }

        });

    })
  });

  // log any errors that occur
  form.on('error', function(err) {
    console.log('An error has occured: \n' + err);
  });

  // once all the files have been uploaded, send a response to the client
  form.on('end', function() {
    // res.end(fileName);
  });

  // parse the incoming request containing the form data
  form.parse(req);

});

// REMOVING FILE
// TBD When removing file I have to check if it is not used by someone or other panel else!
router.delete('/uploads/:fileName', function(req, res){

	const fileName = req.params.fileName;
  const userName = req.decoded.username;
  // console.log( hash, file, userName);
  const hash = fileName.substr ( 0 , fileName.indexOf(".") );


  File.findOne({
    hash: hash
  }, function(err, fileMeta) {

      if ( err ) throw err;

      // File not find
      if ( !fileMeta ) {
        res.json({ success : true, message : "Removed file is not in DB. WTF is going on, man?" });
        return;
      };

      // More users owns this file.
      if ( fileMeta.users.length > 1) {

        const userPostion = fileMeta.users.indexOf( userName );

        if ( userPostion < 0 ) {
          res.json({ success : false, message : "User is not associated with this file???" });
          return;
        }

        fileMeta.users.splice( userPostion, 1);

        fileMeta.instances--;

        fileMeta.save( function (err, updatedFile) {

          if ( err ) throw err;

          res.json({
            success : true,
            message : "successfully deleted " + hash
          });

        });

        return;
      }

      // Just one user owns this one file.
      if ( fileMeta.users.length == 1) {

        // Maybe there is same file used by one user more times. Just decrease number of instances. Dont delete physically.
        if ( fileMeta.instances > 1 ) {

          fileMeta.instances--;

          fileMeta.save( function (err, updatedFile) {

            if ( err ) throw err;

            res.json({
              success : true,
              message : "successfully deleted " + hash
            });

          });

          return;
        }

        fileMeta.remove( function( err, removed ) {
          if ( err ) throw err;
        });

        fs.unlink( path.join(__dirname, 'uploads/' + fileName), function ( err ) {

          if ( err ) {
            return res.json({ success: false, message: 'Operation failed.' });
            return;
          }

          console.log('successfully deleted uploads/' + fileName);

          res.json({ success : true, message : 'successfully deleted uploads/' + fileName });
        });
      }
  });

});

// Saving userdata. body should contain helix or segments or panels to save

router.post('/userdata', function(req, res){

  const helix = req.body.helix;
  const segments = req.body.segments;
  const panels = req.body.panels;

  const now = new Date();

  if ( !( helix || segments || panels ) ) {
    return res.json({ success: false, message: 'Data not found in request' });
    return;
  }

  for ( var i=0, len = segments.length; i < len; i++ ) {

    const newSeg = new Segments({
      owner: req.decoded.username,
      uuid: req.body.segments[i]["uuid"],
      type: "segment",
      options: req.body.segments[i]["o"], // Strigyfied options of panel
      added: now
    });

    newSeg.save( function(err) { if ( err ) throw err; });

  }

  for ( var i=0, len = panels.length; i < len; i++ ) {

    const newPanel = new Panels({
      owner: req.decoded.username,
      uuid: req.body.panels[i]["uuid"],
      type: "panel",
      options: req.body.panels[i]["o"], // Strigyfied options of panel
      added: now
    });

    newPanel.save( function(err) { if ( err ) throw err; });

  }

  for ( var i=0, len = helix.length; i < len; i++ ) {

    const newHelix = new Helix({
      owner: req.decoded.username,
      uuid: req.body.helix[i]["uuid"],
      type: "helix",
      options: req.body.helix[i]["o"], // Strigyfied options of panel
      added: now
    });

    newHelix.save( function(err) { if ( err ) throw err; });

  }

  return res.json({ success: true, message: 'Data saved' });
  return;

});


router.get('/userdata/:type', function(req, res){

  const type = req.params.type;
  const userName = req.decoded.username;

  var response = {};

  Helix.find( { owner : userName },
    function(err, helix) {
      if ( err ) throw err;
      response.helix = helix;
    }
  );

  Segments.find( { owner : userName },
    function(err, segments) {
      if ( err ) throw err;
      response.segments = segments;
    }
  );

  Panels.find( { owner : userName },
    function(err, panels) {
      if ( err ) throw err;
      response.panels = panels;
    }
  );

  return res.json({ success: true, message: response });
  return;

});

var server = app.listen(80, function(){
  console.log('Server listening on port 80');
});
