require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
// const encrypt = require('mongoose-encryption');
// const md5 = require('md5');
// const bcrypt = require('bcrypt');
// const saltRounds = 10;
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');

//function find or createStrategy
const findOrCreate = require('mongoose-findorcreate')

//Signin goole
const GoogleStrategy = require('passport-google-oauth20').Strategy;

//Signin Facebook
const FacebookStrategy = require('passport-facebook').Strategy;
const app = express();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

app.use(session({
  secret: 'Our little secret.',
  resave: false,
  saveUninitialized: false
}))

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: false})
mongoose.set('useCreateIndex', true);


const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  googleId: String,
  facebookId: String,
  secrets: String
});

// hash and salt the passport to save user into mongodb
userSchema.plugin(passportLocalMongoose);


userSchema.plugin(findOrCreate);

// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });


const User = new mongoose.model("User", userSchema);

// create local login straitgy
// to authenticate user to use email and passport
passport.use(User.createStrategy());

/*only using session*/


// create cookie and user idenfication to the the cookie
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

//check who is this user
passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRETS,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    uerProfileURL: "https://www.googleapis.com/oath2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRETS,
    callbackURL: "http://localhost:3000/auth/facebook/secrets",
    enableProof: true
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res) {
  res.render("home")
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

app.get('/auth/facebook',
  passport.authenticate('facebook', { scope: ['email'] }));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('secrets/');
  });

app.get("/login", function(req, res) {
  res.render("login")
});

app.get("/register", function(req, res) {
  res.render("register")
});

app.get("/secrets", function(req, res) {
  // if (req.isAuthenticated()) {
  //   res.render("secrets");
  // } else {
  //   res.redirect('/login');
  // }
  User.find({"secrets": {$ne:null}}, function(err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        res.render("secrets", {usersWithSecrets: foundUser});
      }
    }
  })
});

app.get("/logout", function(req, res) {
  req.logout();
  res.redirect("/");
});

app.get('/submit', function(req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect('/login');
  }
});

app.post('/submit', function(req, res) {
  const submittedSecret = req.body.secret;
  User.findById(req.user.id, function(err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secrets = submittedSecret;
        foundUser.save(function() {
          res.redirect("/secrets")
        })
      }
    }
  })
})
app.post("/register", function(req, res) {

  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //      // Store hash in your password DB.
  //      const newUser = new User(
  //        {
  //          email: req.body.username,
  //          // password: md5(req.body.password)
  //          password: hash
  //        }
  //      );
  //      newUser.save(function(err) {
  //        if (err) {
  //          console.log(err);
  //        } else {
  //          res.render('secrets');
  //
  //        }
  //      });
  //  });

  User.register({username: req.body.username}, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  })

});

app.post("/login", function(req, res) {
  // const username = req.body.username;
  // const password = req.body.password;
  // // const password = md5(req.body.password);
  //
  // User.findOne({email: username}, function(err, foundUser) {
  //   if (err) {
  //     console.log(err);
  //   } else {
  //     if (foundUser) {
  //       // if (results.password == password) {
  //       //   res.render("secrets");
  //       //
  //       // }
  //       bcrypt.compare(password, foundUser.password, function(err, result) {
  //   // result == true
  //         if (result == true) {
  //           res.render("secrets");
  //           console.log("true");
  //         }
  //       });
  //     }
  //   }
  // });

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  console.log(user.username, user.password);
  req.login(user, function(err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  })

});


app.listen(3000, function() {
  console.log("Server started on port 3000");
});
