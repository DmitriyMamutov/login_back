const express = require("express");
const router = express.Router();

const User = require("./../models/User");

//passport handler
const bcrypt = require("bcrypt");

///signup
router.post("/signup", (req, res) => {
  let { name, email, password } = req.body;
  name = name.trim();
  email = email.trim();
  password = password.trim();

  if (name == "" || email == "" || password == "") {
    res.json({
      status: "FAILED",
      message: "empty input fields",
    });
  } else if (!/^[a-zA-Z ]*$/.test(name)) {
    res.json({
      status: "FAILED",
      message: "Invalid name entered",
    });
  } else if (!/^[\w-\.]+@([\w-]+\.)+[\w]{2,4}$/.test(email)) {
    res.json({
      status: "FAILED",
      message: "Invalid email entered",
    });
  } else if (password.length < 8) {
    res.json({
      status: "FAILED",
      message: "password is too short",
    });
  } else {
    //checking if user already exist
    User.find({ email })
      .then((result) => {
        if (result.length) {
          res.json({
            status: "FAILED",
            message: "User with provided email aleady exist",
          });
        } else {
          //try to create new user

          //password handling
          const saltRounds = 10;
          bcrypt
            .hash(password, saltRounds)
            .then((hashedPassword) => {
              const newUser = new User({
                name,
                email,
                password: hashedPassword,
              });

              newUser
                .save()
                .then((result) => {
                  res.json({
                    status: "SUCCESS",
                    message: "Sign Up success",
                    data: result,
                  });
                })
                .catch((err) => {
                  res.json({
                    status: "FAILED",
                    message: "An error occured saving user account",
                  });
                });
            })
            .catch((err) => {
              res.json({
                status: "FAILED",
                message: "An error occured while hashing password",
              });
            });
        }
      })
      .catch((err) => {
        console.log(err);
        res.json({
          status: "FAILED",
          message: "An error occured while checking for existing user",
        });
      });
  }
});

router.post("/signin", (req, res) => {
  let { email, password } = req.body;
  email = email.trim();
  password = password.trim();

  if (email == "" || password == "") {
    res.json({
      status: "FAILED",
      message: "empty credentials supplied",
    });
  } else {
    User.find({ email })
      .then((data) => {
        if (data.length) {
          //user exist
          const hashedPassword = data[0].password;
          bcrypt
            .compare(password, hashedPassword)
            .then((result) => {
              if (result) {
                res.json({
                  status: "SUCCESS",
                  message: "Signin successful",
                  data: data,
                });
              } else {
                res.json({
                  status: "FAILED",
                  message: "INVALID PASSWORD ENTERED",
                });
              }
            })
            .catch((err) => {
              res.json({
                status: "FAILED",
                message: "An error occurred while compired",
              });
            });
        } else {
          res.json({
            status: "FAILED",
            message: "Invalid credentials entered",
          });
        }
      })
      .catch((err) => {
        res.json({
          status: "FAILED",
          message: "An error occured whle checking for existing user",
        });
      });
  }
});

module.exports = router;
