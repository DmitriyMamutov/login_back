const express = require("express");
const router = express.Router();

// mongodb user model
const User = require("./../models/User");

// mongodb user verification model
const UserVerification = require("./../models/UserVerification");

// mongodb password reset model
const PasswordReset = require("./../models/PasswordReset");

//email handler
const nodemailer = require("nodemailer");

//unique string
const { v4: uuidv4 } = require("uuid");

//env variables
require("dotenv").config();

//password handler
const bcrypt = require("bcrypt");

//path for static verified page
const path = require("path");

const { dirname } = require("path");

// nodemailer stuff
let transporter = nodemailer.createTransport({
  service: "hotmail",
  auth: {
    user: process.env.AUTH_EMAIL,
    pass: process.env.AUTH_PASS,
  },
});

//testing success
transporter.verify((error, success) => {
  if (error) {
    console.log(error);
  } else {
    console.log("Ready for messages");
    console.log(success);
  }
});

//signup
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
                verified: false,
              });

              newUser
                .save()
                .then((result) => {
                  //handle account verification
                  sendVerificationEmail(result, res);
                })
                .catch((err) => {
                  res.json({
                    status: "FAILED",
                    message: "An error occured saving user account",
                  });
                });
            })
            .catch((err) => {
              console.log(err);
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

//send verification email
sendVerificationEmail = ({ _id, email }, res) => {
  //url to be used in the email
  const currentUrl = "https://obscure-garden-97051.herokuapp.com/";

  const uniqueString = uuidv4() + _id;

  //mail options
  const mailOptions = {
    from: process.env.AUTH_EMAIL,
    to: email,
    subject: "Verify Your Email",
    html: `<p>Verify your email address to complete the signup and
    login into your account.</p><p>This link <b>expires in 6 hours.</b></p>
    <p>Press <a href=${currentUrl + "user/verify/" + _id + "/" + uniqueString}>here</a>
     to proceed.</p>`,
  };

  //hash a unique string
  const saltRounds = 10;
  bcrypt
    .hash(uniqueString, saltRounds)
    .then((hashedUniqueString) => {
      const newVerification = new UserVerification({
        userId: _id,
        uniqueString: hashedUniqueString,
        createdAt: Date.now(),
        expiresAt: Date.now() + 21600000,
      });

      newVerification
        .save()
        .then(() => {
          transporter
            .sendMail(mailOptions)
            .then(() => {
              //email sent and verification record saved
              res.json({
                status: "PENDING",
                message: "Verification email sent",
              });
            })
            .catch((error) => {
              console.log(error);
              res.json({
                status: "FAILED",
                message: "Verification Email failed",
              });
            });
        })
        .catch((error) => {
          console.log(error);
          res.json({
            status: "FAILED",
            message: "Couldn't save verification email data!",
          });
        });
    })
    .catch(() => {
      res.json({
        status: "FAILED",
        message: "An error occured while hashing email data!",
      });
    });
};

// verify email
router.get("/verify/:userId/:uniqueString", (req, res) => {
  let { userId, uniqueString } = req.params;

  UserVerification.find({ userId })
    .then((result) => {
      if (result.length > 0) {
        //user verification record exist so we proceed
        const { expiresAt } = result[0];
        const hashedUniqueString = result[0].uniqueString;

        //checking for expired unique string
        if (expiresAt < Date.now()) {
          //record has expired so we delete it
          UserVerification.deleteOne({ userId })
            .then((result) => {
              User.deleteOne({ _id: userId })
                .then(() => {
                  let message = "Link has expired. Please sign up again.";
                  res.redirect(`/user/verified/error=true&message=${message}`);
                })
                .catch((error) => {
                  console.log(error);

                  let message = "Clearing user with expired unique string failed";
                  res.redirect(`/user/verified/error=true&message=${message}`);
                });
            })
            .catch((error) => {
              console.log(error);

              let message = "An error occured while clearing expired user verification record";
              res.redirect(`/user/verified/error=true&message=${message}`);
            });
        } else {
          //valid record exists so we validate the user string

          //First compare the hashed unique string

          bcrypt
            .compare(uniqueString, hashedUniqueString)
            .then((result) => {
              if (result) {
                //strings match

                User.updateOne({ _id: userId }, { verified: true })
                  .then(() => {
                    UserVerification.deleteOne({ userId })
                      .then(() => {
                        res.sendFile(path.join(__dirname, "./../views/verified.html"));
                      })
                      .catch((error) => {
                        console.log(error);

                        let message = "An error occured while finalizing sucessfull verification.";
                        res.redirect(`/user/verified/error=true&message=${message}`);
                      });
                  })
                  .catch((error) => {
                    console.log(error);

                    let message = "An error occured while updating user record to show verified.";
                    res.redirect(`/user/verified/error=true&message=${message}`);
                  });
              } else {
                // existing record but incorrect verification details passed.

                let message = "Invalid verification details passed. Check your inbox.";
                res.redirect(`/user/verified/error=true&message=${message}`);
              }
            })
            .catch((error) => {
              let message = "An error occured while comparing unique strings.";
              res.redirect(`/user/verified/error=true&message=${message}`);
            });
        }
      } else {
        //user verification record doesn't exist
        let message =
          "Account record doesn't exist or has been verified already. Please sign up or login.";
        res.redirect(`/user/verified/error=true&message=${message}`);
      }
    })
    .catch((error) => {
      console.log(error);
      let message = "An error occured while checking for existing user verification record";
      res.redirect(`/user/verified/error=true&message=${message}`);
    });
});

//verified page router
router.get("/verified", (req, res) => {
  res.sendFile(path.join(__dirname, "./../views/verified.html"));
});

//signin
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
          // check if user in verified

          if (!data[0].verified) {
            res.json({
              status: "FAILED",
              message: "Email hasn't been verified yet. Check your inbox.",
            });
          } else {
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
          }
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

// Password reset stuff
router.post("/requestPasswordReset", (req, res) => {
  const { email, redirectUrl } = req.body;

  User.find({ email })
    .then((data) => {
      if (data.length) {
        //user exists

        //check if user is verified
        if (!data[0].verified) {
          res.json({
            status: "FAILED",
            message: "Email hasn't been verified yet. Check your inbox.",
          });
        } else {
          //proceed with email to reset password
          sendResetEmail(data[0], redirectUrl, res);
        }
      } else {
        res.json({
          status: "FAILED",
          message: "An error occured whle checking for existing user",
        });
      }
    })
    .catch((error) => {
      console.log(error);

      res.json({
        status: "FAILED",
        message: "An error occured whle checking for existing user",
      });
    });
});

// send password reset Email
const sendResetEmail = ({ _id, email }, redirectUrl, res) => {
  const resetString = uuidv4() + _id;

  //first, we clear all existing reset records
  PasswordReset.deleteMany({ userId: _id })
    .then((result) => {
      //reset records deleted successfully
      //Now we send the mail

      //mail options
      const mailOptions = {
        from: process.env.AUTH_EMAIL,
        to: email,
        subject: "Password reset",
        html: `<p>We heard that you lost the password.</p>
      <p>Don't worry, use the link below to reset it. </p>
      <p>This link <b>expires in 60 minutes.</b></p>
      <p>Press <a href=${redirectUrl + "/" + _id + "/" + resetString}>here</a>
       to proceed.</p>`,
      };

      //hash the reset string
      const saltRounds = 10;

      bcrypt
        .hash(resetString, saltRounds)
        .then((hashedResetString) => {
          //set values in password reset collection

          const newPasswordReset = new PasswordReset({
            userId: _id,
            resetString: hashedResetString,
            createdAt: Date.now(),
            expiresAt: Date.now() + 3600000,
          });

          newPasswordReset
            .save()
            .then(() => {
              transporter
                .sendMail(mailOptions)
                .then(() => {
                  //reset email sent and password reset record saved
                  res.json({
                    status: "PENDING",
                    message: "Password reset email sent",
                  });
                })
                .catch((error) => {
                  console.log(error);

                  res.json({
                    status: "FAILED",
                    message: "Password reset email failed",
                  });
                });
            })
            .catch((error) => {
              console.log(error);

              res.json({
                status: "FAILED",
                message: "Couldn't save password reset data!",
              });
            });
        })
        .catch((error) => {
          console.log(error);

          res.json({
            status: "FAILED",
            message: "An error occurred while hashing he password reset data!",
          });
        });
    })
    .catch((error) => {
      //error while clearing existing records
      console.log(error);

      res.json({
        status: "FAILED",
        message: "Clearing existing password reset records failed",
      });
    });
};

//Actually reset the password
router.post("/resetPassword", (req, res) => {
  let { userId, resetString, newPassword } = req.body;

  PasswordReset.find({ userId })
    .then((result) => {
      if (result.length > 0) {
        //process reset record exists so we proceed

        const { expiresAt } = result[0];

        const hashedResetString = result[0].resetString;

        //checking for expired reset string
        if (expiresAt < Date.now()) {
          PasswordReset.deleteOne({ userId })
            .then(() => {
              // Reset record deleted successfully
              res.json({
                status: "FAILED",
                message: "Clearing password reset record failed.",
              });
            })
            .catch((error) => {
              //deletion failed
              console.log(error);

              res.json({
                status: "FAILED",
                message: "Clearing password reset record failed.",
              });
            });
        } else {
          //valid reset record exists so we validate the reset string
          //first compare the hashed reset string
          bcrypt
            .compare(resetString, hashedResetString)
            .then((result) => {
              if (result) {
                //strings matched
                //hash password again

                const saltRounds = 10;

                bcrypt
                  .hash(newPassword, saltRounds)
                  .then((hashedNewPassword) => {
                    //update user password

                    User.updateOne({ _id: userId }, { password: hashedNewPassword })
                      .then(() => {
                        //update complete. Now delete reset record

                        PasswordReset.deleteOne({ userId })
                          .then(()=>{
                            //both user record and reset record updated
                            res.json({
                              status: "SUCCESS",
                              message: "Password has been reset succesfully.",
                            });
                          })
                          .catch((error) => {
                            console.log(error);

                            res.json({
                              status: "FAILED",
                              message: "An error occured while finalizing password reset.",
                            });
                          });
                      })
                      .catch((error) => {
                        console.log(error);

                        res.json({
                          status: "FAILED",
                          message: "Updating user password failed.",
                        });
                      });
                  })
                  .catch((error) => {
                    console.log(error);

                    res.json({
                      status: "FAILED",
                      message: "An error occured while hashing new password.",
                    });
                  });
              } else {
                //existing record but incorrect reset string passed
                res.json({
                  status: "FAILED",
                  message: "Invalid password reset details passed.",
                });
              }
            })
            .catch((error) => {
              console.log(error);

              res.json({
                status: "FAILED",
                message: "Comparing password reset strings failed.",
              });
            });
        }
      } else {
        //password reset record doesn't exist
        res.json({
          status: "FAILED",
          message: "Password reset request not found.",
        });
      }
    })
    .catch((error) => {
      console.log(error);

      res.json({
        status: "FAILED",
        message: "Checking for existing password.",
      });
    });
});

module.exports = router;
