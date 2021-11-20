const AWS = require('aws-sdk');
const User = require('../models/user');
const Link = require('../models/link');
const jwt = require("jsonwebtoken");
const {registerEmailParams, forgotPasswordEmailParams} = require("../helpers/email");
const { nanoid } = require('nanoid');
const expressJwt = require('express-jwt');
const _ = require('lodash');

AWS.config.update({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION
});

const ses = new AWS.SES({apiVersion: "2010-12-01"});

exports.register = (req, res)=>{
    // console.log("REGISTER CONTROLLER ", req.body);
    const { name, email, password, categories } = req.body;
    // check if user exists in our db
    User.findOne({email}).exec((err, user) =>{
        if(user){
            res.status(400).json({
                error: 'Email is taken'
            })
        }
        // generate token with user name, email and password
        const token = jwt.sign({ name, email, password, categories }, process.env.JWT_ACCOUNT_ACTIVATION,{
            expiresIn: '60m'
        });

        // send email
        const params = registerEmailParams(email, token);

        const sendEmailOnRegister = ses.sendEmail(params).promise()

        sendEmailOnRegister
            .then(data => {
                console.log("email submitted SES ", data);
                res.json({
                    message: `Email has been sent to ${email}, Follow the instructions to complete your registration`
                });
            })
            .catch(error => {
                console.log("ses email on register ", error);
                res.json({
                    message: `We could not verify your email. Please try again`
                })
            })
    })
};

exports.registerActivate = (req, res) => {
    const {token} = req.body;
    // console.log(token)
    jwt.verify(token, process.env.JWT_ACCOUNT_ACTIVATION, function (err, decode){
        if(err){
            return res.status(401).json({
                error: 'Expired link. Try again'
            });
        }
        const {name, email, password, categories} = jwt.decode(token);
        const username = nanoid();

        User.findOne({email}).exec((err, user) => {
            if(user){
                res.status(401).json({
                    error: 'Email is taken'
                });
            }
            // register new user
            let newUser = new User({username, name, email, password, categories});
            newUser.save((err, result) => {
                if(err){
                    return res.status(401).json({
                        error: 'Error saving user in database. Try later.'
                    });
                }
                return res.status(401).json({
                    message: 'Registration success. Please login.'
                });
            });
        });
    });
}

exports.login = (req, res) => {
    const {email, password} = req.body;
    // console.table({email, password})
    User.findOne({email}).exec((err, user) => {
        if(err || !user) {
            return res.status(400).json({
                error: "User with that email does not exist. Please register."
            });
        }
        // authenticate
        if(!user.authenticate(password)) {
            return res.status(400).json({
                error: "Email and Password does not match."
            });
        }
        // generate token and send to client
        const token = jwt.sign({_id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'})
        const {_id, name, email, role} = user;

        return res.json({
            token,
            user: {_id, name, email, role}
        });
    })
}

// User Profile
exports.requireSignin = expressJwt({secret: process.env.JWT_SECRET, algorithms: ['HS256']});

exports.authMiddleware = (req, res, next) => {
    const authUserId = req.user._id;
    // console.log("authUserId", authUserId)
    User.findOne({authUserId}).exec((err, user) => {
        if(err || !user) {
            res.status(400).json({
                error: "User not found"
            });
        }
        // console.log("user>> ", user)
        req.profile = user;
        next();
    })
}

exports.adminMiddleware = (req, res, next) => {
    const adminUserId = req.user._id;
    User.findOne({adminUserId}).exec((err, user) => {
        if(err || !user) {
            return res.status(400).json({
                error: "User not found"
            });
        }

        if(user.role !== 'admin') {
            return res.status(400).json({
                error: "Admin resource. Access denied"
            });
        }

        req.profile = user;
        next();
    })
}

// Forgot Password
exports.forgotPassword = (req, res) => {
    const {email} = req.body;

    User.findOne({email}).exec((err, user) => {
        if(err || !user) {
            return res.status(400).json({
                error: "User with that email doesn't exist"
            });
        }
        // generate token and email to user
        const token = jwt.sign({name: user.name}, process.env.JWT_RESET_PASSWORD, 
                {expiresIn:'10m'}
            );
        // send email
        const params = forgotPasswordEmailParams(email, token);

        // populate the db > user > resetPasswordLink
        return User.updateOne({resetPasswordLink: token}).exec((err, success) => {
            if(err) {
                return res.json({
                    error: "Password reset failed. Try later."
                });
            }
            const sendEmailForgotPassword = ses.sendEmail(params).promise();
            sendEmailForgotPassword
            .then(data => {
                console.log("ses reset pw success ", data);
                return res.json({
                    message: `Email has been sent to ${email}. Click on the link to reset your password.`
                })
            })
            .catch(error => {
                console.log("ses reset pw failed ", error);
                return res.json({
                    message: `We could not verify your email. Try later.`
                })
            })
        })
    })
}

// Reset Password
exports.resetPassword = (req, res) => {
    const {resetPasswordLink, newPassword} = req.body;

    // verify token
    jwt.verify(resetPasswordLink, process.env.JWT_RESET_PASSWORD, (err, success) => {
        if(err) {
            return res.status(400).json({
                error: "Expired Link. Try again."
            });
        }

        User.findOne({resetPasswordLink}).exec((err, user) => {
            if(err || !user) {
                return res.status(400).json({
                    error: "Invalid token. Try again."
                });
            }

            const updateFields = {
                password: newPassword,
                resetPasswordLink: ''
            }

            user = _.extend(user, updateFields);

            user.save((err, result) => {
                if(err) {
                    return res.status(400).json({
                        error: "Password reset failed. Try again."
                    });
                }
                
                res.json({
                    message: `Great! Now you can login with your new password.`
                });
            })
        })
    })
}


exports.canUpdateDeleteLink = (req, res, next) => {
    const { id } = req.params;
    Link.findOne({ _id: id }).exec((err, data) => {
        if (err) {
            return res.status(400).json({
                error: 'Could not find link'
            });
        }
        let authorizedUser = data.postedBy._id.toString() === req.user._id.toString();
        if (!authorizedUser) {
            return res.status(400).json({
                error: 'You are not authorized'
            });
        }
        next();
    });
};