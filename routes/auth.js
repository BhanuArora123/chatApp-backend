const authController = require("../controller/auth.js");
const express = require("express");

const user = require("../model/userModel");

const { body } = require("express-validator/check");

const router = express.Router();


router.put("/signup",[
    body("email")
    .isEmail()
    .withMessage("the email is not correct")
    .custom((value,{ req }) => {
        return user.findOne({email:value})
        .then((userData) => {
            if(userData){
                return Promise.reject("the email already exists");
            }
        })
    }),
    body("password")
    .isLength({min:6})
    .withMessage("the password must be atleast 6 characters long"),
    body("name")
    .isLength({min:3})
    .withMessage("the name must be atleast 3 characters long")
],authController.signup);

router.post("/login",[
    body("email")
    .isEmail()
    .withMessage("the email is not correct")
],authController.loginHandler);

module.exports = router;