const contact = require("../controller/contacts.js");
const express = require("express");

const { body } = require("express-validator/check")

const isAuth = require("../utils/isAuth");

const router = express.Router();

router.post("/addContact",[
    body("email")
    .isEmail()
    .withMessage("the email is not correct"),
    body("name")
    .isLength({min:3})
    .withMessage("the name must be atleast 3 characters long")
],isAuth,contact.addContact);

module.exports = router;