const groupController = require("../controller/groups.js");

const { body } = require("express-validator/check");

const express = require("express");

const isAuth = require("../utils/isAuth");

const router = express.Router();

router.post("/createGroup",[
    body("groupName").isLength({
        min:3
    }).withMessage("the group name must be of length atleast 3"),
    body("members")
    .isLength({min:1})
    .withMessage("the group must have at least 1 member")
],isAuth,groupController.addGroup);
router.post("/sendGrpMessage",[
    body("groupName").isLength({
        min:3
    }).withMessage("the group name must be of length atleast 3"),
    body("creatorId").not().isEmpty()
    .withMessage("creator Id must be provided")
],isAuth,groupController.sendGrpMessage);
router.post("/displayGrpMessages",isAuth,groupController.displayMsg);

router.post("/searchGrp",isAuth,groupController.searchGrp)
module.exports = router;