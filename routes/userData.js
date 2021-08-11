const userController = require("../controller/userData");

const express = require("express");

const router = express.Router();

const isAuth = require("../utils/isAuth")

router.get("/profile",isAuth,userController.Profile);
router.get("/chats",isAuth,userController.Chats);
router.get("/groups",isAuth,userController.Groups);
router.get("/contacts",isAuth,userController.Contacts);
router.get("/settings",isAuth,userController.Settings);
router.get("/init",isAuth,userController.Contacts);
router.post("/editUser",isAuth,userController.editUser)
router.post("/searchChat",isAuth,userController.searchChat);
// router.post("/makeCall",isAuth,userController.makeCall);
module.exports = router;
// dbms,computer network,os,software engineering