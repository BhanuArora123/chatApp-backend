const messageController = require("../controller/messages");

const express = require("express");

const isAuth = require("../utils/isAuth");

const router = express.Router();

router.post("/sendMessage",isAuth,messageController.SendMessage);

router.post("/displayMessages",isAuth,messageController.DisplayMessages);

router.post("/downloadNow",isAuth,messageController.downloadNow)

module.exports = router;