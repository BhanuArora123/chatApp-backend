const chats = require("../model/chatModel");

let socketIo = require("../utils/socket.js");

const user = require("../model/userModel");

const mediaModel = require("../model/MediaModel");

const path = require("path");

const fs = require("fs");

const crypto = require('crypto');

const headerSet = require("../utils/setRightHeader");

const mongoose = require("mongoose");

const { validationResult, header } = require("express-validator/check");

exports.SendMessage = async (req, res, next) => {
    let msg = req.body.msg;
    let email = req.body.recipientEmail;
    let errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(422).json({
            msg: errors.array()
        })
    }
    let userData = await user.findOne({ email: email })
    if (!userData) {
        return res.status(404).json({
            msg: "user not found"
        })
    }
    let mediaId;
    let mediaData;
    console.log(req.files)
    if (req.files.chatfile) {
        msg = req.files.chatfile[0].path;
        mediaData = new mediaModel({
            fileType:msg.split(".")[msg.split(".").length - 1],
            fileurl:msg,
            chatId:"dummyChat"
        });
        let result = await mediaData.save();
        mediaId = mediaData._id;
        userData.attachments.push({
            fileId:mediaId
        })
    }
    let chatType = req.files.chatfile == undefined ? "Text" : "File";
    let chatData = new chats({
        chatTime: new Date(Date.now()).toISOString(),
        sentTo: userData._id,
        sentBy: mongoose.Types.ObjectId(req.userId),
        chatContent: msg,
        chatType: chatType
    });
    chatData.save();
    userData.chats.push({
        chatId: chatData._id
    })
    userData.save();
    let myData = await user.findOne({ email: req.email });
    myData.chats.push({
        chatId: chatData._id
    })
    if(mediaId){
        myData.attachments.push({
            fileId:mediaId.toString()
        })
        mediaData.chatId = chatData._id.toString();
        mediaData.save();
    }
    myData.save();
    let ioObj = await socketIo.getIO();
    let hashed = await crypto.createHash('sha256').update(email).digest('hex');
    console.log(hashed);
    ioObj.to(hashed).emit("new_msg", {
        msg: "msg sent successfully",
        chat: msg,
        chatType: chatType,
        chatTime: chatData.chatTime,
        chatId: chatData._id.toString()
    })

    return res.status(201).json({
        msg: "msg sent successfully",
        chat: msg,
        chatType: chatType,
        chatTime: chatData.chatTime,
        chatId: chatData._id.toString()
    })
}
exports.DisplayMessages = async (req, res, next) => {
    let currentId = req.body.currentId;
    let otherId = req.userId;
    let messages = await chats.find({
        $or: [
            {
                sentBy: currentId,
                sentTo: otherId
            },
            {
                sentBy: otherId,
                sentTo: currentId
            }
        ]
    })
        .sort({
            chatTime: "1"
        });
    return res.status(200).json({
        msg: "messages displayed Successfully",
        chats: messages
    });
}
exports.downloadNow = (req, res, next) => {
    let chatId = req.body.chatId;
    chats.findById(chatId)
        .then((chatDoc) => {
            if (!chatDoc) {
                return res.status(404).json({
                    msg: "chat not found"
                })
            }
            if (chatDoc.sentTo.toString() != req.userId.toString() && chatDoc.sentBy.toString() != req.userId.toString()) {
                return res.status(401).json({
                    msg: "unauthorised"
                })
            }
            console.log(path.join(__dirname, "..", chatDoc.chatContent));
            let filename = "hello.png";
            let readStream = fs.createReadStream(path.join(__dirname, "..", chatDoc.chatContent));
            let chatArray = chatDoc.chatContent.split(".");
            let extension = chatArray[chatArray.length - 1];
            // headerSet(extension,res);
            res.setHeader("Content-Type", "multipart/formdata");
            res.setHeader("Content-Disposition", `inline; filename=${filename}`);
            readStream.on("open", () => {
                readStream.pipe(res);
            })
            // return res.download(path.join(__dirname,"..",chatDoc.chatContent),(err) => {
            //     console.log(err);
            // })
        })
}