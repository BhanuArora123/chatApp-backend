const groups = require("../model/groupsModels");

const { validationResult } = require("express-validator/check");

const mongoose = require("mongoose");

const crypto = require("crypto");

const socketIo = require("../utils/socket");

const chats = require("../model/chatModel");

const media = require("../model/MediaModel");

const _filePath = import("../utils/temp.mjs");

const user = require("../model/userModel");

exports.addGroup = async (req, res, next) => {
    let groupName = req.body.groupName;
    let members = JSON.parse(req.body.members).map((member) => {
        member.memberId = mongoose.Types.ObjectId(member.memberId);
        return member;
    });
    let groupIcon = req.body.groupIcon;
    let errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(422).json({
            msg: errors.array()
        })
    }

    let userData = await user.findOne({
        email: req.email
    });
    if (!userData) {
        return res.status(404).json({
            msg: "user not found , can't create group"
        });
    }
    // checking if the group already exists,
    let aboutGroup = await groups.findOne({ creatorId: userData._id, groupName: groupName });
    if (aboutGroup) {
        return res.status(409).json({
            msg: "this group already exist with a similar group name and creator"
        })
    }
    console.log(req.files);
    if (req.files.groupIcon) {
        let mod = await _filePath;
        groupIcon = await mod.posixPath("https://chatappbackend12345.herokuapp.com/" + req.files.groupIcon[0].path)
    }
    if (!groupIcon) {
        groupIcon = `https://chatappbackend12345.herokuapp.com//images/custom.jpg`
    }
    console.log(groupName)
    let groupData = new groups({
        groupName: groupName,
        members: members,
        groupIcon: groupIcon,
        creatorId: userData._id
    });
    let result = await groupData.save();
    if (!result) {
        return res.status(400).json({
            msg: "database validation failed"
        })
    }
    // adding groups to all the members of it
    members.forEach(element => {
        user.findById(element.memberId)
            .then((userDoc) => {
                userDoc.groups.push({
                    groupId: groupData._id
                })
                userDoc.save();
            })
    });
    userData.groups.push({
        groupId: groupData._id
    })
    userData.save();
    return res.status(201).json({
        msg: "group created successfully",
        groupDoc: groupData
    });
}

exports.sendGrpMessage = async (req, res, next) => {
    let msg = req.body.msg;
    let creatorId = req.body.creatorId;
    let groupName = req.body.groupName;
    let email = req.email;
    let error = validationResult(req);
    if (!error.isEmpty()) {
        return res.status(422).json({
            msg: error.array()
        })
    }
    let groupData = await groups.findOne({
        creatorId: mongoose.Types.ObjectId(creatorId),
        groupName: groupName
    }).populate("members.memberId")
    if (!groupData) {
        return res.status(404).json({
            msg: "group Not Found"
        });
    }
    let userData = await user.findById(req.userId);
    if (!userData) {
        return res.status(404).json({
            msg: "user does not exist"
        })
    }
    let name = userData.name;
    let memberIndex = groupData.members.findIndex((member) => {
        if (member.memberId._id.toString() == req.userId.toString()) {
            return member;
        }
    })
    if (memberIndex == -1 && req.userId.toString() != creatorId.toString()) {
        return res.status(401).json({
            msg: "unauthorised"
        })
    }
    let chatData;
    if (req.files.chatfile) {
        let mod = await _filePath;
        msg = await mod.posixPath(req.files.chatfile[0].path)
        chatData = new chats({
            chatTime: new Date(Date.now()).toISOString(),
            sentTo: mongoose.Types.ObjectId(groupData._id),
            sentBy: mongoose.Types.ObjectId(req.userId),
            chatContent: msg,
            chatType: req.files.chatfile != undefined ? "File" : "Text",
            name: name,
            email: email
        })
        await chatData.save();
    }
    else {
        chatData = new chats({
            chatTime: new Date(Date.now()).toISOString(),
            sentTo: mongoose.Types.ObjectId(groupData._id),
            sentBy: mongoose.Types.ObjectId(req.userId),
            chatContent: msg,
            chatType: req.files.chatfile != undefined ? "File" : "Text",
            name: name,
            email: email
        })
        await chatData.save();
    }
    groupData.chats.push({
        chatId: chatData._id
    });
    if (req.files.chatFile) {
        let mediaData = new media({
            fileType: msg.split(".")[msg.split(".").length - 1],
            fileurl: msg,
            chatId: chatData._id
        })
        await mediaData.save();
        groupData.attachments.push({
            fileId: mediaData._id
        })
    }
    let creatorData = await user.findById(creatorId);
    groupData.save();
    let iocon = socketIo.getIO();
    groupData.members.forEach((element) => {
        let hashed = crypto.createHash('sha256').update(element.memberId.email).digest('hex');
        iocon.to(hashed).emit("group_msg",
            {
                msg: "msg sent successfully",
                chat: msg,
                chatType: chatData.chatType,
                chatTime: chatData.chatTime,
                chatId: chatData._id.toString(),
                name: name,
                email: email,
                userId: req.userId
            }
        )
    })
    let hashed = crypto.createHash('sha256').update(creatorData.email).digest('hex');
    iocon.to(hashed).emit("group_msg",
        {
            msg: "msg sent successfully",
            chat: msg,
            chatType: chatData.chatType,
            chatTime: chatData.chatTime,
            chatId: chatData._id.toString(),
            name: name,
            email: email,
            userId: req.userId
        }
    )
    return res.status(201).json(
        {
            msg: "msg sent successfully"
        }
    )
}
exports.displayMsg = async (req, res, next) => {
    let groupName = req.body.groupName;
    let creatorId = req.body.creatorId;
    let userData = await user.findById(req.userId);
    if (!userData) {
        return res.status(404).json({
            msg: "user doesn't exists"
        });
    }
    let groupData = await groups.findOne({
        groupName: groupName,
        creatorId: creatorId
    })
        .populate("chats.chatId")
        .populate("chats.chatId.sentBy", "name email")
    if (!groupData) {
        return res.status(404).json({
            msg: "group doesn't exist"
        })
    }
    let memberIndex = groupData.members.findIndex((member) => {
        if (member.memberId.toString() == req.userId.toString()) {
            return member;
        }
    })
    if (memberIndex == -1 && req.userId.toString() != creatorId.toString()) {
        return res.status(401).json({
            msg: "unauthorised"
        })
    }
    return res.status(200).json({
        msg: "message sent successfully",
        chats: groupData.chats
    })
}
exports.searchGrp = (req, res, next) => {
    let searchVal = req.body.searchField;
    let regex = new RegExp(searchVal, "i");
    user.findById(req.userId)
        .populate("groups.groupId")
        .populate("contacts.contactId", "name email status profilePic")
        .then((userData) => {
            let groupsMatch = userData.groups.filter((group) => {
                if (regex.test(group.groupId.groupName)) {
                    return group;
                }
            })
            let requiredData = (({ _id, contacts, groups, name, email }) => ({ _id, contacts, groups, name, email }))(userData);
            return res.status(200).json({
                userData: {
                    ...requiredData, groups: groupsMatch
                }
            })
        })
}