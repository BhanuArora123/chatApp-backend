const user = require("../model/userModel");

const _filePath = import("../utils/temp.mjs");

const filehelper = require("../utils/filehelper");

const socketIo = require("../utils/socket");

const path = require("path");

// const call = require("../model/callModel")

// const crypto = require("crypto")

exports.Profile = async (req, res, next) => {
    // validate the request sent by the server
    let userData = await user.findOne({ email: req.email })
        .populate("attachments.fileId");
    if (!userData) {
        return res.status(404).json({
            msg: "email doesn't exists"
        })
    }
    let requiredData = (({ profilePic, name, status, email, attachments }) => ({ profilePic, name, status, email, attachments }))(userData);
    return res.status(200).json({
        userData: {
            ...requiredData
        }
    })
}
exports.Chats = async (req, res, next) => {
    // validate the request sent by the server
    let userData = await user.findOne({ email: req.email })
        .populate("contacts.contactId", "name email status profilePic isActive");
    if (!userData) {
        return res.status(404).json({
            msg: "email doesn't exists"
        })
    }
    let contactsAlt = await userData.contacts.map(contact => {
        let value = Object.keys(socketIo.users).find(key => {
            return socketIo.users[key].toString() == contact.contactId._id.toString()
        })
        if (value) {
            let contactAlt = contact.toObject();
            contactAlt.isActive = true;
            return contactAlt;
        }
        return contact;
    })
    let requiredData = (({ contacts, email, name, isActive }) => ({ contacts, email, name, isActive }))(userData);
    return res.status(200).json({
        userData: {
            ...requiredData
            , contacts: contactsAlt
        }
    })
}
exports.Groups = async (req, res, next) => {
    // validate the request sent by the server
    let userData = await user.findOne({ email: req.email })
        .populate("groups.groupId")
        .populate("contacts.contactId", "name email status profilePic");
    if (!userData) {
        return res.status(404).json({
            msg: "email doesn't exists"
        })
    }
    let requiredData = (({ _id, contacts, groups, name, email }) => ({ _id, contacts, groups, name, email }))(userData);
    return res.status(200).json({
        userData: {
            ...requiredData
        }
    })
}
exports.Contacts = async (req, res, next) => {
    // validate the request sent by the server
    let userData = await user.findOne({ email: req.email })
        .populate("contacts.contactId", "name email status profilePic");
    if (!userData) {
        return res.status(404).json({
            msg: "email doesn't exists"
        })
    }
    let contactsAlt = await userData.contacts.map(contact => {
        let value = Object.keys(socketIo.users).find(key => {
            return socketIo.users[key].toString() == contact.contactId._id.toString()
        })
        if (value) {
            let contactAlt = contact.toObject();
            contactAlt.isActive = true;
            return contactAlt;
        }
        return contact;
    })
    let requiredData = (({ _id, contacts, name, email }) => ({ _id, contacts, name, email }))(userData);
    console.log(userData.contacts);
    return res.status(200).json({
        userData: {
            ...requiredData
            , contacts: contactsAlt
        }
    })
}
exports.Settings = async (req, res, next) => {
    // validate the request sent by the server
    let userData = await user.findOne({ email: req.email });
    if (!userData) {
        return res.status(404).json({
            msg: "email doesn't exists"
        })
    }
    let requiredData = (({ profilePic, name, status, email, attachments, isActive }) => ({ profilePic, name, status, email, attachments, isActive }))(userData);
    return res.status(200).json({
        userData: {
            ...requiredData
        }
    })
}
exports.editUser = async (req, res, next) => {
    let name = req.body.name;
    console.log(name + "the name")
    let status = req.body.status;
    let userData = await user.findOne({ email: req.email })
    .populate("attachments.fileId");
    let profilePic = userData.profilePic;
    let mod = await _filePath;
    console.log(req.files);
    if (req.files.image) {
        filehelper(path.join(__dirname, "..", userData.profilePic));
        profilePic = await mod.posixPath("https://chatappbackend12345.herokuapp.com/" + req.files.image[0].path);
        console.log(profilePic);
    }
    userData.name = name;
    userData.status = status;
    userData.profilePic = profilePic;
    userData.save();
    let requiredData = (({ profilePic, name, status, email, attachments }) => ({ profilePic, name, status, email, attachments }))(userData);
    return res.status(200).json({
        msg: "User updated successfully",
        userData: { ...requiredData }
    });
}
exports.searchChat = (req, res, next) => {
    let searchVal = req.body.searchField;
    let regex = new RegExp(searchVal, "i");
    console.log(regex)
    user.findById(req.userId)
        .populate("contacts.contactId", "name email status profilePic")
        .then((userData) => {
            let contactsAlt = userData.contacts.map(contact => {
                let value = Object.keys(socketIo.users).find(key => {
                    return socketIo.users[key].toString() == contact.contactId._id.toString()
                })
                if (value) {
                    let contactAlt = contact.toObject();
                    contactAlt.isActive = true;
                    return contactAlt;
                }
                return contact;
            })
            let contactMatch = contactsAlt.filter((userDoc) => {
                if (regex.test(userDoc.contactId.name)) {
                    return userDoc;
                }
            });
            let requiredData = (({ _id, contacts, name, email }) => ({ _id, contacts, name, email }))(userData);

            return res.status(200).json({
                userData: {
                    ...requiredData
                    , contacts:contactMatch
                }
            })
        })
        .catch((err) => {
            console.log(err);
        })
}
// exports.makeCall = async (req,res,next) => {
//     let callTo = req.body.callTo;
//     let userData = await user.findOne({email:callTo})
//     if(!userData){
//         return res.status(404).json({
//             msg:"user not found"
//         })
//     }
//     let currentUser = await user.findById(req.userId);
//     let callData = new call({
//         callTo:userData._id,
//         callBy:req.userId,
//         callTime:new Date(Date.now()).toISOString()
//     })
//     callData.save();
//     let ioObj = await socketIo.getIO();
//     let hashed = await crypto.createHash('sha256').update(callTo).digest('hex');
//     ioObj.to(hashed).emit("callPerson", {
//         msg: "call done successfully",
//         callId:callData._id,
//         name:currentUser.name,
//         profilePic:currentUser.profilePic,
//         roomId:uuidV4()
//     })
//     return res.status(200).json({
//         msg:"called successfully"
//     })
// }