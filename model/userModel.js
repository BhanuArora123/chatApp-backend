const mongoose = require("mongoose");
const schema = mongoose.Schema;

const path = require("path");

const group = require("../model/groupsModels");

const media = require("../model/MediaModel");

const chat = require("../model/chatModel");

const userSchema = new schema({
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    name: {
        type: String,
        required: true
    },
    location: {
        type: String,
        default: "Not Known"
    },
    status: {
        type: String,
        default: "Available"
    },
    about: {
        type: String,
        default: "No Info Available"
    },
    profilePic: {
        type: String,
        default: "https://chatappbackend12345.herokuapp.com/images/custom.jpg"
    },
    attachments: [
        {
            fileId: {
                type: mongoose.Schema.Types.ObjectId,
                ref:"media",
                required: true
            }
        }
    ],
    chats: [
        {
            chatId:{
                type:mongoose.Schema.Types.ObjectId,
                ref:"chat",
                required:true
            }
        }
    ],
    groups: [{
        groupId: {
            type: mongoose.Schema.Types.ObjectId,
            ref:"group",
            required: true
        }
    }],
    contacts: [
        {
            contactId: {
                type: mongoose.Schema.Types.ObjectId,
                ref:"user",
                required: true
            },
            isBlocked: {
                type: mongoose.Schema.Types.Boolean,
                required: true
            }
        }
    ]
})
module.exports = mongoose.model("user", userSchema);