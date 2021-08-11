const mongoose = require("mongoose");



const Schema = mongoose.Schema;

const groupSchema = new Schema({
    groupName:{
        type:String,
        required:true
    },
    groupIcon:{
        type:String,
        required:true
    },
    groupDesc:{
        type:String,
        default:"This is a nice group"
    },
    members:[
        {
            memberId:{
                type:mongoose.Schema.Types.ObjectId,
                ref:"user",
                required:true
            }
        }
    ],
    creatorId:{
        type:mongoose.Schema.Types.ObjectId,
        ref:"user",
        required:true
    },
    attachments:[
        {
            fileId:{
                type:mongoose.Schema.Types.ObjectId,
                ref:"media",
                required:true
            }
        }
    ],
    chats:[
        {
            chatId:{
                type:mongoose.Schema.Types.ObjectId,
                ref:"chat",
                required:true
            }
        }
    ]
})

module.exports = mongoose.model("group",groupSchema);