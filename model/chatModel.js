const mongoose = require("mongoose");

const schema = mongoose.Schema;

const chatSchema = new schema({
    chatTime:{
        type:Date,
        required:true
    },
    name:{
        type:String
    },
    email:{
        type:String
    },
    sentTo:{
        type:mongoose.Schema.Types.ObjectId,
        required:true
    },
    sentBy:{
        type:mongoose.Schema.Types.ObjectId,
        required:true
    }
    ,
    chatContent:{
        type:String,
        required:true
    },
    chatType:{
        type:String,
        required:true
    }
})

module.exports = mongoose.model("chat",chatSchema);