const mongoose = require("mongoose");

const schema = mongoose.Schema;

const mediaSchema = schema({
    fileType:{
        type:String,
        required:true
    },
    fileurl:{
        type:String,
        required:true
    },
    chatId:{
        type:String,
        required:true
    }
});

module.exports = mongoose.model("media",mediaSchema);