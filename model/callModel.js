const mongoose = require("mongoose");

const schema = mongoose.Schema;

const callSchema = new schema({
    callTo:{
        type:mongoose.Types.ObjectId,
        required:true
    },
    callBy:{
        type:mongoose.Types.ObjectId,
        required:true
    },
    callTime:{
        type:Date,
        required:true
    },
    callEnd:{
        type:Date
    }
})

module.exports = mongoose.model("call",callSchema);