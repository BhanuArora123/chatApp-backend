const fs = require("fs");
const deleteFile = (path) => {
    if(!path){
        return ;
    }
    else{
        fs.unlink(path,(err) => {
            console.log(err);
        });
    }
}
module.exports = deleteFile;