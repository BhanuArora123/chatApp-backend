const socketIo = require("socket.io");
let io;
exports.init = async (server) => {
    io = await socketIo(server.httpServer,server.corsSetup);
    return io;
}
exports.getIO = () => {
    if(!io){
        console.log("there is some error");
    }
    return io;
}
exports.users = {};