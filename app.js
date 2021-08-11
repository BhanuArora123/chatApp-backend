const express = require("express");
const app = express();
const mongoose = require("mongoose");

const socketIO = require("./utils/socket.js");

const path = require("path");

const bodyParser = require("body-parser");

const authRouter = require("./routes/auth");

const userRouter = require("./routes/userData");

const contactRouter = require("./routes/contact");

const groupRouter = require("./routes/groups");

const messageRouter = require("./routes/messages");

const cookieParser = require("cookie-parser");

const cors = require("cors");

const multer = require("multer");

// handling cors
// app.use((req,res,next) => {
//     res.setHeader("Access-Control-Allow-Origin","http://localhost:8081")
//     res.setHeader("Access-Control-Allow-Methods","GET , POST , DELETE , PUT , PATCH");
//     res.setHeader("Access-Control-Allow-Headers","Content-Type , Authorization");
//     next();
// })

app.use(cors({
    origin: "https://chatapp-client-12345.herokuapp.com",
    credentials: true,
    withCredentials: true
}))

let fileStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, "images");
    },
    filename: (req, file, cb) => {
        cb(null, new Date().toISOString().replace(/:/g, '-') + "-" + file.originalname);
    }
});

let fileFilter = (req, file, cb) => {
    console.log(file.mimetype);
    console.log("hello")
    if (file.mimetype == "image/jpg" || file.mimetype == "image/png" || file.mimetype == "image/jpeg") {
        cb(null, true);
    }
    else {
        cb(null, false);
    }
}

app.use(multer({
    storage: fileStorage
}).fields(
    [
        {
            name: "image"
        },
        {
            name: "chatfile"
        },
        {
            name: "groupIcon"
        }
    ]
)
);

app.use(bodyParser.json())

app.use(cookieParser());

// storage for multer



// let the client access the images
app.use("/images", express.static(path.join(__dirname, "images")));

app.use(authRouter);

app.use(contactRouter);

app.use(userRouter);

app.use(groupRouter);

app.use(messageRouter);

mongoose.connect(`mongodb+srv://${process.env.USER}:${process.env.PASS}@cluster0.kpq9o.mongodb.net/${process.env.DB}?retryWrites=true&w=majority`)
    .then((result) => {
        let server = app.listen(process.env.PORT || 8080);
        // setting up websockets
        let iocon = socketIO.init({
            httpServer: server,
            corsSetup: {
                cors: {
                    origin: "http://localhost:8081",
                    methods: ["GET", "POST"],
                    allowedHeaders: ["Content-Type"]
                }
            }
        })
        return iocon;
    })
    .then((iocon) => {
        iocon.on("connect_error", (err) => {
            console.log(err);
        })
        iocon.on("connection", (socket) => {
            console.log("client connected");
            socket.on("join", function (data) {
                socket.join(data.encData);
                socketIO.users[socket.id] = data.currentId;
                socket.broadcast.emit("isActive", {
                    userId: data.currentId
                })
            })
            socket.on("disconnect", (sock) => {
                console.log("client disconnected");
                let userId = socketIO.users[socket.id];
                console.log(userId)
                iocon.emit("isOffline", {
                    userId: userId
                })
                delete socketIO.users[socket.id];
            })
            socket.on('join-room', (roomId, userId) => {
                socket.join(roomId)
                socket.to(roomId).emit('user-connected', userId)

                socket.on('disconnect', () => {
                    socket.to(roomId).emit('user-disconnected', userId)
                })
            })
        })
    })
    .catch((err) => {
        console.log(err);
    });