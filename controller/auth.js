const user = require("../model/userModel.js");
const bcryptjs = require("bcryptjs");

const { validationResult } = require("express-validator/check");

const jwt = require("jsonwebtoken");

const Vonage = require('@vonage/server-sdk');

exports.signup = async (req, res, next) => {
    const email = req.body.email;
    const pass = req.body.password;
    const name = req.body.name;
    //adding validation 
    let errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(422).json({
            msg: errors.array()
        })
    }
    let result = await bcryptjs.hash(pass, 12)
    let userData = new user({
        email: email,
        password: result,
        name: name
    });
    let userDoc = await userData.save();
    res.status(201).json({
        msg:"user Created successfully",
        userId:userDoc._id,
        status:201
    })
}
exports.loginHandler = async (req, res, next) => {
    const email = req.body.email;
    const pass = req.body.password;
    let errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(422).json({
            msg: errors.array(),
            status: 422
        })
    }
    let userData = await user.findOne({ email: email });
    if (!userData) {
        return res.status(404).json({
            msg: [{
                msg: "user not found signup"
            }],
            status: 404
        })
    }
    let result = await bcryptjs.compare(pass, userData.password);
    if (!result) {
        return res.status(403).json({
            msg: [{
                msg: "invalid password"
            }],
            status: 403
        });
    }
    if(!userData.isverified){
        return res.status(403).json({
            msg:"user is not verified"
        })
    }
    // generate jwt
    let jwtToken = jwt.sign({
        email: email,
        userId: userData._id
    }, "secretismysecretnoneofyoursecret");
    res.cookie("jwtToken", jwtToken, {
        expires: new Date(Date.now() + 3600000),
        httpOnly: true,
        secure: true,
        domain: "chatapp-client-12345.herokuapp.com"
    });
    return res.status(200).json({
        token: jwtToken,
        msg: "user created successfully",
        token: jwtToken,
        status: 200
    });
}
exports.generateOTP = (req, res, next) => {
    let userId = req.body.userId;
    let phn_no = req.body.number;
    let errors = validationResult(req);
    let otp;
    if(!errors.isEmpty()){
        return res.status(422).json({
            msg:errors.array()
        })
    }
    user.findById(userId)
        .then((userData) => {
            let otp_part1 = Math.floor(1000 + Math.random() * 9000);
            let otp_part2 = Math.floor(1000 + Math.random() * 9000);
            otp = otp_part1 * 10000 + otp_part2;
            userData.otp = {
                value: otp,
                expires: new Date(Date.now() + 6000)
            };
            return userData.save();
        })
        .then((userDoc) => {
            const vonage = new Vonage({
                apiKey: process.env.apiKey,
                apiSecret: process.env.apiSecret
            })
            const from = "Vonage APIs";
            const to = (phn_no).toString();
            const message = `use this otp ${otp} to login , code expires in 10 minutes`;
            vonage.message.sendSms(from, to, message, (err, responseData) => {
                if (err) {
                    return res.status(424).json({
                        msg: "failed to send messages",
                        error: err
                    })
                }
                if (responseData.messages[0]['status'] === "0") {
                    return res.status(200).json({
                        msg: "Message sent successfully.",
                        userId:req.body.userId
                    })
                } 
                return res.status(424).json({
                    msg:`Message failed with error: ${responseData.messages[0]['error-text']}`
                });
            })
        })
}
exports.verifyOTP = (req,res,next) => {
    let otp = req.body.otp;
    user.findOne({
        $and:[
            {
                otp:{
                    value:parseInt(otp),
                    expires:{
                        $gt : new Date(Date.now())
                    }
                }
            },
            {
                userId:req.body.userId
            }
        ]
    })
    .then((userDoc) => {
        if(!userDoc){
            return res.status(401).json({
                msg:"invalid otp"
            })
        }
        userDoc.isverified = true;
        return userDoc.save();
    })
    .then(() => {
        return res.status(200).json({
            msg:"otp verified"
        })
    })
    .catch(err => console.log(err))
}