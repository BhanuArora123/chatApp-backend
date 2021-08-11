const user = require("../model/userModel.js");
const bcryptjs = require("bcryptjs");

const { validationResult } = require("express-validator/check");

const jwt = require("jsonwebtoken");

exports.signup = async (req, res, next) => {
    const email = req.body.email;
    const pass = req.body.password;
    const name = req.body.name;
    //adding validation 
    let errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.json({
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
    return res.json({
        msg:"User successfully created"
    })
}
exports.loginHandler = async (req,res,next) => {
    const email = req.body.email;
    const pass = req.body.password;
    console.log(email)
    let errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.status(422).json({
            msg:errors.array(),
            status:422
        })
    }
    let userData = await user.findOne({email:email});
    if(!userData){
        return res.status(404).json({
            msg:"user not found signup"
        })
    }
    let result = await bcryptjs.compare(pass,userData.password);
    if(!result){
        return res.status(403).json({
            msg:"invalid password"
        });
    }
    // generate jwt
    let jwtToken = jwt.sign({
        email:email,
        userId:userData._id
    },"somesupersecret");
    res.cookie("jwtToken",jwtToken,{
        expires:new Date(Date.now() + 3600000),
        httpOnly:true,
        crossDomain:true
    });
    return res.status(200).json({
        token:jwtToken,
        msg:"user created successfully",
        status:200
    });
}