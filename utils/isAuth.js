const jwt = require("jsonwebtoken");

const isAuth = (req, res, next) => {
    try {
        let jwtTok = req.cookies.jwtToken;
        let userData = jwt.verify(jwtTok, "somesupersecret");
        console.log(userData);
        if (!userData) {
            return res.status(401).json({
                msg: "invalid Token"
            })
        }
        req.userId = userData.userId;
        req.email = userData.email;
        req.isActive = true;
        next();
    } catch (err) {
        res.status(401).json({
            msg:err
        })
    }
}
module.exports = isAuth;