const contact = require("../model/userModel");

const {validationResult} = require("express-validator/check")

exports.addContact = async (req,res,next) => {
    let name = req.body.name;
    let email = req.body.email;
    let errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.json({
            msg: errors.array()
        })
    }
    let newContact = await contact.findOne({
        email:email
    });
    if(!newContact || req.email == email){
        return res.status(404).json({
            msg:"this user is not registered or its you itself"
        })
    }
    let currentUser = await contact.findOne({
        email:req.email
    });
    let userData = await contact.findOne({
        email:req.email
    }).populate("contacts.contactId");
    console.log(userData);
    // check if this user is already added into the contact list
    for (let i = 0; i < currentUser.contacts.length; i++) {
        const element = userData.contacts[i];
        console.log(element.contactId)
        if(email == element.contactId.email){
            return res.status(409).json({
                msg:"user Already exists "
            })
        }
    }
    currentUser.contacts.push({
        contactId:newContact._id,
        isBlocked:false
    });
    let requiredData = (({ name,email,status,profilePic }) => ({ name,email,status,profilePic }))(newContact);
    currentUser.save();
    return res.status(201).json({
        msg:"Contact added sucessfully",
        userData:{
            contact:{...requiredData}
        }
    });
}