const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        required:[true,'Please provide name'],
        minlength: 3,
        maxlength: 50,
    },
    email: {
        type: String,
        required: [true, 'Please provide email'],
        match: [
            /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
            'Please provide valid email'
        ],
        unique: true,
    },
    password: {
        type: String,
        required:[true,'Please provide name'],
        minlength: 6
    },
})

// Pre
// Pre middleware functions are executed one after another, when each middleware calls next
// In mongoose 5.x, instead of calling next() manually, you can use a function that returns a promise. In particular, you can use async/await

// database mein save karne se pehle ye middleware implement hoga
// pre ke pass document hota hai, jisko hum this se access karte hai
// we should call next() here because the response to the request is still not provided
// but in pre and post middleware we can use async/await functions and can neglect next()
UserSchema.pre('save', async function(){

    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password,salt)
})

// Method to create functions
// syntax -> UserSchema.methods.function name
UserSchema.methods.createJWT = function () {
    return jwt.sign({ userId:this._id,name:this.name}, process.env.JWT_SECRET , {
        expiresIn: process.env.JWT_LIFETIME
    })
}


UserSchema.methods.comparePassword = async function (candidatePassword) {
    const isMatch = await bcrypt.compare(candidatePassword, this.password)
    return isMatch
}

module.exports = mongoose.model('User',UserSchema)