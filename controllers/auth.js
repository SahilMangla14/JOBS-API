const User = require('../models/User')
const { StatusCodes } = require('http-status-codes')
const { BadRequestError, UnauthenticatedError } = require('../errors')

const register = async(req,res) => {
    // Method 1 -> validation checking
    // const {name , email, password} = req.body
    // if(!name || !email || !password) {
    //     throw new BadRequestError('Please provide name,email and password')
    // }

    // Method-2 -> using mongoose schema validators

    const user = await User.create({...req.body})

    // M1 to create token
    // const token = jwt.sign({userId:user._id,name:user.name},'jwtSecret',{expiresIn:'30d'})

    // M2 using functions
    const token = user.createJWT()
    res.status(StatusCodes.CREATED).json({ user:{ name:user.name}, token })
}

const login = async (req, res) => {
    const { email, password } = req.body
  
    if (!email || !password) {
      throw new BadRequestError('Please provide email and password')
    }
    const user = await User.findOne({ email })
    if (!user) {
      throw new UnauthenticatedError('Invalid Credentials')
    }

    // compare password
    const isPasswordCorrect = await user.comparePassword(password)
    if (!isPasswordCorrect) {
      throw new UnauthenticatedError('Invalid Credentials')
    }
    const token = user.createJWT()
    res.status(StatusCodes.OK).json({ user: { name: user.name }, token })
  }
  
  module.exports = {
    register,
    login,
  }
  

// bcryptjs library is used to hash passwords 