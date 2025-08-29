import mongoose from 'mongoose'

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    googleId: { type: String },
    otp: { type: String },
    otpExpires: { type: Date }
})

export default mongoose.model('User', userSchema)