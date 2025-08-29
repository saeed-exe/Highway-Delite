import { Request, Response } from 'express'
import User from '../models/User'
import jwt from 'jsonwebtoken'
import nodemailer from 'nodemailer'
import { OAuth2Client } from 'google-auth-library'

const generateOtp = () => Math.floor(100000 + Math.random() * 900000).toString()

export const sendOtp = async (req: Request, res: Response) => {
    const { email } = req.body
    if (!email) return res.status(400).json({ message: 'Email is required' })

    const otp = generateOtp()
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000)

    try {
        let user = await User.findOne({ email })
        if (!user) {
            user = new User({ email, otp, otpExpires })
        } else {
            user.otp = otp
            user.otpExpires = otpExpires
        }
        await user.save()

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            }
        })

        await transporter.sendMail({
            to: email,
            subject: 'Your OTP Code',
            text: `Your OTP code is ${otp}. It expires in 10 minutes.`
        })

        res.json({ message: 'OTP sent' })
    } catch (error) {
        res.status(500).json({ message: 'Server error' })
    }
}

export const verifyOtp = async (req: Request, res: Response) => {
    const { email, otp } = req.body
    if (!email || !otp) return res.status(400).json({ message: 'Email and OTP are required' })

    try {
        const user = await User.findOne({ email })
        if (!user || user.otp !== otp || user.otpExpires! < new Date()) {
            return res.status(400).json({ message: 'Invalid or expired OTP' })
        }

        user.otp = undefined
        user.otpExpires = undefined
        await user.save()

        const token = jwt.sign({ userId: user._id, email: user.email }, process.env.JWT_SECRET!, {
            expiresIn: '1d'
        })

        res.json({ token })
    } catch (error) {
        res.status(500).json({ message: 'Server error' })
    }
}

export const googleAuth = async (req: Request, res: Response) => {
    const { token } = req.body
    if (!token) return res.status(400).json({ message: 'Token is required' })

    try {
        const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID)
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID
        })
        const payload = ticket.getPayload()
        if (!payload) return res.status(400).json({ message: 'Invalid token' })

        const { email, sub: googleId } = payload
        let user = await User.findOne({ email })
        if (!user) {
            user = new User({ email, googleId })
            await user.save()
        } else if (!user.googleId) {
            user.googleId = googleId
            await user.save()
        }

        const jwtToken = jwt.sign({ userId: user._id, email: user.email }, process.env.JWT_SECRET!, {
            expiresIn: '1d'
        })

        res.json({ token: jwtToken })
    } catch (error) {
        res.status(500).json({ message: 'Server error' })
    }
}