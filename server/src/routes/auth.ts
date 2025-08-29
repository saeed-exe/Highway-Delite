import express from 'express'
import { sendOtp, verifyOtp, googleAuth } from '../controllers/auth'

const router = express.Router()

router.post('/send-otp', sendOtp)
router.post('/verify-otp', verifyOtp)
router.post('/google', googleAuth)

export default router