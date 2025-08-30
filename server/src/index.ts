import express from "express"
import mongoose, { Schema, Types } from "mongoose"
import cors from "cors"
import dotenv from "dotenv"
import jwt from "jsonwebtoken"
import bcrypt from "bcryptjs"
import { OAuth2Client } from "google-auth-library"
import { z } from "zod"
import nodemailer from "nodemailer"

dotenv.config()

const app = express()
app.use(express.json())
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173"
app.use(cors({ origin: FRONTEND_URL.split(",").map(s => s.trim()) }))

const MONGODB_URI = process.env.MONGODB_URI || ""
const JWT_SECRET = process.env.JWT_SECRET || "secret"
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || ""
const PORT = Number(process.env.PORT || 8080)

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID)

mongoose.set('strictQuery', false)
mongoose.connect(MONGODB_URI)

const UserSchema = new Schema({ email: { type: String, unique: true, index: true }, name: String, provider: { type: String, enum: ["email", "google"], default: "email" }, googleId: String, picture: String }, { timestamps: true })
const NoteSchema = new Schema({ userId: { type: Schema.Types.ObjectId, ref: "User", index: true }, content: String }, { timestamps: true })
const OtpSchema = new Schema({ email: String, otpHash: String, expiresAt: Date, attempts: { type: Number, default: 0 } }, { timestamps: true })

const User = mongoose.model("User", UserSchema)
const Note = mongoose.model("Note", NoteSchema)
const Otp = mongoose.model("Otp", OtpSchema)

function signToken(u: any) { return jwt.sign({ sub: u._id.toString(), email: u.email, name: u.name }, JWT_SECRET, { expiresIn: "7d" }) }

function auth(req: any, res: any, next: any) {
    const h = req.headers.authorization || ""
    const t = h.startsWith("Bearer ") ? h.slice(7) : ""
    if (!t) return res.status(401).json({ error: "unauthorized" })
    try {
        const p = jwt.verify(t, JWT_SECRET) as any
        req.userId = p.sub
        next()
    } catch {
        res.status(401).json({ error: "unauthorized" })
    }
}

const emailSchema = z.object({ email: z.string().email() })
const otpVerifySchema = z.object({ email: z.string().email(), otp: z.string().regex(/^\d{6}$/), name: z.string().min(2).max(60) })
const noteSchema = z.object({ content: z.string().min(1).max(2000) })

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
})

app.post("/auth/send-otp", async (req, res) => {
    const p = emailSchema.safeParse(req.body)
    if (!p.success) return res.status(400).json({ error: "invalid_email" })

    const email = p.data.email.toLowerCase()
    const code = Math.floor(100000 + Math.random() * 900000).toString()
    const otpHash = await bcrypt.hash(code, 10)
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000)

    await Otp.deleteMany({ email })
    await Otp.create({ email, otpHash, expiresAt })

    // send email
    try {
        await transporter.sendMail({
            from: `"Notes App" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: "Your OTP Code",
            text: `Your OTP is: ${code}`,
            html: `<p>Your OTP is: <b>${code}</b></p>`,
        })
    } catch (err) {
        console.error("Email send failed", err)
        return res.status(500).json({ error: "email_failed" })
    }

    res.json({ ok: true })
})

app.post("/auth/verify-otp", async (req, res) => {
    const p = otpVerifySchema.safeParse(req.body)
    if (!p.success) return res.status(400).json({ error: "invalid_input" })
    const { email, otp, name } = p.data
    const rec = await Otp.findOne({ email }).sort({ createdAt: -1 })
    if (!rec) return res.status(400).json({ error: "otp_not_found" })
    if (rec.expiresAt! < new Date()) return res.status(400).json({ error: "otp_expired" })
    if (rec.attempts >= 5) return res.status(429).json({ error: "too_many_attempts" })
    const ok = await bcrypt.compare(otp, rec.otpHash)
    if (!ok) {
        await Otp.updateOne({ _id: rec._id }, { $inc: { attempts: 1 } })
        return res.status(400).json({ error: "otp_incorrect" })
    }
    await Otp.deleteMany({ email })
    let user = await User.findOne({ email })
    if (!user) user = await User.create({ email, name, provider: "email" })
    else if (!user.name && name) { user.name = name; await user.save() }
    const token = signToken(user)
    res.json({ token, user: { id: user._id.toString(), email: user.email, name: user.name, picture: user.picture } })
})

app.post("/auth/google", async (req, res) => {
    const idToken = req.body?.idToken
    if (!idToken) return res.status(400).json({ error: "missing_token" })
    try {
        const ticket = await googleClient.verifyIdToken({ idToken, audience: GOOGLE_CLIENT_ID })
        const payload: any = ticket.getPayload()
        const email = String(payload.email || "").toLowerCase()
        const sub = payload.sub as string
        const name = payload.name as string
        const picture = payload.picture as string
        let user = await User.findOne({ email })
        if (!user) user = await User.create({ email, name, provider: "google", googleId: sub, picture })
        else { user.googleId = user.googleId || sub; user.provider = user.provider === "email" ? "email" : "google"; user.name = user.name || name; user.picture = user.picture || picture; await user.save() }
        const token = signToken(user)
        res.json({ token, user: { id: user._id.toString(), email: user.email, name: user.name, picture: user.picture } })
    } catch (e) {
        res.status(400).json({ error: "google_verify_failed" })
    }
})

app.get("/me", auth, async (req: any, res) => {
    const u = await User.findById(req.userId)
    if (!u) return res.status(404).json({ error: "not_found" })
    res.json({ id: u._id.toString(), email: u.email, name: u.name, picture: u.picture })
})

app.get("/notes", auth, async (req: any, res) => {
    const list = await Note.find({ userId: new Types.ObjectId(req.userId) }).sort({ createdAt: -1 })
    res.json(list.map(n => ({ id: n._id.toString(), content: n.content, createdAt: n.createdAt })))
})

app.post("/notes", auth, async (req: any, res) => {
    const p = noteSchema.safeParse(req.body)
    if (!p.success) return res.status(400).json({ error: "invalid_input" })
    const n = await Note.create({ userId: new Types.ObjectId(req.userId), content: p.data.content })
    res.status(201).json({ id: n._id.toString(), content: n.content, createdAt: n.createdAt })
})

app.delete("/notes/:id", auth, async (req: any, res) => {
    const id = req.params.id
    const n = await Note.findOne({ _id: id, userId: new Types.ObjectId(req.userId) })
    if (!n) return res.status(404).json({ error: "not_found" })
    await n.deleteOne()
    res.json({ ok: true })
})

app.get("/health", (_req, res) => res.json({ ok: true }))

app.listen(PORT, () => console.log(`api:${PORT}`))
