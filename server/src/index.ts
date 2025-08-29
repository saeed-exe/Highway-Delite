import express from 'express'
import mongoose from 'mongoose'
import cors from 'cors'
import authRoutes from './routes/auth'
import noteRoutes from './routes/notes'
import dotenv from 'dotenv'

dotenv.config()

const app = express()

app.use(cors())
app.use(express.json())

app.use('/api/auth', authRoutes)
app.use('/api/notes', noteRoutes)

mongoose.connect(process.env.MONGO_URI!)
    .then(() => console.log('MongoDB connected'))
    .catch((err) => console.error(err))

const PORT = process.env.PORT || 5000
app.listen(PORT, () => console.log(`Server running on port ${PORT}`))