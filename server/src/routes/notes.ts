import express from 'express'
import { authMiddleware } from '../middleware/auth'
import { createNote, getNotes, deleteNote } from '../controllers/notes'

const router = express.Router()

router.use(authMiddleware)
router.post('/', createNote)
router.get('/', getNotes)
router.delete('/:id', deleteNote)

export default router