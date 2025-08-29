import { Request, Response } from 'express'
import Note from '../models/Note'

export const createNote = async (req: Request, res: Response) => {
    const { content } = req.body
    const userId = req.user!.userId

    if (!content) return res.status(400).json({ message: 'Content is required' })

    try {
        const note = new Note({ userId, content })
        await note.save()
        res.json(note)
    } catch (error) {
        res.status(500).json({ message: 'Server error' })
    }
}

export const getNotes = async (req: Request, res: Response) => {
    const userId = req.user!.userId

    try {
        const notes = await Note.find({ userId }).sort({ createdAt: -1 })
        res.json(notes)
    } catch (error) {
        res.status(500).json({ message: 'Server error' })
    }
}

export const deleteNote = async (req: Request, res: Response) => {
    const { id } = req.params
    const userId = req.user!.userId

    try {
        const note = await Note.findOne({ _id: id, userId })
        if (!note) return res.status(404).json({ message: 'Note not found' })

        await note.deleteOne()
        res.json({ message: 'Note deleted' })
    } catch (error) {
        res.status(500).json({ message: 'Server error' })
    }
}