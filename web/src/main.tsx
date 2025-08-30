import React from 'react'
import ReactDOM from 'react-dom/client'
import { z } from 'zod'
import './styles.css'

const API = (import.meta.env.VITE_API_URL as string) || 'http://localhost:8080'

async function apiPost(path: string, body: any, token?: string) {
  const res = await fetch(API + path, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(body) })
  const j = await res.json().catch(() => ({}))
  if (!res.ok) throw j
  return j
}

async function apiGet(path: string, token?: string) {
  const res = await fetch(API + path, { headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}) } })
  const j = await res.json().catch(() => ({}))
  if (!res.ok) throw j
  return j
}

async function apiDel(path: string, token?: string) {
  const res = await fetch(API + path, { method: 'DELETE', headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}) } })
  const j = await res.json().catch(() => ({}))
  if (!res.ok) throw j
  return j
}

const emailSchema = z.string().email()
const nameSchema = z.string().min(2).max(60)
const otpSchema = z.string().regex(/^\d{6}$/)

function App() {
  const [token, setToken] = React.useState<string | null>(localStorage.getItem('token'))
  const [user, setUser] = React.useState<any | null>(null)
  const [view, setView] = React.useState<'auth' | 'notes'>(token ? 'notes' : 'auth')
  const [email, setEmail] = React.useState('')
  const [name, setName] = React.useState('')
  const [otpSent, setOtpSent] = React.useState(false)
  const [otp, setOtp] = React.useState('')
  const [status, setStatus] = React.useState('')
  const [notes, setNotes] = React.useState<any[]>([])
  const [newNote, setNewNote] = React.useState('')
  const googleRef = React.useRef<HTMLDivElement | null>(null)
  const [sendingOtp, setSendingOtp] = React.useState(false)

  const validEmail = React.useMemo(() => emailSchema.safeParse(email).success, [email])
  const validName = React.useMemo(() => nameSchema.safeParse(name).success, [name])
  const validOtp = React.useMemo(() => otpSchema.safeParse(otp).success, [otp])

  React.useEffect(() => {
    if (!token) return
    apiGet('/me', token).then(u => { setUser(u); setView('notes'); loadNotes(token) }).catch(() => { logout() })
  }, [])

  React.useEffect(() => {
    const id = import.meta.env.VITE_GOOGLE_CLIENT_ID as string
    if (!id) return
    
    const scriptLoaded = () => {
      const w = window as any
      if (w.google && googleRef.current) {
        w.google.accounts.id.initialize({
          client_id: id,
          callback: async (r: any) => {
            try {
              setStatus('')
              const res = await apiPost('/auth/google', { idToken: r.credential })
              localStorage.setItem('token', res.token)
              setToken(res.token)
              setUser(res.user)
              setView('notes')
              loadNotes(res.token)
            } catch {
              setStatus('Google sign-in failed')
            }
          }
        })
        w.google.accounts.id.renderButton(googleRef.current, { theme: 'outline', size: 'large', shape: 'pill' })
      }
    }

    if ((window as any).google) {
      scriptLoaded()
    } else {
      window.addEventListener('load', scriptLoaded)
    }

  }, [])

  function logout() {
    localStorage.removeItem('token')
    setToken(null)
    setUser(null)
    setNotes([])
    setNewNote('')
    setView('auth')
  }

  async function sendOtp() {
    if (sendingOtp) return
    setSendingOtp(true)
    setStatus('')
    if (!validEmail || !validName) {
      setStatus('Enter a valid name and email')
      setSendingOtp(false)
      return
    }
    try {
      await apiPost('/auth/send-otp', { email })
      setOtpSent(true)
      setStatus('OTP sent')
    } catch (e: any) {
      setStatus(e?.error || 'Failed to send OTP')
      setSendingOtp(false)
    }
  }

  async function verifyOtp() {
    setStatus('')
    if (!validOtp) { setStatus('Enter a 6 digit OTP'); return }
    try {
      const r = await apiPost('/auth/verify-otp', { email, otp, name })
      localStorage.setItem('token', r.token)
      setToken(r.token)
      setUser(r.user)
      setView('notes')
      loadNotes(r.token)
    } catch (e: any) { setStatus(e?.error || 'Verification failed') }
  }

  async function loadNotes(t?: string) {
    const tk = t || token
    if (!tk) return
    try {
      const list = await apiGet('/notes', tk)
      setNotes(list)
    } catch (e: any) { setStatus('Failed to load notes') }
  }

  async function addNote() {
    setStatus('')
    if (!newNote.trim()) return
    try {
      const n = await apiPost('/notes', { content: newNote.trim() }, token || undefined)
      setNotes([n, ...notes])
      setNewNote('')
    } catch (e: any) { setStatus(e?.error || 'Failed to add') }
  }

  async function removeNote(id: string) {
    try { await apiDel('/notes/' + id, token || undefined); setNotes(notes.filter(n => n.id !== id)) } catch (e: any) { setStatus('Failed to delete') }
  }

  return (
    <div className="wrap">
      {view === 'auth' && (
        <div className="card">
          <h1>Welcome</h1>
          <p className="muted">Sign up with email and OTP or continue with Google</p>
          <div className="fields">
            <label>Name</label>
            <input value={name} onChange={e => setName(e.target.value)} placeholder="Your name" />
            <label>Email</label>
            <input value={email} onChange={e => setEmail(e.target.value)} placeholder="you@example.com" />
            {!otpSent && (<button onClick={sendOtp} disabled={!validEmail || !validName || sendingOtp} className="primary">{sendingOtp ? 'Sending...' : 'Send OTP'}</button>)}
            {otpSent && (
              <div className="otpArea">
                <label>Enter OTP</label>
                <input value={otp} onChange={e => setOtp(e.target.value)} placeholder="6 digits" maxLength={6} />
                <div style={{ display: 'flex', gap: 8 }}>
                  <button onClick={verifyOtp} disabled={!validOtp} className="primary">Verify</button>
                  {/*<button onClick={sendOtp} className="ghost">Resend</button>*/}
                </div>
              </div>
            )}
          </div>
          <div className="or"><span>or</span></div>
          <div ref={googleRef} className="gbox" />
          {status && <div className="status">{status}</div>}
          <div className="foot muted">By continuing you agree to the terms</div>
        </div>
      )}

      {view === 'notes' && user && (
        <div className="card">
          <div className="top">
            <div className="me">
              {user.picture ? <img src={user.picture} className="avatar" /> : <div className="avatar alt">{(user.name || user.email)[0].toUpperCase()}</div>}
              <div>
                <div className="hello">Hi {user.name || user.email}</div>
                <div className="muted small">{user.email}</div>
              </div>
            </div>
            <button onClick={logout} className="ghost">Logout</button>
          </div>

          <div className="composer">
            <textarea placeholder="Write a note" value={newNote} onChange={e => setNewNote(e.target.value)} />
            <button onClick={addNote} disabled={!newNote.trim()} className="primary">Add</button>
          </div>

          <div className="list">
            {notes.length === 0 && <div className="empty">No notes yet</div>}
            {notes.map(n => (
              <div key={n.id} className="note">
                <div className="content">{n.content}</div>
                <div className="meta">
                  <span>{new Date(n.createdAt).toLocaleString()}</span>
                  <button onClick={() => removeNote(n.id)} className="danger">Delete</button>
                </div>
              </div>
            ))}
          </div>
          {status && <div className="status">{status}</div>}
        </div>
      )}
    </div>
  )
}

ReactDOM.createRoot(document.getElementById('root')!).render(<App />)
