
import { useState } from 'react'
import './App.css'

function App() {
  const [isRegister, setIsRegister] = useState(false)
  const [isLoggedIn, setIsLoggedIn] = useState(false)

  const [documents, setDocuments] = useState([])
  const [selectedFile, setSelectedFile] = useState(null)

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [email, setEmail] = useState('')

  // LOGIN AND REGISTER
  const handleSubmit = async (e) => {
    e.preventDefault()

    try {
      if (isRegister) {
        const response = await fetch(
          'http://127.0.0.1:8000/register',
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              username,
              email,
              password,
              role: 'viewer',
            }),
          }
        )

        const data = await response.json()

        if (!response.ok) {
          alert(data.detail || 'Registration failed')
          return
        }

        alert('Registration successful! Please login.')

        setIsRegister(false)
        setUsername('')
        setPassword('')
        setEmail('')
      } else {
        const formData = new URLSearchParams()

        formData.append('username', username)
        formData.append('password', password)

        const response = await fetch(
          'http://127.0.0.1:8000/token',
          {
            method: 'POST',
            headers: {
              'Content-Type':
                'application/x-www-form-urlencoded',
            },
            body: formData,
          }
        )

        const data = await response.json()

        if (!response.ok) {
          alert(data.detail || 'Login failed')
          return
        }

        localStorage.setItem('token', data.access_token)

        setIsLoggedIn(true)

        // Load documents after login
        await fetchDocuments()
      }
    } catch (error) {
      alert('Backend connection failed. Please check your server.')
    }
  }

  // LOAD DOCUMENTS
  const fetchDocuments = async () => {
    try {
      const token = localStorage.getItem('token')

      const response = await fetch(
        'http://127.0.0.1:8000/documents',
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      )

      if (!response.ok) {
        alert('Failed to load documents')
        return
      }

      const data = await response.json()

      setDocuments(data)
    } catch (error) {
      alert('Error loading documents')
    }
  }

  // UPLOAD DOCUMENT
  const handleUpload = async () => {
    if (!selectedFile) {
      alert('Please select a file first')
      return
    }

    try {
      const token = localStorage.getItem('token')

      const formData = new FormData()

      formData.append('file', selectedFile)

      const response = await fetch(
        'http://127.0.0.1:8000/documents/upload',
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${token}`,
          },
          body: formData,
        }
      )

      const data = await response.json()

      if (!response.ok) {
        alert(data.detail || 'Upload failed')
        return
      }

      alert('Document uploaded successfully!')

      setSelectedFile(null)

      await fetchDocuments()
    } catch (error) {
      alert('Error uploading document')
    }
  }

  // DOWNLOAD DOCUMENT
  const handleDownload = async (doc) => {
    try {
      const token = localStorage.getItem('token')

      const response = await fetch(
        `http://127.0.0.1:8000/documents/${doc.id}/download`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      )

      if (!response.ok) {
        alert('Download failed')
        return
      }

      const blob = await response.blob()

      const url = window.URL.createObjectURL(blob)

      const link = document.createElement('a')

      link.href = url
      link.download = doc.filename

      document.body.appendChild(link)
      link.click()
      link.remove()

      window.URL.revokeObjectURL(url)
    } catch (error) {
      alert('Error downloading document')
    }
  }

  // DASHBOARD
  if (isLoggedIn) {
    return (
      <div className="app">
        <nav className="navbar">
          <h2>🛡️ DocuShield AI</h2>
          <span>Secure Document Dashboard</span>
        </nav>

        <main className="dashboard">
          <h1>Welcome to DocuShield AI</h1>

          <p>Your secure document workspace</p>

          {/* DOCUMENT SECTION */}
          <div className="documents-section">
            <h2>📁 My Documents</h2>

            <input
              type="file"
              onChange={(e) =>
                setSelectedFile(e.target.files[0] || null)
              }
            />

            <button
              className="primary"
              onClick={handleUpload}
            >
              Upload Document
            </button>

            <button
              className="secondary"
              onClick={fetchDocuments}
            >
              Load Documents
            </button>

            {/* DOCUMENT LIST */}
            {documents.length === 0 ? (
              <p>No documents found</p>
            ) : (
              documents.map((doc) => (
                <div
                  className="document-item"
                  key={doc.id}
                >
                  <h3>{doc.filename}</h3>

                  <button
                    className="primary"
                    onClick={() => handleDownload(doc)}
                  >
                    Download
                  </button>
                </div>
              ))
            )}
          </div>

          {/* DASHBOARD CARDS */}
          <div className="dashboard-cards">
            <div className="dashboard-card">
              <h3>📁 My Documents</h3>
              <p>Upload and manage your files</p>
            </div>

            <div className="dashboard-card">
              <h3>🔐 Shared Documents</h3>
              <p>Manage document permissions</p>
            </div>

            <div className="dashboard-card">
              <h3>📋 Audit Trail</h3>
              <p>Track document activities</p>
            </div>
          </div>

          {/* LOGOUT */}
          <button
            className="primary"
            onClick={() => {
              localStorage.removeItem('token')
              setIsLoggedIn(false)
              setDocuments([])
              setSelectedFile(null)
            }}
          >
            Logout
          </button>
        </main>
      </div>
    )
  }

  // LOGIN / REGISTER PAGE
  return (
    <div className="app">
      <nav className="navbar">
        <h2>🛡️ DocuShield AI</h2>
        <span>Secure Document Sharing</span>
      </nav>

      <main className="hero">
        <div className="hero-icon">🔐</div>

        <h1>
          {isRegister ? 'Create Account' : 'Welcome Back'}
        </h1>

        <p>
          Securely manage and share your documents.
        </p>

        <div className="form-heading">
          <h2>
            {isRegister
              ? 'Create your account'
              : 'Sign in to your account'}
          </h2>

          <p>
            {isRegister
              ? 'Join DocuShield AI and secure your documents'
              : 'Access your secure document workspace'}
          </p>
        </div>

        <form
          onSubmit={handleSubmit}
          className="login-form"
        >
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />

          {isRegister && (
            <input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          )}

          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />

          <button
            type="submit"
            className="primary"
          >
            {isRegister ? 'Register' : 'Login'}
          </button>
        </form>

        <p>
          {isRegister
            ? 'Already have an account?'
            : "Don't have an account?"}
        </p>

        <button
          className="secondary"
          onClick={() => setIsRegister(!isRegister)}
        >
          {isRegister ? 'Login' : 'Create Account'}
        </button>
      </main>
    </div>
  )
}

export default App
