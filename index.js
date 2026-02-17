// index.js
const express = require('express');
const session = require('express-session');
const cors = require('cors');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

const { USERNAME, PASSWORD, validateUser } = require('./user');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: "radhekrishna-secret",
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 24 * 60 * 60 * 1000 } // 1 day
}));

// Create uploads folder if missing
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

// Multer setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, file.originalname)
});
const upload = multer({ storage });

// ------------------- ROUTES ------------------- //

// Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (validateUser(username, password)) {
    req.session.user = username;
    return res.json({ success: true, message: "Login successful" });
  } else {
    return res.json({ success: false, message: "Invalid username or password" });
  }
});

// Middleware to protect routes
function requireLogin(req, res, next) {
  if (req.session.user === USERNAME) return next();
  res.status(401).json({ error: "Not authorized" });
}

// List files
app.get('/files', requireLogin, (req, res) => {
  fs.readdir(UPLOAD_DIR, (err, files) => {
    if (err) return res.status(500).json({ error: "Failed to list files" });
    res.json(files);
  });
});

// Upload file
app.post('/upload', requireLogin, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });
  res.json({ success: true, filename: req.file.originalname });
});

// Download file info
app.get('/file/:name', requireLogin, (req, res) => {
  const filePath = path.join(UPLOAD_DIR, req.params.name);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: "File not found" });
  res.json({ success: true, downloadUrl: `/download/${encodeURIComponent(req.params.name)}` });
});

// Serve file for download
app.get('/download/:name', requireLogin, (req, res) => {
  const filePath = path.join(UPLOAD_DIR, req.params.name);
  if (!fs.existsSync(filePath)) return res.status(404).send("File not found");
  res.download(filePath);
});

// Delete file
app.delete('/file/:name', requireLogin, (req, res) => {
  const filePath = path.join(UPLOAD_DIR, req.params.name);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: "File not found" });
  fs.unlink(filePath, err => {
    if (err) return res.status(500).json({ error: "Failed to delete file" });
    res.json({ success: true, message: "File deleted" });
  });
});

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true, message: "Logged out successfully" });
});

// Serve static frontend (optional)
app.use(express.static(path.join(__dirname, 'public')));

// Start server
app.listen(PORT, () => console.log(`Radhe Krishna backend running on port ${PORT}`));
