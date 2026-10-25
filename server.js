
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const crypto = require("crypto");
const app = express();
const PORT = Number(process.env.PORT) || 3000;

if (!process.env.SESSION_SECRET) {
  console.error("Missing SESSION_SECRET in your .env file.");
  process.exit(1);
}

// Create required folders
const databaseFolder = path.join(__dirname, "database");
fs.mkdirSync(databaseFolder, { recursive: true });
const storageFolder = path.join(__dirname, "storage");
fs.mkdirSync(storageFolder, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: storageFolder,
    filename: (req, file, callback) => {
      callback(null, crypto.randomUUID());
    }
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, callback) => {
    const allowed = new Set([
      ".pdf", ".txt", ".png", ".jpg", ".jpeg"
    ]);

    if (!allowed.has(path.extname(file.originalname).toLowerCase())) {
      return callback(new Error("Unsupported file type."));
    }

    callback(null, true);
  }
});

// Database setup
const db = new Database(path.join(databaseFolder, "trustvault.db"));

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");


db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer'
      CHECK(role IN ('admin', 'owner', 'viewer')),
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    details TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    original_name TEXT NOT NULL,
    storage_name TEXT NOT NULL UNIQUE,
    mime_type TEXT NOT NULL,
    size INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS document_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL,
    viewer_id INTEGER NOT NULL,
    can_view INTEGER NOT NULL DEFAULT 1,
    can_download INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(document_id, viewer_id),
    FOREIGN KEY (document_id) REFERENCES documents(id),
    FOREIGN KEY (viewer_id) REFERENCES users(id)
  );
`);


// Create the initial admin or update its password from .env.
const adminEmail = process.env.ADMIN_EMAIL?.trim().toLowerCase();
const adminPassword = process.env.ADMIN_PASSWORD;

if (adminEmail && adminPassword) {
  const passwordHash = bcrypt.hashSync(adminPassword, 12);

  db.prepare(`
    INSERT INTO users (email, password_hash, role)
    VALUES (?, ?, 'admin')
    ON CONFLICT(email) DO UPDATE SET
      password_hash = excluded.password_hash,
      role = 'admin'
  `).run(adminEmail, passwordHash);

  console.log("Admin account created or password updated.");
}

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));

if (process.env.NODE_ENV === "production") {
  app.set("trust proxy", 1);
}

app.use(
  session({
    name: "trustvault.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "strict",
      secure: process.env.NODE_ENV === "production",
      maxAge: 30 * 60 * 1000
    }
  })
);

// Serve the frontend
app.use(express.static(path.join(__dirname, "public")));

function audit(userId, action, details = "") {
  db.prepare(`
    INSERT INTO audit_logs (user_id, action, details)
    VALUES (?, ?, ?)
  `).run(userId || null, action, details);
}

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: "Please log in first." });
  }

  next();
}

function requireAdmin(req, res, next) {
  if (req.session.user?.role !== "admin") {
    return res.status(403).json({ error: "Admin access required." });
  }

  next();
}

// Health check
app.get("/api/health", (req, res) => {
  res.json({
    status: "success",
    message: "TrustVault server is running"
  });
});
// Temporary API test
app.get("/api/test", (req, res) => {
  console.log("API TEST ROUTE HIT");
  res.json({ message: "API routes are working" });
});

// Current logged-in user
app.get("/api/me", requireLogin, (req, res) => {
  res.json({ user: req.session.user });
});

app.post("/api/login-check", (req, res) => {
  res.json({ message: "Login route system works" });
});

// Login
console.log("LOGIN ROUTE REGISTERED");
app.post("/api/login", (req, res, next) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const password = String(req.body?.password || "");

    if (
      !email ||
      email.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      !password ||
      password.length > 200
    ) {
      return res.status(400).json({
        error: "Enter a valid email and password."
      });
    }

    const user = db.prepare(`
      SELECT id, email, password_hash, role
      FROM users
      WHERE email = ?
    `).get(email);

    const passwordMatches =
      user && bcrypt.compareSync(password, user.password_hash);

    if (!passwordMatches) {
      audit(null, "LOGIN_FAILED", email);
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    // Regenerate the session to reduce session-fixation risk.
    req.session.regenerate((err) => {
      if (err) {
        return next(err);
      }

      req.session.user = {
        id: user.id,
        email: user.email,
        role: user.role
      };

      audit(user.id, "LOGIN_SUCCESS");

      req.session.save((saveError) => {
        if (saveError) {
          return next(saveError);
        }

        res.json({
          message: "Login successful.",
          user: req.session.user
        });
      });
    });
  } catch (err) {
    next(err);
  }
});

// Logout
app.post("/api/logout", requireLogin, (req, res, next) => {
  audit(req.session.user.id, "LOGOUT");

  req.session.destroy((err) => {
    if (err) {
      return next(err);
    }

    res.clearCookie("trustvault.sid", {
      httpOnly: true,
      sameSite: "strict",
      secure: process.env.NODE_ENV === "production"
    });

    res.json({ message: "Logged out successfully." });
  });
});

// Admin-only audit log access
app.get(
  "/api/admin/audit-logs",
  requireLogin,
  requireAdmin,
  (req, res, next) => {
    try {
      const logs = db.prepare(`
        SELECT audit_logs.id,
               users.email,
               audit_logs.action,
               audit_logs.details,
               audit_logs.created_at
        FROM audit_logs
        LEFT JOIN users ON users.id = audit_logs.user_id
        ORDER BY audit_logs.id DESC
        LIMIT 200
      `).all();

      res.json({ logs });
    } catch (err) {
      next(err);
    }
  }
);

function getDocumentAccess(documentId, userId) {
  const document = db.prepare(`
    SELECT * FROM documents WHERE id = ?
  `).get(documentId);

  if (!document) return { document: null, allowed: false, owner: false };

  const owner = document.owner_id === userId;

  const permission = db.prepare(`
    SELECT can_view, can_download, revoked
    FROM document_permissions
    WHERE document_id = ? AND viewer_id = ?
  `).get(documentId, userId);

  return {
    document,
    owner,
    allowed: owner || Boolean(permission && !permission.revoked && permission.can_view),
    canDownload: owner || Boolean(permission && !permission.revoked && permission.can_download)
  };
}

function documentMimeType(filename) {
  const extension = path.extname(filename).toLowerCase();
  const types = {
    ".pdf": "application/pdf",
    ".txt": "text/plain",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg"
  };
  return types[extension] || "application/octet-stream";
}

// Upload a document. Owners and admins may upload.
app.post("/api/documents", requireLogin, (req, res, next) => {
  if (!["admin", "owner"].includes(req.session.user.role)) {
    return res.status(403).json({ error: "Only owners can upload documents." });
  }

  upload.single("document")(req, res, (err) => {
    if (err) {
      return res.status(400).json({ error: err.message || "Upload failed." });
    }

    try {
      if (!req.file) {
        return res.status(400).json({ error: "Choose a document to upload." });
      }

      const result = db.prepare(`
        INSERT INTO documents
          (owner_id, original_name, storage_name, mime_type, size)
        VALUES (?, ?, ?, ?, ?)
      `).run(
        req.session.user.id,
        path.basename(req.file.originalname),
        req.file.filename,
        documentMimeType(req.file.originalname),
        req.file.size
      );

      audit(req.session.user.id, "DOCUMENT_UPLOADED", `Document ID: ${result.lastInsertRowid}`);

      res.status(201).json({
        message: "Document uploaded successfully.",
        documentId: result.lastInsertRowid
      });
    } catch (error) {
      if (req.file) fs.unlink(req.file.path, () => {});
      next(error);
    }
  });
});

// List documents owned by the user or shared with them.
app.get("/api/documents", requireLogin, (req, res, next) => {
  try {
    const documents = db.prepare(`
      SELECT d.id, d.original_name, d.size, d.created_at,
             d.owner_id, u.email AS owner_email,
             CASE WHEN d.owner_id = ? THEN 1 ELSE 0 END AS is_owner,
             COALESCE(p.can_view, 0) AS can_view,
             COALESCE(p.can_download, 0) AS can_download
      FROM documents d
      JOIN users u ON u.id = d.owner_id
      LEFT JOIN document_permissions p
        ON p.document_id = d.id AND p.viewer_id = ? AND p.revoked = 0
      WHERE d.owner_id = ? OR p.viewer_id = ?
      ORDER BY d.id DESC
    `).all(
      req.session.user.id,
      req.session.user.id,
      req.session.user.id,
      req.session.user.id
    );

    res.json({ documents });
  } catch (error) {
    next(error);
  }
});

// Share a document with an existing user by email.
app.post("/api/documents/:id/share", requireLogin, (req, res, next) => {
  try {
    const documentId = Number(req.params.id);
    const email = String(req.body?.email || "").trim().toLowerCase();
    const canDownload = req.body?.canDownload === true;

    const document = db.prepare(`
      SELECT id, owner_id FROM documents WHERE id = ?
    `).get(documentId);

    if (!document) {
      return res.status(404).json({ error: "Document not found." });
    }

    if (document.owner_id !== req.session.user.id) {
      return res.status(403).json({ error: "Only the document owner can share it." });
    }

    const viewer = db.prepare(`
      SELECT id, role FROM users WHERE email = ?
    `).get(email);

    if (!viewer || viewer.id === req.session.user.id) {
      return res.status(400).json({ error: "Enter another existing user's email." });
    }

    db.prepare(`
      INSERT INTO document_permissions
        (document_id, viewer_id, can_view, can_download, revoked)
      VALUES (?, ?, 1, ?, 0)
      ON CONFLICT(document_id, viewer_id) DO UPDATE SET
        can_view = 1,
        can_download = excluded.can_download,
        revoked = 0
    `).run(documentId, viewer.id, canDownload ? 1 : 0);

    audit(req.session.user.id, "DOCUMENT_SHARED", `Document ${documentId} shared with ${email}`);

    res.json({ message: "Document access granted." });
  } catch (error) {
    next(error);
  }
});

// Revoke a viewer's access.
app.post("/api/documents/:id/revoke", requireLogin, (req, res, next) => {
  try {
    const documentId = Number(req.params.id);
    const email = String(req.body?.email || "").trim().toLowerCase();

    const document = db.prepare(`
      SELECT id FROM documents
      WHERE id = ? AND owner_id = ?
    `).get(documentId, req.session.user.id);

    if (!document) {
      return res.status(404).json({ error: "Owned document not found." });
    }

    const viewer = db.prepare(`
      SELECT id FROM users WHERE email = ?
    `).get(email);

    if (!viewer) {
      return res.status(404).json({ error: "User not found." });
    }

    const result = db.prepare(`
      UPDATE document_permissions
      SET revoked = 1
      WHERE document_id = ? AND viewer_id = ?
    `).run(documentId, viewer.id);

    if (!result.changes) {
      return res.status(404).json({ error: "No sharing permission found for this user." });
    }

    audit(req.session.user.id, "ACCESS_REVOKED", `Document ${documentId}; viewer ${email}`);

    res.json({ message: "Document access revoked." });
  } catch (error) {
    next(error);
  }
});

// View a document only if access is currently allowed.
app.get("/api/documents/:id/view", requireLogin, (req, res, next) => {
  try {
    const access = getDocumentAccess(Number(req.params.id), req.session.user.id);

    if (!access.document) {
      return res.status(404).json({ error: "Document not found." });
    }

    if (!access.allowed) {
      audit(req.session.user.id, "DOCUMENT_ACCESS_DENIED", `Document ${req.params.id}`);
      return res.status(403).json({ error: "You do not have permission to view this document." });
    }

    audit(req.session.user.id, "DOCUMENT_VIEWED", `Document ${req.params.id}`);

    res.setHeader("X-Content-Type-Options", "nosniff");
    res.type(access.document.mime_type);
    res.setHeader("Content-Disposition", "inline");

    res.sendFile(
      path.join(storageFolder, access.document.storage_name),
      (error) => {
        if (error && !res.headersSent) next(error);
      }
    );
  } catch (error) {
    next(error);
  }
});

// Download only if the owner or an authorized viewer is permitted.
app.get("/api/documents/:id/download", requireLogin, (req, res, next) => {
  try {
    const access = getDocumentAccess(Number(req.params.id), req.session.user.id);

    if (!access.document) {
      return res.status(404).json({ error: "Document not found." });
    }

    if (!access.allowed || !access.canDownload) {
      audit(req.session.user.id, "DOWNLOAD_DENIED", `Document ${req.params.id}`);
      return res.status(403).json({ error: "Download permission is required." });
    }

    audit(req.session.user.id, "DOCUMENT_DOWNLOADED", `Document ${req.params.id}`);

    res.download(
      path.join(storageFolder, access.document.storage_name),
      access.document.original_name,
      (error) => {
        if (error && !res.headersSent) next(error);
      }
    );
  } catch (error) {
    next(error);
  }
});

// Return JSON for unknown API routes rather than an HTML page.
app.use("/api", (req, res) => {
  res.status(404).json({ error: "API endpoint not found." });
});

// Handle malformed JSON and other server errors.
app.use((err, req, res, next) => {
  console.error(err);

  if (res.headersSent) {
    return next(err);
  }

  if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
    return res.status(400).json({ error: "Invalid JSON request body." });
  }

  res.status(500).json({
    error: "An unexpected server error occurred."
  });
});


console.log("SERVER FILE:", __filename);


const server = app.listen(PORT, "127.0.0.1", () => {
  console.log(`TrustVault running at http://127.0.0.1:${PORT}`);
});

server.on("error", (err) => {
  console.error("Server error:", err.message);
});


// Close the database cleanly when the process stops.
function shutdown() {
  server.close(() => {
    db.close();
    process.exit(0);
  });
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);


