# TrustVault — Secure Document Sharing

TrustVault is a secure document-sharing application designed to give users control over who can view and download their documents, with an audit trail of important actions.

## Features

- Session-based authentication
- Document uploads with a 5 MB size limit
- Document viewing and downloading
- Sharing with existing users by email
- Separate view and download permissions
- Access revocation
- Audit logging for security-related events
- Security headers using Helmet
- SQLite database storage

## Technology Stack

- Node.js
- Express.js
- SQLite and better-sqlite3
- HTML, CSS, and JavaScript
- Multer for file uploads
- bcryptjs for password hashing
- express-session for session management

## Setup

1. Install Node.js.
2. Clone this repository.
3. Install dependencies:

   `npm install`

4. Copy `.env.example` to `.env`.
5. Set a strong, unique `SESSION_SECRET`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD` in `.env`.
6. Start the application:

   `npm start`

7. Open `http://127.0.0.1:3000`.

## Security

- Passwords are hashed before storage.
- Document access is checked on the server.
- Only document owners can share or revoke access.
- Download permissions are enforced by the backend.
- Revoked viewers are denied access.
- Secrets, local databases, and uploaded files should not be committed to Git.

## Current Limitations

- Sharing requires the recipient to already have an account.
- File validation currently relies on filename extensions; content-level validation should be added before production use.
- Production deployment requires persistent database and file storage, secure session configuration, and HTTPS.

## Testing

Manually tested login, upload, listing, viewing, download restrictions, and access revocation. Automated tests remain to be added.

## Project Status

Challenge prototype. Further security hardening and automated testing are recommended before production use.