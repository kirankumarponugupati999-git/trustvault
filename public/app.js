const loginForm = document.getElementById("login-form");
const loginSection = document.getElementById("login-card");
const dashboard = document.getElementById("dashboard");
const messageElement = document.getElementById("message");
const logoutButton = document.getElementById("logout-button");

async function api(url, options = {}) {
  const response = await fetch(url, {
    credentials: "same-origin",
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });

  const text = await response.text();
  let data;

  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(`Unexpected server response (HTTP ${response.status}).`);
  }

  if (!response.ok) {
    throw new Error(data.error || "Request failed.");
  }

  return data;
}

function showMessage(message, isError = true) {
  if (!messageElement) return;
  messageElement.textContent = message;
  messageElement.style.color = isError ? "#ff7070" : "#70e0a0";
}

function showDashboard(user) {
  loginSection.hidden = true;
  loginSection.classList.add("hidden");
  dashboard.hidden = false;
  dashboard.classList.remove("hidden");

  document.getElementById("user-info").textContent =
    `${user.email} (${user.role})`;

  document.getElementById("role-info").textContent =
    `Your role: ${user.role}`;

  const auditSection = document.getElementById("audit-section");
  auditSection.hidden = user.role !== "admin";

  if (user.role === "admin") loadAuditLogs();
  loadDocuments();
}

function showLogin() {
    loginSection.hidden = false;
    loginSection.classList.remove("hidden");
    dashboard.hidden = true;
    dashboard.classList.add("hidden");
  }

if (loginForm) {
  loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value;

    showMessage("Signing in...", false);

    try {
      const result = await api("/api/login", {
        method: "POST",
        body: JSON.stringify({ email, password })
      });

      loginForm.reset();
      showDashboard(result.user);
      showMessage("Login successful.", false);
    } catch (error) {
      showMessage(error.message);
      console.error("Login failed:", error);
    }
  });
}

if (logoutButton) {
  logoutButton.addEventListener("click", async () => {
    try {
      const result = await api("/api/logout", {
        method: "POST",
        body: JSON.stringify({})
      });

      showLogin();
      showMessage(result.message || "Logged out successfully.", false);
    } catch (error) {
      showMessage(error.message);
    }
  });
}

async function loadAuditLogs() {
  const auditList = document.getElementById("audit-list");

  try {
    const result = await api("/api/admin/audit-logs");
    auditList.replaceChildren();

    if (!result.logs || result.logs.length === 0) {
      auditList.textContent = "No audit events yet.";
      return;
    }

    for (const log of result.logs) {
      const item = document.createElement("li");
      item.textContent =
        `${log.created_at} — ${log.email || "Unknown user"} — ` +
        `${log.action}${log.details ? " — " + log.details : ""}`;
      auditList.appendChild(item);
    }
  } catch (error) {
    auditList.textContent = error.message;
    console.error("Audit logs failed:", error);
  }
}

async function checkSession() {
  try {
    const result = await api("/api/me");
    showDashboard(result.user);
  } catch {
    showLogin();
  }
}

checkSession();






const uploadForm = document.getElementById("upload-form");
const documentFile = document.getElementById("document-file");
const uploadMessage = document.getElementById("upload-message");
const documentList = document.getElementById("document-list");
const documentsMessage = document.getElementById("documents-message");
const refreshDocumentsButton = document.getElementById("refresh-documents");

async function loadDocuments() {
  if (!documentList) return;

  documentsMessage.textContent = "Loading documents...";
  documentList.replaceChildren();

  try {
    const result = await api("/api/documents");
    const documents = result.documents || [];

    if (documents.length === 0) {
      documentsMessage.textContent = "No documents uploaded yet.";
      return;
    }

    documentsMessage.textContent = "";

    for (const doc of documents) {
      const item = document.createElement("li");
      const name = document.createElement("strong");
      name.textContent = doc.original_name;
      item.appendChild(name);
      item.appendChild(document.createTextNode(` — ${doc.size} bytes `));

      const view = document.createElement("a");
      view.textContent = "View";
      view.href = `/api/documents/${doc.id}/view`;
      view.target = "_blank";
      view.rel = "noopener noreferrer";
      item.appendChild(view);

      if (doc.is_owner || doc.can_download) {
        const download = document.createElement("a");
        download.textContent = " Download";
        download.href = `/api/documents/${doc.id}/download`;
        download.style.marginLeft = "10px";
        item.appendChild(download);
      }

      documentList.appendChild(item);
    }
  } catch (error) {
    documentsMessage.textContent = error.message || "Could not load documents.";
  }
}

if (uploadForm) {
  uploadForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    if (!documentFile.files.length) {
      uploadMessage.textContent = "Choose a document first.";
      return;
    }

    const formData = new FormData();
    formData.append("document", documentFile.files[0]);
    uploadMessage.textContent = "Uploading...";

    try {
      const response = await fetch("/api/documents", {
        method: "POST",
        body: formData
      });

      const result = await response.json();
      if (!response.ok) throw new Error(result.error || result.message || "Upload failed.");

      uploadMessage.textContent = "Document uploaded successfully.";
      uploadForm.reset();
      await loadDocuments();
    } catch (error) {
      uploadMessage.textContent = error.message || "Upload failed.";
    }
  });
}

if (refreshDocumentsButton) {
  refreshDocumentsButton.addEventListener("click", loadDocuments);
}





const shareForm = document.getElementById("share-form");
const shareMessage = document.getElementById("share-message");
const revokeForm = document.getElementById("revoke-form");
const revokeMessage = document.getElementById("revoke-message");

if (shareForm) {
  shareForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const id = document.getElementById("share-document-id").value;
    const email = document.getElementById("share-email").value.trim();
    const canDownload = document.getElementById("share-can-download").checked;

    shareMessage.textContent = "Sharing...";

    try {
      const result = await api(`/api/documents/${id}/share`, {
        method: "POST",
        body: JSON.stringify({ email, canDownload })
      });

      shareMessage.textContent = result.message || "Access granted.";
      shareForm.reset();
      await loadDocuments();
    } catch (error) {
      shareMessage.textContent = error.message || "Sharing failed.";
    }
  });
}

if (revokeForm) {
  revokeForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const id = document.getElementById("revoke-document-id").value;
    const email = document.getElementById("revoke-email").value.trim();

    revokeMessage.textContent = "Revoking access...";

    try {
      const result = await api(`/api/documents/${id}/revoke`, {
        method: "POST",
        body: JSON.stringify({ email })
      });

      revokeMessage.textContent = result.message || "Access revoked.";
      revokeForm.reset();
      await loadDocuments();
    } catch (error) {
      revokeMessage.textContent = error.message || "Revocation failed.";
    }
  });
}
