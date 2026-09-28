// Frontend logic: talks to the FastAPI backend with fetch().
const API = "/api";

const $ = (id) => document.getElementById(id);
const form = $("student-form");
const fields = ["first_name", "last_name", "email", "department", "year"];

async function request(path, options = {}) {
  const res = await fetch(API + path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (res.status === 204) return null;
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = Array.isArray(body.detail)
      ? body.detail.map((d) => d.msg).join("; ")
      : body.detail || res.statusText;
    throw new Error(detail);
  }
  return body;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function showMessage(text, isError = false) {
  const el = $("form-message");
  el.textContent = text;
  el.className = "message " + (isError ? "error" : "success");
}

async function checkHealth() {
  try {
    await request("/health");
    $("api-status").textContent = "API online";
    $("api-status").classList.add("ok");
  } catch {
    $("api-status").textContent = "API offline";
    $("api-status").classList.add("down");
  }
}

async function loadStudents() {
  const q = $("search").value.trim();
  const students = await request("/students" + (q ? `?q=${encodeURIComponent(q)}` : ""));
  $("student-rows").innerHTML = students.length
    ? students.map((s) => `
      <tr>
        <td>${escapeHtml(s.first_name)} ${escapeHtml(s.last_name)}</td>
        <td>${escapeHtml(s.email)}</td>
        <td>${escapeHtml(s.department)}</td>
        <td>${s.year}</td>
        <td class="row-actions">
          <button class="link" data-action="transcript" data-id="${s.id}">Transcript</button>
          <button class="link" data-action="edit" data-id="${s.id}">Edit</button>
          <button class="link danger" data-action="delete" data-id="${s.id}">Delete</button>
        </td>
      </tr>`).join("")
    : `<tr><td colspan="5" class="empty">No students found</td></tr>`;
}

function resetForm() {
  form.reset();
  $("student-id").value = "";
  $("form-title").textContent = "Add student";
  $("submit-btn").textContent = "Add student";
  $("cancel-btn").hidden = true;
}

async function startEdit(id) {
  const s = await request(`/students/${id}`);
  $("student-id").value = s.id;
  fields.forEach((f) => ($(f).value = s[f]));
  $("form-title").textContent = `Edit ${s.first_name} ${s.last_name}`;
  $("submit-btn").textContent = "Save changes";
  $("cancel-btn").hidden = false;
  window.scrollTo({ top: 0, behavior: "smooth" });
}

async function showTranscript(id) {
  const t = await request(`/students/${id}/transcript`);
  $("transcript-title").textContent = `Transcript — ${t.student.first_name} ${t.student.last_name}`;
  $("transcript-rows").innerHTML = t.courses.length
    ? t.courses.map((c) => `
      <tr>
        <td>${escapeHtml(c.course_code)}</td>
        <td>${escapeHtml(c.course_title)}</td>
        <td>${c.credits}</td>
        <td>${c.score ?? "—"}</td>
        <td>${c.letter ?? "—"}</td>
      </tr>`).join("")
    : `<tr><td colspan="5" class="empty">No enrollments</td></tr>`;
  $("transcript-summary").innerHTML =
    `<strong>GPA:</strong> ${t.gpa ?? "—"} &nbsp; <strong>Credits:</strong> ${t.total_credits} &nbsp; <strong>Standing:</strong> ${escapeHtml(t.standing)}`;
  $("transcript-card").hidden = false;
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const payload = Object.fromEntries(fields.map((f) => [f, $(f).value]));
  payload.year = Number(payload.year);
  const id = $("student-id").value;
  try {
    if (id) {
      await request(`/students/${id}`, { method: "PUT", body: JSON.stringify(payload) });
      showMessage("Student updated");
    } else {
      await request("/students", { method: "POST", body: JSON.stringify(payload) });
      showMessage("Student added");
    }
    resetForm();
    await loadStudents();
  } catch (err) {
    showMessage(err.message, true);
  }
});

$("cancel-btn").addEventListener("click", resetForm);

$("student-rows").addEventListener("click", async (e) => {
  const btn = e.target.closest("button[data-action]");
  if (!btn) return;
  const id = btn.dataset.id;
  try {
    if (btn.dataset.action === "edit") await startEdit(id);
    if (btn.dataset.action === "transcript") await showTranscript(id);
    if (btn.dataset.action === "delete") {
      await request(`/students/${id}`, { method: "DELETE" });
      $("transcript-card").hidden = true;
      await loadStudents();
    }
  } catch (err) {
    showMessage(err.message, true);
  }
});

let searchTimer;
$("search").addEventListener("input", () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(loadStudents, 250);
});

checkHealth();
loadStudents();
