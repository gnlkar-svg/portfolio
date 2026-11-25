// Every <form data-api="/api/..."> posts its fields as JSON and shows the answer.
// data-next="/page" goes there after success; a message for the next page travels in sessionStorage.
const notice = sessionStorage.getItem("notice");
if (notice) {
  sessionStorage.removeItem("notice");
  show(document.querySelector(".message"), notice, "ok");
}

function show(box, text, kind) {
  if (!box) return;
  box.textContent = text;
  box.className = `message ${kind}`;
  box.hidden = false;
}

for (const form of document.querySelectorAll("form[data-api]")) {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const box = form.querySelector(".message") || document.querySelector(".message");
    const button = form.querySelector("button[type=submit]");
    button.disabled = true;
    try {
      const body = Object.fromEntries(new FormData(form));
      const res = await fetch(form.dataset.api, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) return show(box, data.error || "Bir şeyler ters gitti.", "error");
      if (form.dataset.next) {
        if (data.message) sessionStorage.setItem("notice", data.message);
        location.href = form.dataset.next;
        return;
      }
      show(box, data.message || "Tamam.", "ok");
      if (form.dataset.clear !== undefined) form.reset();
    } catch {
      show(box, "Sunucuya ulaşılamadı. İnternet bağlantını kontrol et.", "error");
    } finally {
      button.disabled = false;
    }
  });
}
