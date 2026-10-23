"use strict";
(() => {
  const live = document.createElement("p");
  live.className = "sr";
  live.setAttribute("role", "status");
  document.body.append(live);

  for (const el of document.querySelectorAll("[data-copy]")) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "copy";
    btn.textContent = "copy";
    btn.setAttribute("aria-label", "Copy " + (el.dataset.copy || "text"));
    btn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(el.textContent.trim());
        btn.dataset.state = "done";
        btn.textContent = "copied";
        live.textContent = "Copied to clipboard";
      } catch {
        btn.dataset.state = "fail";
        btn.textContent = "select";
        live.textContent = "Copy failed, select the text instead";
      }
      setTimeout(() => { delete btn.dataset.state; btn.textContent = "copy"; }, 1600);
    });
    el.after(btn);
  }

  const form = document.querySelector("form[data-removal]");
  if (!form) return;
  const msg = form.querySelector("[data-msg]");
  const submit = form.querySelector("button[type=submit]");
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    for (const f of form.querySelectorAll("[aria-invalid]")) f.removeAttribute("aria-invalid");
    submit.disabled = true;
    submit.textContent = "Sending";
    try {
      const res = await fetch(form.action, {
        method: "POST",
        headers: { accept: "application/json" },
        body: new URLSearchParams(new FormData(form)),
      });
      const data = await res.json();
      if (data.ok) {
        const done = document.createElement("div");
        done.className = "msg";
        done.setAttribute("tabindex", "-1");
        done.textContent = data.message;
        form.replaceWith(done);
        done.focus();
        return;
      }
      msg.hidden = false;
      msg.textContent = data.error;
      const field = data.field && form.elements.namedItem(data.field);
      if (field) { field.setAttribute("aria-invalid", "true"); field.focus(); }
    } catch {
      msg.hidden = false;
      msg.textContent = "Network error. Try again, or write to abuse@offseq.com.";
    }
    if (window.turnstile) window.turnstile.reset();
    submit.disabled = false;
    submit.textContent = "Send request";
  });
})();
