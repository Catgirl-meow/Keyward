// Chromium-only offscreen document: the service worker has no clipboard access.
const ta = document.createElement("textarea");
document.body.append(ta);

chrome.runtime.onMessage.addListener((msg, sender, respond) => {
  if (msg?.kw !== "offscreen" || sender.id !== chrome.runtime.id) return false;
  if (msg.op === "write") {
    ta.value = msg.text || " ";
    ta.select();
    document.execCommand("copy");
    ta.value = "";
    respond(true);
  } else if (msg.op === "read") {
    ta.value = "";
    ta.focus();
    document.execCommand("paste");
    respond(ta.value);
    ta.value = "";
  }
  return false;
});
