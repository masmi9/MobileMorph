document.addEventListener("DOMContentLoaded", function () {
  const apkName = window.location.pathname.split("/").pop();
  const fileToOpen = new URLSearchParams(window.location.search).get("file");
  const lineToScroll = parseInt(new URLSearchParams(window.location.search).get("line"));

  const fileList = document.getElementById("file-list");
  const sourceCode = document.getElementById("source-code");
  let selectedLines = new Set();

  function highlightLineDiv(lineDiv, lineNumber) {
    if (selectedLines.has(lineNumber)) {
      lineDiv.style.backgroundColor = "#1e1e1e";
      selectedLines.delete(lineNumber);
    } else {
      lineDiv.style.backgroundColor = "#333355";
      selectedLines.add(lineNumber);
    }
  }

  fetch(`/api/source/list?apk=${apkName}`)
    .then(res => res.json())
    .then(files => {
      files.forEach(f => {
        const li = document.createElement("li");
        li.textContent = f;
        li.style.cursor = "pointer";
        li.onclick = () => loadSourceFile(f, null);
        fileList.appendChild(li);
      });

      if (fileToOpen) {
        loadSourceFile(fileToOpen, lineToScroll);
      }
    });

  function loadSourceFile(filePath, highlightLine = null) {
    fetch(`/api/source/view?apk=${apkName}&path=${encodeURIComponent(filePath)}`)
      .then(res => res.json())
      .then(data => {
        if (!data.content) {
          sourceCode.textContent = "Failed to load file.";
          return;
        }

        selectedLines.clear();
        const lines = data.content.split("\n");
        let html = "";

        lines.forEach((line, idx) => {
          const lineNumber = idx + 1;
          const escapedLine = line.replace(/</g, "&lt;").replace(/>/g, "&gt;");
          const lineHTML = `<span class="line-number" style="color:#888888;">${lineNumber.toString().padStart(4)}:</span> ${escapedLine}`;
          html += `<div class="code-line" data-line="${lineNumber}" style="cursor:pointer;">${lineHTML}</div>`;
        });

        sourceCode.innerHTML = html;

        document.querySelectorAll(".code-line").forEach(div => {
          const lineNum = parseInt(div.dataset.line);
          if (highlightLine && lineNum === highlightLine) {
            div.style.backgroundColor = "#fff59d";
            div.scrollIntoView({ behavior: "smooth", block: "center" });
          }

          div.addEventListener("click", () => highlightLineDiv(div, lineNum));
        });
      });
  }

  document.getElementById("copy-selected").addEventListener("click", () => {
    const selectedText = Array.from(selectedLines)
      .sort((a, b) => a - b)
      .map(num => {
        const div = document.querySelector(`[data-line="${num}"]`);
        return div ? div.innerText : "";
      })
      .join("\n");

    navigator.clipboard.writeText(selectedText).then(() => {
      alert("Selected lines copied to clipboard!");
    });
  });

  document.getElementById("comment-selected").addEventListener("click", () => {
    const comment = prompt("Enter your comment for the selected lines:");
    if (!comment) return;

    selectedLines.forEach(num => {
      const div = document.querySelector(`[data-line="${num}"]`);
      if (div) {
        const note = document.createElement("span");
        note.textContent = " 💬 " + comment;
        note.style.color = "orange";
        note.style.marginLeft = "10px";
        div.appendChild(note);
      }
    });
  });
});
