document.addEventListener("DOMContentLoaded", function () {
  fetch(`/api/source/list?apk=${apkName}`)
    .then(res => res.json())
    .then(files => {
      const fileList = document.getElementById("file-list");
      files.forEach(f => {
        const li = document.createElement("li");
        li.textContent = f;
        li.style.cursor = "pointer";
        li.onclick = () => loadSourceFile(f);
        fileList.appendChild(li);
      });
    });

  function loadSourceFile(filePath) {
    fetch(`/api/source/view?apk=${apkName}&path=${encodeURIComponent(filePath)}`)
      .then(res => res.json())
      .then(data => {
        document.getElementById("source-code").textContent = data.content || "Error loading file.";
      });
  }
});
