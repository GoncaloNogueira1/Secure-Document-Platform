document.addEventListener("DOMContentLoaded", () => {

  const params = new URLSearchParams(window.location.search);
  const title = params.get("uploaded");

  if (title)
  {
      const container = document.getElementById("flash-container");
      if (container)
      {
          const li = document.createElement("li");
          li.className = "flash success";

          li.textContent = `Document uploaded: ${title}`;

          container.appendChild(li);
      }
  }

  // File validation
  const fileInput = document.getElementById("document-input");
  const uploadBtn = document.getElementById("upload-btn");
  const fileError = document.getElementById("file-error");
  const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB

  if (fileInput) {
    fileInput.addEventListener("change", () => {
      const file = fileInput.files[0];
      if (!file) {
        fileError.style.display = "none";
        uploadBtn.disabled = true;
        return;
      }

      const isPdf = file.type === "application/pdf" || file.name.toLowerCase().endsWith(".pdf");

      if (!isPdf) {
        fileError.textContent = "Only PDF files are allowed.";
        fileError.style.display = "block";
        uploadBtn.disabled = true;
        return;
      }

      if (file.size > MAX_FILE_SIZE) {
        const sizeMB = (file.size / (1024 * 1024)).toFixed(2);
        fileError.textContent = `File too large: ${sizeMB} MB. Maximum allowed is 10 MB.`;
        fileError.style.display = "block";
        uploadBtn.disabled = true;
      } else {
        fileError.style.display = "none";
        uploadBtn.disabled = false;
      }
    });
  }

  const buttons = document.querySelectorAll(".details-btn");

  buttons.forEach(btn => {

    btn.addEventListener("click", () => {

      const title = btn.dataset.title;

      const details = document.getElementById("doc-details");
      const titleField = document.getElementById("doc-title");

      details.style.display = "block";

      renderTitle(title)

    });

  });

    function renderTitle(title) {
      const el = document.getElementById("doc-title");
      updateField(el, title);
    }

    function updateField(element, value) {
      element.textContent = "Title: " + value;
    }

});