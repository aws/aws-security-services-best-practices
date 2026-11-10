// Adds an "Expand table" button to tables wrapped in <div class="expandable-table" markdown>
// and opens the table in a full-screen dialog.
function initExpandableTables() {
  document.querySelectorAll(".expandable-table").forEach(function (wrapper) {
    if (wrapper.dataset.expandReady) return;
    var table = wrapper.querySelector("table");
    if (!table) return;
    wrapper.dataset.expandReady = "true";

    var button = document.createElement("button");
    button.type = "button";
    button.className = "md-button expandable-table__button";
    button.textContent = "⤢ Expand table";
    wrapper.insertBefore(button, wrapper.firstChild);

    button.addEventListener("click", function () {
      var dialog = document.createElement("dialog");
      dialog.className = "expandable-table__dialog";

      var close = document.createElement("button");
      close.type = "button";
      close.className = "md-button expandable-table__close";
      close.textContent = "✕ Close";
      close.addEventListener("click", function () { dialog.close(); });

      var content = document.createElement("div");
      content.className = "md-typeset expandable-table__content";
      content.appendChild(table.cloneNode(true));
      content.querySelectorAll("a[href^='#']").forEach(function (link) {
        link.addEventListener("click", function () { dialog.close(); });
      });

      dialog.appendChild(close);
      dialog.appendChild(content);
      dialog.addEventListener("click", function (e) { if (e.target === dialog) dialog.close(); });
      dialog.addEventListener("close", function () { dialog.remove(); });
      document.body.appendChild(dialog);
      dialog.showModal();
    });
  });
}

if (typeof document$ !== "undefined") {
  document$.subscribe(initExpandableTables);
} else {
  document.addEventListener("DOMContentLoaded", initExpandableTables);
}
