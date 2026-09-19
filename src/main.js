const { invoke } = window.__TAURI__.core;

const $ = (id) => document.getElementById(id);
const key = $("key"), input = $("input"), output = $("output"), status = $("status"), copy = $("copy");

const MODES = {
  decrypt: {
    button: "Descifrar", input: "Texto cifrado", output: "Texto en claro",
    placeholder: "Base64, hex o iv:tag:ciphertext",
  },
  encrypt: {
    button: "Cifrar", input: "Texto en claro", output: "Texto cifrado",
    placeholder: "Texto a cifrar",
  },
};
let mode = "decrypt";

function reset() {
  output.value = "";
  copy.disabled = true;
  status.className = "";
  status.textContent = "";
}

document.querySelectorAll(".tab").forEach((tab) =>
  tab.addEventListener("click", () => {
    if (tab.dataset.mode === mode) return;
    // El resultado anterior pasa a ser la nueva entrada, para ir y volver fácilmente.
    if (output.value) input.value = output.value;
    mode = tab.dataset.mode;
    document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t === tab));
    const m = MODES[mode];
    $("go").textContent = m.button;
    $("input-label").textContent = m.input;
    $("output-label").textContent = m.output;
    input.placeholder = m.placeholder;
    $("format-row").hidden = mode !== "encrypt";
    reset();
  })
);

$("toggle").addEventListener("click", () => {
  const hidden = key.type === "password";
  key.type = hidden ? "text" : "password";
  $("toggle").textContent = hidden ? "Ocultar" : "Ver";
});

async function run() {
  reset();
  status.textContent = mode === "decrypt" ? "Descifrando…" : "Cifrando…";
  try {
    if (mode === "decrypt") {
      const res = await invoke("decrypt", { key: key.value, ciphertext: input.value });
      output.value = res.plaintext;
      status.textContent = `✓ ${res.method}`;
    } else {
      output.value = await invoke("encrypt", { key: key.value, plaintext: input.value, format: $("format").value });
      status.textContent = `✓ ${$("format").selectedOptions[0].text}`;
    }
    status.className = "ok";
    copy.disabled = false;
  } catch (err) {
    status.className = "err";
    status.textContent = `✗ ${err}`;
  }
}

$("go").addEventListener("click", run);
input.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) run();
});

copy.addEventListener("click", async () => {
  await navigator.clipboard.writeText(output.value);
  copy.textContent = "¡Copiado!";
  setTimeout(() => (copy.textContent = "Copiar"), 1200);
});
