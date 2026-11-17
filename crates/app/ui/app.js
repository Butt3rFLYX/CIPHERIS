"use strict";

// CIPHERIS interface. Rules this file follows:
// * Text from the server or the user only ever goes into textContent, never
//   into HTML, so no input can turn into markup or script.
// * Keys and messages live only in variables and the visible page. Nothing is
//   written to localStorage, sessionStorage, cookies or the URL by this script.
// * A log row is added only after the server confirmed that step.

const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();
const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
const isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);

const limits = { maxPngBytes: 100 * 1024 * 1024, maxMessageBytes: 32768, warnRate: 0.05, idleMinutes: 6 };
const ENVELOPE_OVERHEAD = 4 + 148 + 2; // length prefix, envelope header and tag, inner schema

const state = {
  hide: { png: null, name: "image", slots: 0, maxBytes: 0, outUrl: null, busy: null },
  reveal: { png: null, busy: null },
};

// ---------- languages ----------
//
// German, Turkish and English. The language follows the browser or system
// language and can be switched in the title bar. The choice is kept only in
// memory, like everything else. Messages from the server arrive in English
// and are translated here; unknown texts are shown as they are.

const TEXTS = {
  en: {
    modeLabel: "Mode", langLabel: "Language",
    tabHide: "hide", tabReveal: "reveal",
    image: "image", message: "message", key: "key",
    dropImage: "Drop an image here",
    dropImageSub: "or click to choose one. Photos (JPEG, HEIC and others) are converted to PNG.",
    messagePlaceholder: "What should stay secret?",
    hideBtn: "hide message", hiding: "hiding …", cancel: "cancel",
    yourKey: "your key", keyHint: "shown once, never stored",
    copy: "copy", copied: "copied", saveImage: "save image", newMessage: "new message",
    noteSeparate: "Send image and key separately.",
    noteFile: "Send the image as a file (mail attachment, AirDrop, USB stick). Messengers compress photos and destroy the message. Clipboard managers may keep copied keys.",
    dropPng: "Drop the PNG here",
    dropPngSub: "or click to choose it. It must be the exact file CIPHERIS created.",
    keyHidden: "hidden while typing", show: "show", hide: "hide", typosDetected: "typos are detected",
    revealBtn: "reveal message", revealing: "revealing …", copyText: "copy text", clear: "clear",
    local: "local", offline: "offline", quit: "quit",
    chooseFirst: "choose an image first",
    tooSmall: "this image is too small; choose a larger one",
    bytesOf: "{n} / {max} bytes", tooLongForImage: ", too long for this image", usesOf: ", uses {p} of the image",
    fileTooLarge: "The file is larger than {mb} MB. Use a smaller image.",
    fileLarger100: "The file is larger than 100 MB.",
    convertedTooLarge: "The converted image is larger than 100 MB. Use a smaller one.",
    readingImage: "reading image", convertedToPng: ", converted to PNG",
    roomFor: "room for {n} bytes", tooSmallForMessage: "too small for a message",
    imageLoaded: "image loaded", imageLoadedVal: "{w} × {h} px, {s} slots",
    working: "working",
    keyGenerated: "key generated", keyGeneratedVal: "128 bit from the system random source",
    encrypted: "encrypted", encryptedVal: "Argon2id + XChaCha20 Poly1305, {n} bytes",
    embedded: "embedded", embeddedVal: "{bits} bits, {p} of slots",
    pngWritten: "png written", metadataRemoved: "metadata removed",
    rateWarning: "The message uses {p} of the image. A larger image or shorter text is harder to detect.",
    cancelledNothingSaved: "cancelled, nothing was saved", cancelled: "cancelled",
    exactPng: "Use the exact PNG file CIPHERIS created. Photos and converted copies no longer contain the message.",
    keyChecked: "key checked", checksumMatches: "checksum matches",
    decrypted: "decrypted", decryptedVal: "authenticity confirmed, {n} bytes",
    stopped: "CIPHERIS has stopped. You can close this tab.",
    limits: "Up to {mb} MB and {mp} megapixels.",
    idleCloses: "closes {m} min after the last tab", staysOpen: "stays open until you quit",
    notRunning: "CIPHERIS is not running anymore. Start it again.",
    sessionEnded: "This session has ended. Start CIPHERIS again.",
    requestFailed: "Request failed ({s}).",
    cannotRead: "This image cannot be read. Use a PNG or JPEG file.",
    convertFailed: "The image could not be converted.",
    busy: "CIPHERIS is busy with another image. Try again in a moment.",
    malformed: "The request was malformed. Reload the page.",
    notText: "The message is not valid text.",
    otherSites: "Requests from other sites are refused.",
    unsupportedImage: "This image cannot be read. Use a PNG or JPEG file; other formats are converted automatically when hiding.",
    imageTooLarge: "The image is larger than 40 megapixels or 100 MB. Use a smaller one.",
    emptyMessage: "Type a message first.",
    messageTooLong: "The message is too long for this image (at most {n} bytes). Use a larger image or shorten the text.",
    invalidKey: "This key contains a typo. Check it character by character.",
    notFound: "No message found: the key does not match, or the image was changed (for example compressed by a messenger).",
    internal: "Something went wrong inside CIPHERIS. Nothing was saved. Try again.",
  },
  de: {
    modeLabel: "Modus", langLabel: "Sprache",
    tabHide: "verstecken", tabReveal: "auslesen",
    image: "bild", message: "nachricht", key: "schlüssel",
    dropImage: "Bild hierher ziehen",
    dropImageSub: "oder klicken, um eines auszuwählen. Fotos (JPEG, HEIC und andere) werden in PNG umgewandelt.",
    messagePlaceholder: "Was soll geheim bleiben?",
    hideBtn: "nachricht verstecken", hiding: "verstecke …", cancel: "abbrechen",
    yourKey: "dein schlüssel", keyHint: "wird nur einmal angezeigt, nie gespeichert",
    copy: "kopieren", copied: "kopiert", saveImage: "bild speichern", newMessage: "neue nachricht",
    noteSeparate: "Bild und Schlüssel getrennt verschicken.",
    noteFile: "Verschicke das Bild als Datei (Mail-Anhang, AirDrop, USB-Stick). Messenger komprimieren Fotos und zerstören dabei die Nachricht. Zwischenablage-Manager können kopierte Schlüssel speichern.",
    dropPng: "PNG hierher ziehen",
    dropPngSub: "oder klicken, um sie auszuwählen. Es muss genau die Datei sein, die CIPHERIS erstellt hat.",
    keyHidden: "beim Tippen verborgen", show: "anzeigen", hide: "verbergen", typosDetected: "Tippfehler werden erkannt",
    revealBtn: "nachricht auslesen", revealing: "lese aus …", copyText: "text kopieren", clear: "löschen",
    local: "lokal", offline: "offline", quit: "beenden",
    chooseFirst: "zuerst ein Bild wählen",
    tooSmall: "dieses Bild ist zu klein; wähle ein größeres",
    bytesOf: "{n} / {max} Bytes", tooLongForImage: ", zu lang für dieses Bild", usesOf: ", nutzt {p} des Bildes",
    fileTooLarge: "Die Datei ist größer als {mb} MB. Nimm ein kleineres Bild.",
    fileLarger100: "Die Datei ist größer als 100 MB.",
    convertedTooLarge: "Das umgewandelte Bild ist größer als 100 MB. Nimm ein kleineres.",
    readingImage: "lese bild", convertedToPng: ", in PNG umgewandelt",
    roomFor: "Platz für {n} Bytes", tooSmallForMessage: "zu klein für eine Nachricht",
    imageLoaded: "bild geladen", imageLoadedVal: "{w} × {h} px, {s} Plätze",
    working: "arbeite",
    keyGenerated: "schlüssel erzeugt", keyGeneratedVal: "128 Bit aus der Zufallsquelle des Systems",
    encrypted: "verschlüsselt", encryptedVal: "Argon2id + XChaCha20 Poly1305, {n} Bytes",
    embedded: "eingebettet", embeddedVal: "{bits} Bit, {p} der Plätze",
    pngWritten: "png geschrieben", metadataRemoved: "Metadaten entfernt",
    rateWarning: "Die Nachricht nutzt {p} des Bildes. Mit einem größeren Bild oder kürzerem Text ist sie schwerer zu entdecken.",
    cancelledNothingSaved: "abgebrochen, nichts wurde gespeichert", cancelled: "abgebrochen",
    exactPng: "Nimm genau die PNG-Datei, die CIPHERIS erstellt hat. Fotos und umgewandelte Kopien enthalten die Nachricht nicht mehr.",
    keyChecked: "schlüssel geprüft", checksumMatches: "Prüfsumme stimmt",
    decrypted: "entschlüsselt", decryptedVal: "Echtheit bestätigt, {n} Bytes",
    stopped: "CIPHERIS wurde beendet. Du kannst diesen Tab schließen.",
    limits: "Bis {mb} MB und {mp} Megapixel.",
    idleCloses: "schließt {m} Min. nach dem letzten Tab", staysOpen: "bleibt offen, bis du beendest",
    notRunning: "CIPHERIS läuft nicht mehr. Starte es neu.",
    sessionEnded: "Diese Sitzung ist beendet. Starte CIPHERIS neu.",
    requestFailed: "Anfrage fehlgeschlagen ({s}).",
    cannotRead: "Dieses Bild kann nicht gelesen werden. Nimm eine PNG- oder JPEG-Datei.",
    convertFailed: "Das Bild konnte nicht umgewandelt werden.",
    busy: "CIPHERIS bearbeitet gerade ein anderes Bild. Versuch es gleich noch einmal.",
    malformed: "Die Anfrage war fehlerhaft. Lade die Seite neu.",
    notText: "Die Nachricht ist kein gültiger Text.",
    otherSites: "Anfragen von anderen Websites werden abgelehnt.",
    unsupportedImage: "Dieses Bild kann nicht gelesen werden. Nimm eine PNG- oder JPEG-Datei; andere Formate werden beim Verstecken automatisch umgewandelt.",
    imageTooLarge: "Das Bild ist größer als 40 Megapixel oder 100 MB. Nimm ein kleineres.",
    emptyMessage: "Gib zuerst eine Nachricht ein.",
    messageTooLong: "Die Nachricht ist zu lang für dieses Bild (höchstens {n} Bytes). Nimm ein größeres Bild oder kürze den Text.",
    invalidKey: "Dieser Schlüssel enthält einen Tippfehler. Prüfe ihn Zeichen für Zeichen.",
    notFound: "Keine Nachricht gefunden: Der Schlüssel passt nicht, oder das Bild wurde verändert (zum Beispiel von einem Messenger komprimiert).",
    internal: "In CIPHERIS ist etwas schiefgelaufen. Es wurde nichts gespeichert. Versuch es noch einmal.",
  },
  tr: {
    modeLabel: "Mod", langLabel: "Dil",
    tabHide: "gizle", tabReveal: "çöz",
    image: "görsel", message: "mesaj", key: "anahtar",
    dropImage: "Görseli buraya sürükleyin",
    dropImageSub: "ya da seçmek için tıklayın. Fotoğraflar (JPEG, HEIC ve diğerleri) PNG'ye dönüştürülür.",
    messagePlaceholder: "Ne gizli kalmalı?",
    hideBtn: "mesajı gizle", hiding: "gizleniyor …", cancel: "iptal",
    yourKey: "anahtarınız", keyHint: "yalnızca bir kez gösterilir, asla kaydedilmez",
    copy: "kopyala", copied: "kopyalandı", saveImage: "görseli kaydet", newMessage: "yeni mesaj",
    noteSeparate: "Görseli ve anahtarı ayrı ayrı gönderin.",
    noteFile: "Görseli dosya olarak gönderin (e-posta eki, AirDrop, USB bellek). Mesajlaşma uygulamaları fotoğrafları sıkıştırır ve mesajı yok eder. Pano yöneticileri kopyalanan anahtarları saklayabilir.",
    dropPng: "PNG dosyasını buraya sürükleyin",
    dropPngSub: "ya da seçmek için tıklayın. CIPHERIS'in oluşturduğu dosyanın kendisi olmalıdır.",
    keyHidden: "yazarken gizlenir", show: "göster", hide: "gizle", typosDetected: "yazım hataları algılanır",
    revealBtn: "mesajı çöz", revealing: "çözülüyor …", copyText: "metni kopyala", clear: "temizle",
    local: "yerel", offline: "çevrimdışı", quit: "kapat",
    chooseFirst: "önce bir görsel seçin",
    tooSmall: "bu görsel çok küçük; daha büyük bir görsel seçin",
    bytesOf: "{n} / {max} bayt", tooLongForImage: ", bu görsel için çok uzun", usesOf: ", görselin {p} kadarını kullanıyor",
    fileTooLarge: "Dosya {mb} MB'tan büyük. Daha küçük bir görsel kullanın.",
    fileLarger100: "Dosya 100 MB'tan büyük.",
    convertedTooLarge: "Dönüştürülen görsel 100 MB'tan büyük. Daha küçük bir görsel kullanın.",
    readingImage: "görsel okunuyor", convertedToPng: ", PNG'ye dönüştürüldü",
    roomFor: "{n} bayt için yer var", tooSmallForMessage: "mesaj için çok küçük",
    imageLoaded: "görsel yüklendi", imageLoadedVal: "{w} × {h} px, {s} yuva",
    working: "çalışıyor",
    keyGenerated: "anahtar oluşturuldu", keyGeneratedVal: "sistemin rastgele sayı kaynağından 128 bit",
    encrypted: "şifrelendi", encryptedVal: "Argon2id + XChaCha20 Poly1305, {n} bayt",
    embedded: "gömüldü", embeddedVal: "{bits} bit, yuvaların {p} kadarı",
    pngWritten: "png yazıldı", metadataRemoved: "meta veriler kaldırıldı",
    rateWarning: "Mesaj görselin {p} kadarını kullanıyor. Daha büyük bir görsel ya da daha kısa bir metin daha zor fark edilir.",
    cancelledNothingSaved: "iptal edildi, hiçbir şey kaydedilmedi", cancelled: "iptal edildi",
    exactPng: "CIPHERIS'in oluşturduğu PNG dosyasının kendisini kullanın. Fotoğraflar ve dönüştürülmüş kopyalar mesajı artık içermez.",
    keyChecked: "anahtar kontrol edildi", checksumMatches: "sağlama toplamı eşleşiyor",
    decrypted: "şifre çözüldü", decryptedVal: "orijinallik doğrulandı, {n} bayt",
    stopped: "CIPHERIS kapatıldı. Bu sekmeyi kapatabilirsiniz.",
    limits: "En fazla {mb} MB ve {mp} megapiksel.",
    idleCloses: "son sekmeden {m} dk sonra kapanır", staysOpen: "siz kapatana kadar açık kalır",
    notRunning: "CIPHERIS artık çalışmıyor. Yeniden başlatın.",
    sessionEnded: "Bu oturum sona erdi. CIPHERIS'i yeniden başlatın.",
    requestFailed: "İstek başarısız oldu ({s}).",
    cannotRead: "Bu görsel okunamıyor. PNG ya da JPEG dosyası kullanın.",
    convertFailed: "Görsel dönüştürülemedi.",
    busy: "CIPHERIS şu anda başka bir görselle meşgul. Birazdan tekrar deneyin.",
    malformed: "İstek hatalıydı. Sayfayı yeniden yükleyin.",
    notText: "Mesaj geçerli bir metin değil.",
    otherSites: "Başka sitelerden gelen istekler reddedilir.",
    unsupportedImage: "Bu görsel okunamıyor. PNG ya da JPEG dosyası kullanın; diğer biçimler gizleme sırasında otomatik olarak dönüştürülür.",
    imageTooLarge: "Görsel 40 megapikselden ya da 100 MB'tan büyük. Daha küçük bir görsel kullanın.",
    emptyMessage: "Önce bir mesaj yazın.",
    messageTooLong: "Mesaj bu görsel için çok uzun (en fazla {n} bayt). Daha büyük bir görsel kullanın ya da metni kısaltın.",
    invalidKey: "Bu anahtarda bir yazım hatası var. Karakter karakter kontrol edin.",
    notFound: "Mesaj bulunamadı: anahtar eşleşmiyor ya da görsel değiştirilmiş (örneğin bir mesajlaşma uygulaması tarafından sıkıştırılmış).",
    internal: "CIPHERIS içinde bir sorun oluştu. Hiçbir şey kaydedilmedi. Tekrar deneyin.",
  },
};

function detectLang() {
  for (const l of navigator.languages || [navigator.language || ""]) {
    const base = String(l).toLowerCase().split("-")[0];
    if (base in TEXTS) return base;
  }
  return "en";
}

let lang = detectLang();

/** Text for `key` in the current language, with {name} placeholders filled. */
function t(key, vars) {
  const s = TEXTS[lang][key] ?? TEXTS.en[key] ?? key;
  return vars ? s.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m)) : s;
}

// Exact English texts the server can send, mapped to their keys.
const SERVER_TEXTS = new Map(
  ["busy", "malformed", "notText", "fileLarger100", "otherSites", "sessionEnded",
   "unsupportedImage", "imageTooLarge", "emptyMessage", "invalidKey", "notFound", "internal"]
    .map((k) => [TEXTS.en[k], k]),
);

/** Translates a message from the server; unknown texts stay as they are. */
function fromServer(text) {
  const k = SERVER_TEXTS.get(text);
  if (k) return t(k);
  const m = /^The message is too long for this image \(at most (\d+) bytes\)/.exec(text);
  if (m) return t("messageTooLong", { n: fmt(m[1]) });
  return text;
}

// ---------- small helpers ----------

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function fmt(n) {
  const v = Number(n);
  return v < 10000 ? String(v) : v.toLocaleString("en-US").replace(/,/g, " ");
}

function pct(rate) {
  const v = rate * 100;
  const s = v < 0.01 && v > 0 ? "< 0.01" : v.toFixed(v < 10 ? 2 : 1);
  return (lang === "en" ? s : s.replace(".", ",")) + " %";
}

function clock() {
  return new Date().toTimeString().slice(0, 8);
}

/** Adds one row to a process log: tag is "ok", "error", "warn" or "…". */
function logRow(logId, tag, step, value) {
  const log = $(logId);
  log.hidden = false;
  const row = el("div", "row" + (tag === "error" ? " error" : tag === "warn" ? " warn" : ""));
  row.append(el("span", "t", clock()), el("span", "tag", tag));
  if (step) row.append(el("span", "lab", step));
  row.append(el("span", "val", value || ""));
  log.append(row);
  return row;
}

/** Prints several rows one after another, like a terminal (60 ms apart). */
async function logRows(logId, rows) {
  for (const r of rows) {
    logRow(logId, ...r);
    if (!reduceMotion.matches) await new Promise((res) => setTimeout(res, 60));
  }
}

function clearLog(logId) {
  const log = $(logId);
  log.replaceChildren();
  log.hidden = true;
}

const SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏";
function spinner(logId, label) {
  const row = logRow(logId, SPIN[0], label, "");
  row.classList.add("spin");
  let i = 0;
  const timer = reduceMotion.matches
    ? (row.querySelector(".tag").textContent = "…", null)
    : setInterval(() => (row.querySelector(".tag").textContent = SPIN[++i % SPIN.length]), 80);
  return () => {
    if (timer) clearInterval(timer);
    row.remove();
  };
}

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function api(path, body, signal) {
  let res;
  try {
    res = await fetch(path, {
      method: "POST",
      headers: { "X-Cipheris": "1", "Content-Type": "application/octet-stream" },
      body: body || new Uint8Array(),
      credentials: "same-origin",
      cache: "no-store",
      signal,
    });
  } catch (e) {
    if (e.name === "AbortError") throw e;
    throw new ApiError(t("notRunning"), 0);
  }
  if (res.status === 401) {
    sessionEnded(t("sessionEnded"));
    throw new ApiError(t("sessionEnded"), 401);
  }
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new ApiError(text ? fromServer(text) : t("requestFailed", { s: res.status }), res.status);
  }
  return res;
}

function packed(field, image) {
  const out = new Uint8Array(4 + field.length + image.byteLength);
  new DataView(out.buffer).setUint32(0, field.length, false);
  out.set(field, 4);
  out.set(new Uint8Array(image), 4 + field.length);
  return out;
}

function isPng(buf) {
  const sig = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  const b = new Uint8Array(buf, 0, Math.min(8, buf.byteLength));
  return sig.every((v, i) => b[i] === v);
}

/** Any image the browser can display, as PNG bytes with orientation applied. */
async function toPng(file) {
  const raw = await file.arrayBuffer();
  if (isPng(raw)) return { png: raw, converted: false };
  let bitmap;
  try {
    bitmap = await createImageBitmap(file, { imageOrientation: "from-image" });
  } catch {
    throw new ApiError(t("cannotRead"), 422);
  }
  const canvas = document.createElement("canvas");
  canvas.width = bitmap.width;
  canvas.height = bitmap.height;
  canvas.getContext("2d").drawImage(bitmap, 0, 0);
  bitmap.close();
  const blob = await new Promise((r) => canvas.toBlob(r, "image/png"));
  canvas.width = canvas.height = 0;
  if (!blob) throw new ApiError(t("convertFailed"), 422);
  return { png: await blob.arrayBuffer(), converted: true };
}

function baseName(name) {
  const b = (name || "image").replace(/\.[^.]+$/, "").replace(/[^\p{L}\p{N}_ ]+/gu, "_").trim().slice(0, 60);
  return b || "image";
}

function showFile(dropId, bytes, lines) {
  const drop = $(dropId);
  const img = drop.querySelector(".thumb");
  if (img.dataset.url) URL.revokeObjectURL(img.dataset.url);
  const url = URL.createObjectURL(new Blob([bytes], { type: "image/png" }));
  img.src = url;
  img.dataset.url = url;
  drop.querySelector(".meta").textContent = lines.join("\n");
  drop.classList.add("filled");
}

function resetFile(dropId) {
  const drop = $(dropId);
  drop.classList.remove("filled");
  const img = drop.querySelector(".thumb");
  if (img.dataset.url) URL.revokeObjectURL(img.dataset.url);
  img.removeAttribute("src");
  delete img.dataset.url;
}

function wireDrop(dropId, inputId, onFile) {
  const drop = $(dropId);
  const input = $(inputId);
  input.addEventListener("change", () => {
    if (input.files[0]) onFile(input.files[0]);
    input.value = "";
  });
  drop.addEventListener("dragover", (e) => {
    e.preventDefault();
    drop.classList.add("over");
  });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", (e) => {
    e.preventDefault();
    drop.classList.remove("over");
    const f = e.dataTransfer.files[0];
    if (f) onFile(f);
  });
}

async function copyText(text, button) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = el("textarea");
    ta.value = text;
    document.body.append(ta);
    ta.select();
    document.execCommand("copy");
    ta.value = "";
    ta.remove();
  }
  const key = button.dataset.i18n;
  button.textContent = t("copied");
  setTimeout(() => (button.textContent = t(key)), 1500);
}

function sessionEnded(msg) {
  const e = $("ended");
  e.textContent = msg;
  e.hidden = false;
  for (const b of document.querySelectorAll("button, textarea, input")) {
    if (b.id !== "quit" && !b.dataset.lang) b.disabled = true;
  }
}

// ---------- tabs ----------

function selectTab(which) {
  for (const t of ["hide", "reveal"]) {
    const on = t === which;
    $(`tab-${t}`).setAttribute("aria-selected", String(on));
    $(`tab-${t}`).tabIndex = on ? 0 : -1;
    $(`panel-${t}`).hidden = !on;
  }
}
$("tab-hide").addEventListener("click", () => selectTab("hide"));
$("tab-reveal").addEventListener("click", () => selectTab("reveal"));
document.querySelector(".modes").addEventListener("keydown", (e) => {
  if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
    const next = $("tab-hide").getAttribute("aria-selected") === "true" ? "reveal" : "hide";
    selectTab(next);
    $(`tab-${next}`).focus();
  }
});

// ---------- hide ----------

function updateMeter() {
  const bytes = enc.encode($("hide-text").value).length;
  const h = state.hide;
  const meter = $("hide-meter");
  const cells = meter.querySelector(".cells");
  const count = meter.querySelector(".count");
  cells.replaceChildren();
  meter.classList.remove("warn", "over");
  if (!h.png) {
    count.textContent = t("chooseFirst");
    $("hide-go").disabled = true;
    return;
  }
  if (h.maxBytes === 0) {
    count.textContent = t("tooSmall");
    meter.classList.add("over");
    $("hide-go").disabled = true;
    return;
  }
  const filled = bytes === 0 ? 0 : Math.max(1, Math.min(20, Math.ceil((bytes / h.maxBytes) * 20)));
  cells.append("▮".repeat(filled));
  cells.append(el("i", "", "▯".repeat(20 - filled)));
  const rate = bytes ? ((bytes + ENVELOPE_OVERHEAD) * 8) / h.slots : 0;
  count.textContent = t("bytesOf", { n: fmt(bytes), max: fmt(h.maxBytes) });
  if (bytes > h.maxBytes) {
    meter.classList.add("over");
    count.textContent += t("tooLongForImage");
  } else if (rate > limits.warnRate) {
    meter.classList.add("warn");
    count.textContent += t("usesOf", { p: pct(rate) });
  }
  $("hide-go").disabled = bytes === 0 || bytes > h.maxBytes || !!h.busy;
}

wireDrop("hide-drop", "hide-file", async (file) => {
  if (state.hide.busy) return;
  clearLog("hide-log");
  $("hide-result").hidden = true;
  if (file.size > limits.maxPngBytes) {
    logRow("hide-log", "error", "", t("fileTooLarge", { mb: fmt(limits.maxPngBytes / 1048576) }));
    return;
  }
  const stop = spinner("hide-log", t("readingImage"));
  try {
    const { png, converted } = await toPng(file);
    if (png.byteLength > limits.maxPngBytes) throw new ApiError(t("convertedTooLarge"), 413);
    const cap = await (await api("/api/capacity", png)).json();
    Object.assign(state.hide, { png, name: baseName(file.name), slots: cap.slots, maxBytes: cap.maxBytes });
    stop();
    showFile("hide-drop", png, [
      file.name,
      `${fmt(cap.width)} × ${fmt(cap.height)} px${converted ? t("convertedToPng") : ""}`,
      cap.maxBytes ? t("roomFor", { n: fmt(cap.maxBytes) }) : t("tooSmallForMessage"),
    ]);
    logRow("hide-log", "ok", t("imageLoaded"), t("imageLoadedVal", { w: fmt(cap.width), h: fmt(cap.height), s: fmt(cap.slots) }));
    $("hide-text").disabled = false;
    $("hide-text").focus();
  } catch (e) {
    stop();
    state.hide.png = null;
    resetFile("hide-drop");
    logRow("hide-log", "error", "", e.message);
  } finally {
    updateMeter();
  }
});

$("hide-text").addEventListener("input", updateMeter);
$("hide-text").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.metaKey || e.ctrlKey) && !$("hide-go").disabled) {
    e.preventDefault();
    $("hide-go").click();
  }
});
$("hide-kbd").textContent = isMac ? "⌘ ⏎" : "Ctrl ⏎";

$("hide-go").addEventListener("click", async () => {
  const h = state.hide;
  if (!h.png || h.busy) return;
  const message = $("hide-text").value;
  const controller = new AbortController();
  h.busy = controller;
  $("hide-go").disabled = true;
  setLabel("hide-go", "hiding");
  $("hide-cancel").hidden = false;
  $("hide-result").hidden = true;
  const stop = spinner("hide-log", t("working"));
  try {
    const res = await api("/api/hide", packed(enc.encode(message), h.png), controller.signal);
    const blob = await res.blob();
    const key = res.headers.get("X-Cipheris-Key") || "";
    const envBytes = Number(res.headers.get("X-Cipheris-Envelope-Bytes"));
    const bits = Number(res.headers.get("X-Cipheris-Bits"));
    const rate = Number(res.headers.get("X-Cipheris-Rate-Ppm")) / 1e6;
    stop();
    await logRows("hide-log", [
      ["ok", t("keyGenerated"), t("keyGeneratedVal")],
      ["ok", t("encrypted"), t("encryptedVal", { n: fmt(envBytes) })],
      ["ok", t("embedded"), t("embeddedVal", { bits: fmt(bits), p: pct(rate) })],
      ["ok", t("pngWritten"), t("metadataRemoved")],
    ]);
    if (rate > limits.warnRate) {
      logRow("hide-log", "warn", "", t("rateWarning", { p: pct(rate) }));
    }
    if (h.outUrl) URL.revokeObjectURL(h.outUrl);
    h.outUrl = URL.createObjectURL(blob);
    $("hide-save").href = h.outUrl;
    $("hide-save").download = `${h.name}.png`;
    $("hide-key").textContent = key;
    $("hide-text").value = "";
    $("hide-result").hidden = false;
    $("hide-result").scrollIntoView({ block: "nearest", behavior: reduceMotion.matches ? "auto" : "smooth" });
  } catch (e) {
    stop();
    if (e.name === "AbortError") logRow("hide-log", "warn", "", t("cancelledNothingSaved"));
    else logRow("hide-log", "error", "", e.message);
  } finally {
    h.busy = null;
    setLabel("hide-go", "hideBtn");
    $("hide-cancel").hidden = true;
    updateMeter();
  }
});

$("hide-cancel").addEventListener("click", () => state.hide.busy && state.hide.busy.abort());
$("hide-copy").addEventListener("click", (e) => copyText($("hide-key").textContent, e.currentTarget));
$("hide-new").addEventListener("click", () => {
  const h = state.hide;
  $("hide-result").hidden = true;
  $("hide-key").textContent = "";
  if (h.outUrl) URL.revokeObjectURL(h.outUrl);
  h.outUrl = null;
  h.png = null;
  resetFile("hide-drop");
  clearLog("hide-log");
  $("hide-text").value = "";
  $("hide-text").disabled = true;
  updateMeter();
});

// ---------- reveal ----------

function keyChars() {
  return $("reveal-key").value.replace(/[\s-]/g, "").length;
}

function updateReveal() {
  $("reveal-go").disabled = !state.reveal.png || keyChars() !== 28 || !!state.reveal.busy;
}

wireDrop("reveal-drop", "reveal-file", async (file) => {
  if (state.reveal.busy) return;
  clearLog("reveal-log");
  $("reveal-result").hidden = true;
  if (file.size > limits.maxPngBytes) {
    logRow("reveal-log", "error", "", t("fileLarger100"));
    return;
  }
  const raw = await file.arrayBuffer();
  if (!isPng(raw)) {
    state.reveal.png = null;
    resetFile("reveal-drop");
    logRow("reveal-log", "error", "", t("exactPng"));
  } else {
    state.reveal.png = raw;
    showFile("reveal-drop", raw, [file.name, `${fmt(Math.round(file.size / 1024))} KB`]);
    $("reveal-key").focus();
  }
  updateReveal();
});

$("reveal-key").addEventListener("input", updateReveal);
$("reveal-key").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !$("reveal-go").disabled) $("reveal-go").click();
});
$("reveal-show").addEventListener("click", () => {
  const input = $("reveal-key");
  const show = input.type === "password";
  input.type = show ? "text" : "password";
  $("reveal-show").textContent = t(show ? "hide" : "show");
  $("reveal-show").setAttribute("aria-pressed", String(show));
});

const GLYPHS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#%&*+=?";

/** The decryption moment. Purely cosmetic: the plaintext is already
 *  decrypted and authenticated, and the glyphs are random, never derived
 *  from the ciphertext. Screen readers get the final text at once. */
function showPlaintext(text) {
  const target = $("reveal-text");
  $("reveal-text-sr").textContent = text;
  const chars = Array.from(text);
  if (reduceMotion.matches || chars.length === 0) {
    target.textContent = text;
    return;
  }
  // Each character scrambles for 240 ms, starts are staggered by up to
  // 12 ms, and the whole effect never takes longer than 900 ms.
  const scramble = 240;
  const stagger = Math.min(12, (900 - scramble) / Math.max(1, chars.length));
  const start = performance.now();
  const frame = (now) => {
    const t = now - start;
    const settled = Math.max(0, Math.min(chars.length, Math.floor((t - scramble) / stagger) + 1));
    if (settled >= chars.length) {
      target.textContent = text;
      return;
    }
    const rest = chars
      .slice(settled)
      .map((c) => (/\s/.test(c) ? c : GLYPHS[Math.floor(Math.random() * GLYPHS.length)]))
      .join("");
    target.replaceChildren(chars.slice(0, settled).join(""), el("span", "scr", rest));
    requestAnimationFrame(frame);
  };
  requestAnimationFrame(frame);
}

$("reveal-go").addEventListener("click", async () => {
  const r = state.reveal;
  if (!r.png || r.busy) return;
  const controller = new AbortController();
  r.busy = controller;
  updateReveal();
  setLabel("reveal-go", "revealing");
  $("reveal-cancel").hidden = false;
  $("reveal-result").hidden = true;
  const stop = spinner("reveal-log", t("working"));
  try {
    const res = await api("/api/reveal", packed(enc.encode($("reveal-key").value), r.png), controller.signal);
    const text = await res.text();
    stop();
    await logRows("reveal-log", [
      ["ok", t("keyChecked"), t("checksumMatches")],
      ["ok", t("decrypted"), t("decryptedVal", { n: fmt(enc.encode(text).length) })],
    ]);
    $("reveal-result").hidden = false;
    showPlaintext(text);
  } catch (e) {
    stop();
    if (e.name === "AbortError") logRow("reveal-log", "warn", "", t("cancelled"));
    else logRow("reveal-log", "error", "", e.message);
  } finally {
    r.busy = null;
    setLabel("reveal-go", "revealBtn");
    $("reveal-cancel").hidden = true;
    updateReveal();
  }
});

$("reveal-cancel").addEventListener("click", () => state.reveal.busy && state.reveal.busy.abort());
$("reveal-copy").addEventListener("click", (e) => copyText($("reveal-text-sr").textContent, e.currentTarget));
$("reveal-clear").addEventListener("click", () => {
  $("reveal-text").textContent = "";
  $("reveal-text-sr").textContent = "";
  $("reveal-result").hidden = true;
});

// ---------- status, keep alive, quit ----------

$("quit").addEventListener("click", async () => {
  try {
    await api("/api/quit");
  } catch {}
  const term = $("term");
  term.replaceChildren(el("p", "stopped", t("stopped")));
});

// ---------- language switch ----------

let serverStatus = null;

function setLabel(id, key) {
  const b = $(id);
  b.dataset.i18nLabel = key;
  b.querySelector(".lbl").textContent = t(key);
}

function showStatus() {
  const s = serverStatus;
  if (!s) return;
  $("hide-limits").textContent = t("limits", { mb: fmt(s.maxPngBytes / 1048576), mp: fmt(s.maxPixels / 1e6) });
  $("status-idle").textContent = s.idleMinutes ? t("idleCloses", { m: s.idleMinutes }) : t("staysOpen");
}

/** Puts every visible text into the current language. Log rows that are
 *  already printed stay as they are, like lines in a terminal. */
function applyLang() {
  document.documentElement.lang = lang;
  for (const e of document.querySelectorAll("[data-i18n]")) e.textContent = t(e.dataset.i18n);
  for (const e of document.querySelectorAll("[data-i18n-placeholder]")) e.placeholder = t(e.dataset.i18nPlaceholder);
  for (const e of document.querySelectorAll("[data-i18n-aria]")) e.setAttribute("aria-label", t(e.dataset.i18nAria));
  for (const b of document.querySelectorAll(".langs button")) b.setAttribute("aria-pressed", String(b.dataset.lang === lang));
  setLabel("hide-go", state.hide.busy ? "hiding" : "hideBtn");
  setLabel("reveal-go", state.reveal.busy ? "revealing" : "revealBtn");
  $("reveal-show").textContent = t($("reveal-key").type === "password" ? "show" : "hide");
  if (!$("ended").hidden) $("ended").textContent = t("sessionEnded");
  showStatus();
  updateMeter();
}

for (const b of document.querySelectorAll(".langs button")) {
  b.addEventListener("click", () => {
    lang = b.dataset.lang;
    applyLang();
  });
}

async function boot() {
  applyLang();
  $("status-addr").textContent = location.host;
  // The session cookie was set by the one time launch link the app opened.
  // Without it every API call answers 401 and the page says so.
  try {
    const s = await (await api("/api/status")).json();
    Object.assign(limits, s);
    serverStatus = s;
    showStatus();
    setInterval(() => api("/api/ping").catch(() => {}), 20000);
  } catch (e) {
    if (e.status !== 401) sessionEnded(e.message);
  }
  updateMeter();
  updateReveal();
}

boot();
