import { useRef, useState } from "react";
import { api } from "../api.js";

const ACCEPT = ".json,.ndjson,.jsonl,.csv";

export default function UploadPanel({ onUploaded }) {
  const inputRef = useRef(null);
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [results, setResults] = useState([]); // one entry per file: {name, ok, message, warnings}

  async function handleFiles(fileList) {
    const files = Array.from(fileList || []);
    if (!files.length) return;
    setBusy(true);
    const out = [];
    for (const file of files) {
      try {
        const r = await api.upload(file);
        const skipped = r.skipped ? `, ${r.skipped} skipped` : "";
        out.push({
          name: file.name, ok: true, warnings: r.warnings,
          message: `${r.ingested} alerts ingested (${r.file_format.toUpperCase()}, ${r.source_formats.join(" + ")}${skipped})`,
        });
      } catch (e) {
        out.push({ name: file.name, ok: false, message: e.message, warnings: [] });
      }
    }
    setResults(out);
    setBusy(false);
    if (inputRef.current) inputRef.current.value = "";
    if (out.some((r) => r.ok)) onUploaded();
  }

  return (
    <section className="card upload">
      <div
        className={`dropzone ${dragging ? "dragging" : ""}`}
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => { e.preventDefault(); setDragging(false); handleFiles(e.dataTransfer.files); }}
      >
        <div>
          <strong>Upload alert export</strong>
          <div className="muted">Wazuh or Splunk · JSON, NDJSON or CSV · drag files here or</div>
        </div>
        <label className={`button ${busy ? "disabled" : ""}`}>
          {busy ? "Uploading…" : "Choose files"}
          <input ref={inputRef} type="file" accept={ACCEPT} multiple hidden disabled={busy}
                 onChange={(e) => handleFiles(e.target.files)} />
        </label>
      </div>
      {results.map((r) => (
        <div key={r.name} className={`banner ${r.ok ? "success" : "error"}`}>
          <strong>{r.name}:</strong> {r.message}
          {r.warnings?.length > 0 && (
            <details>
              <summary>{r.warnings.length} warning(s)</summary>
              <ul>{r.warnings.map((w, i) => <li key={i}>{w}</li>)}</ul>
            </details>
          )}
        </div>
      ))}
    </section>
  );
}
