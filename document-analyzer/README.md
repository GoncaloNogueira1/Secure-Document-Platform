# Document Analyzer

The Document Analyzer is a separate service in the upload pipeline. Earlier versions stored PDFs directly under the web application; in the current design, every upload is checked before it can enter permanent storage.

## Purpose

Browser uploads cannot be trusted: files may be corrupted, badly formed, or contain unwanted behaviour. The web application therefore does not write uploads straight into final storage. Each file is placed in a staging directory, the analyzer is called, and the file is promoted only when the analyzer returns a successful result. In permanent storage each file is saved as `<sha256>.pdf`. That way two different uploads can both be called `report.pdf` without overwriting each other, and we do not trust the uploaded filename as the real name of the file on disk.

This matches the architecture in the project report: a Document Analyzer between the application layer and Document Storage. In this implementation, Document Storage is the Docker volume mounted at `/data`, operated as part of the same Compose stack as the application.

## Processing flow

1. The user uploads a PDF. The Flask application saves it under `/data/staging/` using a generated UUID as the filename, not the original name.
2. The application sends an HTTP request on the internal Docker network to `document-analyzer` (port 9000 is not published on the host).
3. The analyzer reads that path, runs the checks, and returns JSON with `ok: true` or `ok: false` and supporting details.
4. If the result is negative, the staged file is removed and the upload fails.
5. If the result is positive, the application moves the file to `/data/storage/` as `<sha256>.pdf`. The original filename is stored in the database metadata for the user interface.

The analyzer service does not move files into final storage; only the web application does, which keeps roles easy to explain.

## Checks performed (minimum viable product scope)

The following checks fit the **minimum viable product** scope of the coursework prototype:

- **ClamAV** (via `clamd`): malware scan of the file bytes.
- **`qpdf --check`**: validation of PDF structure. Exit codes that represent warnings are accepted according to the configured policy; severe structural errors lead to rejection.
- **Keyword heuristic inspired by pdfid:** the code searches the PDF for a small set of keywords associated with active content or risky features (for example `/JS`, `/Launch`). This is not the original pdfid utility; it is a simple in-house counter built on the same general idea. It may flag unusual but legitimate PDFs; for this prototype we accepted stricter filtering instead of maximising permissiveness.
- **SHA-256:** hash for integrity and for stable storage filenames.

## Deployment

The service runs in the `document-analyzer` container defined by the `Dockerfile` in this directory. Traffic stays on the internal Compose network. The container uses a read-only root filesystem where practical and uses tmpfs for `/tmp`; the staged file is read from the shared volume in read-only mode.

## Runtime considerations

The ClamAV daemon may require several minutes on first start while signature databases download; until then, antivirus checks can fail or return errors. Diagnosing ClamAV-related problems should include the `clamd` container logs.

For live troubleshooting of PDF analysis, watch both services together:

```bash
docker compose logs -f --since=5m clamd document-analyzer
```

The analyzer now emits per-request `request_id` values and logs each stage (`clamav`, `qpdf`, `pdfid`, final verdict), making it easier to correlate an API response with ClamAV activity.

Optional analyzer log tuning via compose environment variables:

- `ANALYZER_LOG_LEVEL` (`INFO`, `DEBUG`, etc.)
- `LOG_CLAM_RAW_RESPONSE` (`true`/`false`) to print raw `clamd` verdict lines

Rejections reported by `qpdf` or by the keyword heuristic match the validation rules defined for this prototype (see the checks above). Those outcomes are expected when a file falls outside the accepted policy, not necessarily signs of incorrect code.
