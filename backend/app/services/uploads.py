"""Capture file upload service — TASK-033 per SRS §9.1 and FR-01..08.

Validates pcap/pcapng files, streams to disk with size limits, computes SHA-256,
and persists upload metadata in MongoDB.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path
from typing import Any

from fastapi import UploadFile
from motor.motor_asyncio import AsyncIOMotorDatabase

from backend.app.config import settings
from backend.app.core.errors import AppError
from backend.app.db.repositories import UploadRepository

# PCAP magic numbers
# Big endian: 0xa1b2c3d4, Little endian: 0xd4c3b2a1
# Nanosecond: 0xa1b23c4d, Little endian ns: 0x4d3cb2a1
# PCAPNG: 0x0a0d0d0a
PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4": "pcap",
    b"\xd4\xc3\xb2\xa1": "pcap",
    b"\xa1\xb2\x3c\x4d": "pcap",
    b"\x4d\x3c\xb2\xa1": "pcap",
    b"\x0a\x0d\x0d\x0a": "pcapng",
}


def detect_capture_format(header: bytes) -> str | None:
    """Detect capture file format from the first 4 bytes."""
    if len(header) < 4:
        return None
    magic = header[:4]
    return PCAP_MAGICS.get(magic)


async def handle_upload(
    db: AsyncIOMotorDatabase,
    file: UploadFile,
) -> dict[str, Any]:
    """Stream uploaded file to disk with limit checks, calculate sha256, and store in DB."""
    filename = file.filename or "capture.pcap"
    clean_filename = os.path.basename(filename)

    # Check extension
    ext = Path(clean_filename).suffix.lower()
    if ext not in (".pcap", ".pcapng", ".cap"):
        raise AppError(
            code="UNSUPPORTED_FILE_TYPE",
            message=f"File '{clean_filename}' is not a recognized capture file (.pcap, .pcapng).",
            status_code=415,
        )

    # Prepare storage path
    file_uuid = str(uuid.uuid4())
    stored_filename = f"{file_uuid}_{clean_filename}"
    upload_dir = Path(settings.UPLOAD_DIR)
    upload_dir.mkdir(parents=True, exist_ok=True)
    stored_path = upload_dir / stored_filename

    hasher = hashlib.sha256()
    max_bytes = settings.MAX_UPLOAD_MB * 1024 * 1024

    # Read first chunk to validate magic bytes BEFORE touching disk
    first_chunk = await file.read(64 * 1024)
    if not first_chunk:
        raise AppError(
            code="VALIDATION_ERROR",
            message="Uploaded file is empty (0 bytes).",
            status_code=422,
        )

    fmt = detect_capture_format(first_chunk)
    if not fmt:
        raise AppError(
            code="UNSUPPORTED_FILE_TYPE",
            message=f"File '{clean_filename}' does not contain a valid PCAP or PCAPNG magic header.",
            status_code=415,
        )
    detected_format = fmt

    size_bytes = len(first_chunk)
    hasher.update(first_chunk)

    with open(stored_path, "wb") as f_out:
        f_out.write(first_chunk)
        while True:
            chunk = await file.read(64 * 1024)
            if not chunk:
                break

            size_bytes += len(chunk)
            if size_bytes > max_bytes:
                f_out.close()
                stored_path.unlink(missing_ok=True)
                raise AppError(
                    code="FILE_TOO_LARGE",
                    message=f"File exceeds maximum upload size of {settings.MAX_UPLOAD_MB} MB.",
                    status_code=413,
                )

            hasher.update(chunk)
            f_out.write(chunk)

    if size_bytes == 0:
        stored_path.unlink(missing_ok=True)
        raise AppError(
            code="VALIDATION_ERROR",
            message="Uploaded file is empty (0 bytes).",
            status_code=422,
        )

    sha256 = hasher.hexdigest()

    # Save to DB
    repo = UploadRepository(db)
    # Check if duplicate sha256 exists
    existing = await repo.get_by_sha256(sha256)
    if existing:
        # Re-use existing upload record
        return existing

    upload_doc = await repo.create(
        original_filename=clean_filename,
        stored_path=str(stored_path),
        sha256=sha256,
        size_bytes=size_bytes,
        detected_format=detected_format,
    )

    return upload_doc
