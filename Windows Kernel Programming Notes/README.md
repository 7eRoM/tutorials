# Windows Kernel Programming Notes

A collection of detailed insights, guidelines, and technical information regarding the development and programming.

Kindly let me know if any of the information I provided is incorrect.

## Some of mini-filter context types

| Level | What it logically represents | Key structure / pointer |
|---|---|---|
| Volume | Whole disk partition (e.g. C:) | `VPB`, `DEVICE_OBJECT` |
| File | A directory entry that can contain one or more data streams | FCB for the file (only in Win11/Server 2022+, see below) |
| Stream | 	An individual ordered sequence of bytes that lives inside a file (the default unnamed stream or any Alternate Data Stream) | `FsContext` inside each `FILE_OBJECT` points to the FCB/SCB for this stream |
| Stream Handle | A single open instance of that stream created by a user‑mode `CreateFile` / kernel `ZwCreateFile` | `FILE_OBJECT` itself |

 * A file can have many streams (NTFS supports alternate data streams like report.txt:secret)
 * A stream can have many handles (every call to CreateFile() returns a new handle that still refers to the same bytes)

```
report.txt                        ← File
 ├─ ::$DATA                       ← unnamed/default STREAM (index 0)
 │    ├─ Handle #1 (FO‑A)         ← STREAMHANDLE_CONTEXT A
 │    └─ Handle #2 (FO‑B)         ← STREAMHANDLE_CONTEXT B
 └─ secret:$DATA                  ← ADS, another STREAM
      └─ Handle #3 (FO‑C)
```

 * Both FO‑A and FO‑B share the same `STREAM_CONTEXT` because their `FsContext` is identical.
 * FO‑C gets its own, separate `STREAM_CONTEXT` (different `FsContext`).
 * One optional `FILE_CONTEXT` can cover all three handles because they belong to the same directory entry.
