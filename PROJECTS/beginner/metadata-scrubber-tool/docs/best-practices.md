# Best Practices for Secure File Sharing

Guidelines for protecting your privacy when sharing files.

## Before Sharing Files

### 1. Always Check Metadata First

```bash
mst read yourfile.pdf
```

Review the output for any sensitive information.

### 2. Scrub Before Sharing

```bash
mst scrub yourfile.pdf --output ./clean
```

Always use the cleaned version for sharing.

### 3. Verify Removal

```bash
mst verify yourfile.pdf ./clean/processed_yourfile.pdf
```

Confirm sensitive data was actually removed.

---

## File Type Specific Guidance

### 📸 Images

**High Risk:** Photos from smartphones contain GPS coordinates by default.

```bash
# Batch process all photos before uploading
mst scrub ./photos -r -ext jpg --output ./clean
```

**Tip:** Disable location services for your camera app to prevent GPS embedding.

### 📄 PDF Documents

**High Risk:** PDFs often contain author name, creator software, and sometimes revision history.

```bash
mst scrub report.pdf --output ./clean
```

**Note:** This tool removes document properties. For redacting visible content, use a dedicated PDF editor.

### 📊 Office Documents (Word, Excel, PowerPoint)

**High Risk:** Office files store author, company, and modification history.

```bash
# Process all Word documents
mst scrub ./documents -r -ext docx --output ./clean
```

---

## Workflow Integration

### For Regular File Sharing

1. Create a "clean" folder for processed files
2. Before sharing, always scrub to that folder
3. Share only from the clean folder

### For Automated Pipelines

```bash
# In CI/CD or scripts
mst scrub ./output -r -ext pdf --output ./publish
```

### For Verification

```bash
# Verify before publishing
mst verify original.pdf ./publish/processed_original.pdf
```

---

## What's Preserved (And Why)

| Property | Reason |
|----------|--------|
| Created Date | File organization, audit trails |
| Modified Date | Version tracking |
| Language | Accessibility, screen readers |

These properties are generally not privacy-sensitive and are often needed for file management.

---

## Common Mistakes to Avoid

1. **Sharing the original instead of the processed file**
   - Always verify you're sharing from the output folder

2. **Not checking the output**
   - Use `mst verify` to confirm removal

3. **Forgetting about PDFs**
   - PDF author metadata is often overlooked

4. **Batch processing without verification**
   - Spot-check a few files after batch processing

5. **Assuming social media strips metadata**
   - Many platforms compress but don't fully remove metadata

---

## Quick Reference

```bash
# Read metadata
mst read file.jpg

# Scrub single file
mst scrub file.jpg --output ./clean

# Scrub directory
mst scrub ./folder -r -ext jpg --output ./clean

# Preview without changes
mst scrub ./folder -r -ext jpg --dry-run

# Verify removal
mst verify original.jpg ./clean/processed_original.jpg
```
