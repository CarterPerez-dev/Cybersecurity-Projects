# Metadata Privacy Risks

Understanding why metadata removal matters for privacy and security.

## What is Metadata?

Metadata is "data about data" - hidden information embedded in files that describes when, where, how, and by whom a file was created or modified.

## Common Metadata Types

### 📸 Images (JPEG, PNG)

| Metadata Type | Privacy Risk |
|---------------|--------------|
| **GPS Coordinates** | Reveals exact location where photo was taken |
| **Camera Model** | Can identify specific device, linked to owner |
| **Date/Time** | Reveals when photo was taken |
| **Software** | Shows editing tools used |
| **Thumbnail** | May contain original uncropped image |

### 📄 Documents (Word, PDF)

| Metadata Type | Privacy Risk |
|---------------|--------------|
| **Author** | Reveals creator's name/username |
| **Company** | Exposes employer information |
| **Last Modified By** | Shows who edited the document |
| **Comments** | May contain internal notes |
| **Revision History** | Can expose previous versions |

### 📊 Spreadsheets (Excel)

| Metadata Type | Privacy Risk |
|---------------|--------------|
| **Author** | Reveals creator identity |
| **Company** | Exposes organization |
| **Keywords** | May reveal document purpose |
| **Custom Properties** | Internal tracking data |

### 📽️ Presentations (PowerPoint)

| Metadata Type | Privacy Risk |
|---------------|--------------|
| **Author** | Creator identity |
| **Title/Subject** | May reveal confidential topics |
| **Comments** | Presenter notes, internal feedback |

---

## Real-World Examples

### Case 1: Location Leak via Photo
A journalist shared a photo online. The embedded GPS coordinates revealed their safe house location, putting sources at risk.

### Case 2: Internal Document Exposed
A company released a redacted PDF. The author metadata still showed an employee's full name and the legal department.

### Case 3: Anonymous Submission Failed
A whistleblower submitted documents "anonymously" but the Word metadata contained their username and computer name.

---

## High-Risk Scenarios

1. **Sharing photos on social media** - GPS can reveal home address
2. **Sending documents to clients** - Author reveals internal usernames
3. **Publishing reports externally** - Revision history may expose drafts
4. **Submitting anonymous tips** - Metadata can identify the source
5. **Legal discovery** - Metadata is often requested in litigation

---

## What This Tool Removes

| Category | Removed Properties |
|----------|-------------------|
| **Identity** | Author, Last Modified By, Creator |
| **Location** | GPS Latitude, Longitude, Altitude |
| **Device** | Camera Model, Software, Device ID |
| **Tracking** | Comments, Keywords, Custom Properties |

### Preserved (Intentionally)

- **Created Date** - Often needed for file organization
- **Modified Date** - Required for version tracking
- **Language** - Accessibility purposes

---

## Best Practice

**Always scrub metadata before sharing files externally.**

```bash
# Check what metadata exists
mst read document.pdf

# Remove metadata
mst scrub document.pdf --output ./clean

# Verify removal
mst verify document.pdf ./clean/processed_document.pdf
```
