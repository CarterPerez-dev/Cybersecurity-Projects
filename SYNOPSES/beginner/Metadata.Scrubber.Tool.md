# Metadata Scrubber Tool

## Overview
Create a comprehensive tool that extracts and removes metadata from various file types (images, PDFs, Office documents) to protect privacy and prevent information leakage. This project teaches file format analysis, metadata extraction techniques, and demonstrates why metadata removal is critical for OPSEC (operational security) in sensitive work environments.

## Step-by-Step Instructions

1. **Research metadata in different file types** by understanding what information is embedded in common files: EXIF data in JPEG/PNG images (camera info, GPS coordinates, timestamps), XMP metadata, IPTC data, PDF properties (author, creation date, edit history), and Office document metadata (author names, edit history, tracked changes). Install libraries like `Pillow`, `piexif`, `pdf-metadata`, `python-pptx`, and `openpyxl` to work with different formats.

2. **Build extraction functionality** that reads metadata from files and displays it in human-readable format, organized by metadata type and field. Start with EXIF data from images using `piexif`, then expand to PDF metadata using `PyPDF2` or `pdfplumber`, and Office documents using their respective libraries. Show users exactly what information is being exposed in their files.

3. **Implement image metadata scrubbing** using `Pillow` to create new image files that contain only the pixel data, stripping all EXIF, XMP, and IPTC metadata. Preserve the image quality and format while removing sensitive information like GPS coordinates, camera models, software versions, and creation timestamps—test that scrubbed images display identically to originals.

4. **Add PDF metadata removal** using `PyPDF2` or similar libraries to create new PDF files without metadata properties like author, subject, creator application, creation date, and modification date. Handle potential issues with encrypted PDFs and protected content, providing appropriate error messages and warnings.

5. **Implement Office document metadata removal** for Word (.docx), Excel (.xlsx), and PowerPoint (.pptx) files by modifying the underlying XML structure or using libraries that provide metadata manipulation APIs. Remove author information, company names, tracked changes, comments, and revision history that could reveal sensitive business information.

6. **Create batch processing capability** allowing users to process entire directories of mixed file types with a single command. Implement options to process recursively through subdirectories and maintain the original directory structure in a cleaned output folder, enabling users to scrub thousands of files efficiently.

7. **Add detection and warning for hidden data** including steganographic content, alternative data streams, embedded objects, and other non-obvious metadata storage locations. Warn users about file types that commonly hide information (compressed archives, executable files) and explain the limitations of your scrubber on complex file formats.

8. **Build a comprehensive reporting interface** that shows detailed before-and-after metadata comparisons, confirms what was removed, and provides verification that sensitive information is genuinely gone. Create detailed documentation explaining metadata risks in different file types, best practices for secure file sharing, and include examples demonstrating why metadata removal matters for privacy and security.

## Key Concepts to Learn
- File format analysis and structure
- Metadata extraction from multiple formats
- Privacy protection and information leakage risks
- Batch processing and file I/O
- OPSEC principles and secure document handling

## Deliverables
- Metadata extraction tool showing all embedded information
- Scrubbing functionality for images, PDFs, and Office documents
- Batch processing with recursive directory support
- Before/after verification and detailed reporting
- Educational documentation on metadata risks
