// ===================
// © AngelaMos | 2026
// tab-headers.tsx
//
// Headers tab displaying binary format metadata,
// format-specific info, section and segment tables
//
// Renders a format info grid (format, arch, bits,
// endianness, entry point, stripped/PIE/debug flags),
// then conditionally shows PE info (image base,
// subsystem, linker version, ASLR/DEP/CFG), ELF info
// (OS ABI, type, RELRO, bind-now, NX stack, needed
// libraries list), or Mach-O info (file type, universal,
// code signature). Below, a sections table shows name,
// virtual address (formatHex), virtual size, raw size,
// and R/W/X permissions via PermsBadge (with execute
// highlighted in a distinct style). Segments are in a
// collapsible section toggled by showSegments state,
// showing name, vaddr, vsize, fsize, and permissions
//
// Connects to:
//   api/types         - AnalysisResponse, SectionInfo,
//                        SegmentInfo
//   core/lib          - formatHex
//   analysis/index    - mounted in renderTab switch
//   analysis.module
//     .scss           - metaGrid, dataTable, perm
//                        styles
// ===================

import { useState } from 'react'
import type { AnalysisResponse, SectionInfo, SegmentInfo } from '@/api'
import { formatHex } from '@/core/lib'
import styles from './analysis.module.scss'

function PermsBadge({
  r,
  w,
  x,
}: {
  r: boolean
  w: boolean
  x: boolean
}): React.ReactElement {
  return (
    <span className={styles.perms}>
      <span className={r ? styles.permActive : styles.permInactive}>R</span>
      <span className={w ? styles.permActive : styles.permInactive}>W</span>
      <span className={x ? styles.permExec : styles.permInactive}>X</span>
    </span>
  )
}

function SectionRow({ section }: { section: SectionInfo }): React.ReactElement {
  return (
    <tr className={styles.tableRow}>
      <td className={styles.cellMono}>{section.name}</td>
      <td className={styles.cellMono}>{formatHex(section.virtual_address)}</td>
      <td className={styles.cellRight}>
        {section.virtual_size.toLocaleString()}
      </td>
      <td className={styles.cellRight}>{section.raw_size.toLocaleString()}</td>
      <td>
        <PermsBadge
          r={section.permissions.read}
          w={section.permissions.write}
          x={section.permissions.execute}
        />
      </td>
    </tr>
  )
}

function SegmentRow({ segment }: { segment: SegmentInfo }): React.ReactElement {
  return (
    <tr className={styles.tableRow}>
      <td className={styles.cellMono}>{segment.name ?? '\u2014'}</td>
      <td className={styles.cellMono}>{formatHex(segment.virtual_address)}</td>
      <td className={styles.cellRight}>
        {segment.virtual_size.toLocaleString()}
      </td>
      <td className={styles.cellRight}>{segment.file_size.toLocaleString()}</td>
      <td>
        <PermsBadge
          r={segment.permissions.read}
          w={segment.permissions.write}
          x={segment.permissions.execute}
        />
      </td>
    </tr>
  )
}

export function TabHeaders({
  data,
}: {
  data: AnalysisResponse
}): React.ReactElement {
  const [showSegments, setShowSegments] = useState(false)
  const fmt = data.passes.format

  if (!fmt) {
    return (
      <div className={styles.tabPanel}>
        <span className={styles.noData}>No format data available</span>
      </div>
    )
  }

  return (
    <div className={styles.tabPanel}>
      <section className={styles.overviewSection}>
        <span className={styles.sectionLabel}>FORMAT INFO</span>
        <div className={styles.metaGrid}>
          <div className={styles.metaField}>
            <span className={styles.metaFieldLabel}>FORMAT</span>
            <span className={styles.metaFieldValue}>{fmt.format}</span>
          </div>
          <div className={styles.metaField}>
            <span className={styles.metaFieldLabel}>ARCH</span>
            <span className={styles.metaFieldValue}>
              {typeof fmt.architecture === 'string'
                ? fmt.architecture
                : fmt.architecture.Other}
            </span>
          </div>
          <div className={styles.metaField}>
            <span className={styles.metaFieldLabel}>BITS</span>
            <span className={styles.metaFieldValue}>{fmt.bits}</span>
          </div>
          <div className={styles.metaField}>
            <span className={styles.metaFieldLabel}>ENDIAN</span>
            <span className={styles.metaFieldValue}>{fmt.endianness}</span>
          </div>
          <div className={styles.metaField}>
            <span className={styles.metaFieldLabel}>ENTRY</span>
            <span className={styles.metaFieldValue}>
              {formatHex(fmt.entry_point)}
            </span>
          </div>
          <div className={styles.metaField}>
            <span className={styles.metaFieldLabel}>STRIPPED</span>
            <span className={styles.metaFieldValue}>
              {fmt.is_stripped ? 'YES' : 'NO'}
            </span>
          </div>
          <div className={styles.metaField}>
            <span className={styles.metaFieldLabel}>PIE</span>
            <span className={styles.metaFieldValue}>
              {fmt.is_pie ? 'YES' : 'NO'}
            </span>
          </div>
          <div className={styles.metaField}>
            <span className={styles.metaFieldLabel}>DEBUG</span>
            <span className={styles.metaFieldValue}>
              {fmt.has_debug_info ? 'YES' : 'NO'}
            </span>
          </div>
        </div>
      </section>

      {fmt.pe_info && (
        <section className={styles.overviewSection}>
          <span className={styles.sectionLabel}>PE INFO</span>
          <div className={styles.metaGrid}>
            <div className={styles.metaField}>
              <span className={styles.metaFieldLabel}>IMAGE BASE</span>
              <span className={styles.metaFieldValue}>
                {formatHex(fmt.pe_info.image_base)}
              </span>
            </div>
            <div className={styles.metaField}>
              <span className={styles.metaFieldLabel}>SUBSYSTEM</span>
              <span className={styles.metaFieldValue}>
                {fmt.pe_info.subsystem}
              </span>
            </div>
            <div className={styles.metaField}>
              <span className={styles.metaFieldLabel}>LINKER</span>
              <span className={styles.metaFieldValue}>
                {fmt.pe_info.linker_version}
              </span>
            </div>
            <div className={styles.metaField}>
              <span className={styles.metaFieldLabel}>ASLR</span>
              <span className={styles.metaFieldValue}>
                {fmt.pe_info.dll_characteristics.aslr ? 'YES' : 'NO'}
              </span>
            </div>
            <div className={styles.metaField}>
              <span className={styles.metaFieldLabel}>DEP</span>
              <span className={styles.metaFieldValue}>
                {fmt.pe_info.dll_characteristics.dep ? 'YES' : 'NO'}
              </span>
            </div>
            <div className={styles.metaField}>
              <span className={styles.metaFieldLabel}>CFG</span>
              <span className={styles.metaFieldValue}>
                {fmt.pe_info.dll_characteristics.cfg ? 'YES' : 'NO'}
              </span>
            </div>
          </div>
        </section>
      )}

      {fmt.elf_info && (
        <section className={styles.overviewSection}>
          <span className={styles.sectionLabel}>ELF INFO</span>
          <div className={styles.metaGrid}>
            <div className={styles.metaField}>
              <span className={styles.metaFieldLabel}>OS ABI</span>
              <span className={styles.metaFieldValue}>{fmt.elf_info.os_abi}</span>
            </div>
            <div className={styles.metaField}>
              <span className={styles.metaFieldLabel}>TYPE</span>
              <span className={styles.metaFieldValue}>
                {fmt.elf_info.elf_type}
              </span>
            </div>
            <div className={styles.metaField}>
              <span className={styles.metaFieldLabel}>RELRO</span>
              <span className={styles.metaFieldValue}>
                {fmt.elf_info.gnu_relro ? 'FULL' : 'NO'}
              </span>
            </div>
            <div className={styles.metaField}>
              <span className={styles.metaFieldLabel}>BIND NOW</span>
              <span className={styles.metaFieldValue}>
                {fmt.elf_info.bind_now ? 'YES' : 'NO'}
              </span>
            </div>
            <div className={styles.metaField}>
              <span className={styles.metaFieldLabel}>NX STACK</span>
              <span className={styles.metaFieldValue}>
                {fmt.elf_info.stack_executable ? 'EXEC' : 'NO-EXEC'}
              </span>
            </div>
          </div>
          {fmt.elf_info.needed_libraries.length > 0 && (
            <div className={styles.libList}>
              <span className={styles.metaFieldLabel}>LIBRARIES</span>
              {fmt.elf_info.needed_libraries.map((lib) => (
                <span key={lib} className={styles.libItem}>
                  {lib}
                </span>
              ))}
            </div>
          )}
        </section>
      )}

      {fmt.macho_info && (
        <section className={styles.overviewSection}>
          <span className={styles.sectionLabel}>MACH-O INFO</span>
          <div className={styles.metaGrid}>
            <div className={styles.metaField}>
              <span className={styles.metaFieldLabel}>FILE TYPE</span>
              <span className={styles.metaFieldValue}>
                {fmt.macho_info.file_type}
              </span>
            </div>
            <div className={styles.metaField}>
              <span className={styles.metaFieldLabel}>UNIVERSAL</span>
              <span className={styles.metaFieldValue}>
                {fmt.macho_info.is_universal ? 'YES' : 'NO'}
              </span>
            </div>
            <div className={styles.metaField}>
              <span className={styles.metaFieldLabel}>CODE SIGN</span>
              <span className={styles.metaFieldValue}>
                {fmt.macho_info.has_code_signature ? 'YES' : 'NO'}
              </span>
            </div>
          </div>
        </section>
      )}

      <section className={styles.overviewSection}>
        <span className={styles.sectionLabel}>
          SECTIONS ({fmt.sections.length})
        </span>
        <div className={styles.tableWrap}>
          <table className={styles.dataTable}>
            <thead>
              <tr>
                <th>NAME</th>
                <th>VADDR</th>
                <th className={styles.cellRight}>VSIZE</th>
                <th className={styles.cellRight}>RAW SIZE</th>
                <th>PERMS</th>
              </tr>
            </thead>
            <tbody>
              {fmt.sections.map((sec) => (
                <SectionRow key={sec.name} section={sec} />
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {fmt.segments.length > 0 && (
        <section className={styles.overviewSection}>
          <button
            type="button"
            className={styles.collapseBtn}
            onClick={() => setShowSegments((prev) => !prev)}
          >
            <span className={styles.sectionLabel}>
              SEGMENTS ({fmt.segments.length})
            </span>
            <span className={styles.collapseIcon}>
              {showSegments ? '\u25B2' : '\u25BC'}
            </span>
          </button>
          {showSegments && (
            <div className={styles.tableWrap}>
              <table className={styles.dataTable}>
                <thead>
                  <tr>
                    <th>NAME</th>
                    <th>VADDR</th>
                    <th className={styles.cellRight}>VSIZE</th>
                    <th className={styles.cellRight}>FSIZE</th>
                    <th>PERMS</th>
                  </tr>
                </thead>
                <tbody>
                  {fmt.segments.map((seg, i) => (
                    <SegmentRow key={`seg-${i.toString()}`} segment={seg} />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
    </div>
  )
}
