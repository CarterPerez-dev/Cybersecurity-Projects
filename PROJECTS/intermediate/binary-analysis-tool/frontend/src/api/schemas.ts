// ===================
// © AngelaMos | 2026
// schemas.ts
//
// Zod runtime validation schemas mirroring every Rust
// engine result type
//
// Defines ~40 Zod schemas that map one-to-one with the
// backend serde output: enum schemas for BinaryFormat,
// Architecture, Endianness, RiskLevel, Severity,
// StringEncoding, StringCategory (14 variants),
// EntropyClassification (5 bands), EntropyFlag,
// FlowControlType, and CfgEdgeType; object schemas for
// SectionInfo, SegmentInfo, PeInfo, ElfInfo, MachOInfo
// (format pass), ImportEntry, ExportEntry, Suspicious
// Combination, ImportMitreMapping, ImportStatistics
// (import pass), ExtractedString, StringStatistics
// (string pass), SectionEntropy, PackingIndicator
// (entropy pass), InstructionInfo, BasicBlockInfo,
// CfgNode, CfgEdge, FunctionCfg, FunctionInfo
// (disassembly pass), ScoringDetail, ScoringCategory,
// ThreatMitreMapping, YaraMetadata, YaraStringMatch,
// YaraMatch (threat pass); and top-level composite
// schemas FormatResult, ImportResult, StringResult,
// EntropyResult, DisassemblyResult, ThreatResult,
// AnalysisPasses (all six optional), AnalysisResponse,
// UploadResponse, and ApiErrorBody. Every API response
// is parsed through these schemas before reaching
// components
//
// Connects to:
//   api/types    - z.infer exports for each schema
//   api/hooks    - AnalysisResponseSchema, UploadResponse
//                  Schema used in parse() calls
//   Rust types   - mirrors types.rs serde output exactly
// ===================

import { z } from 'zod'

export const BinaryFormatSchema = z.enum(['Elf', 'Pe', 'MachO'])

export const ArchitectureSchema = z.union([
  z.literal(['X86', 'X86_64', 'Arm', 'Aarch64']),
  z.object({ Other: z.string() }),
])

export const EndiannessSchema = z.enum(['Little', 'Big'])

export const RiskLevelSchema = z.enum([
  'Benign',
  'Low',
  'Medium',
  'High',
  'Critical',
])

export const SeveritySchema = z.enum(['Low', 'Medium', 'High', 'Critical'])

export const StringEncodingSchema = z.enum(['Ascii', 'Utf8', 'Utf16Le'])

export const StringCategorySchema = z.enum([
  'Url',
  'IpAddress',
  'FilePath',
  'RegistryKey',
  'ShellCommand',
  'CryptoWallet',
  'Email',
  'SuspiciousApi',
  'PackerSignature',
  'DebugArtifact',
  'AntiAnalysis',
  'PersistencePath',
  'EncodedData',
  'Generic',
])

export const EntropyClassificationSchema = z.enum([
  'Plaintext',
  'NativeCode',
  'Compressed',
  'Packed',
  'Encrypted',
])

export const EntropyFlagSchema = z.enum([
  'HighEntropy',
  'HighVirtualToRawRatio',
  'EmptyRawData',
  'Rwx',
  'PackerSectionName',
])

export const FlowControlTypeSchema = z.enum([
  'Next',
  'Branch',
  'ConditionalBranch',
  'Call',
  'Return',
  'Interrupt',
])

export const CfgEdgeTypeSchema = z.enum([
  'Fallthrough',
  'ConditionalTrue',
  'ConditionalFalse',
  'Unconditional',
  'Call',
])

export const SectionPermissionsSchema = z.object({
  read: z.boolean(),
  write: z.boolean(),
  execute: z.boolean(),
})

export const SectionInfoSchema = z.object({
  name: z.string(),
  virtual_address: z.number(),
  virtual_size: z.number(),
  raw_offset: z.number(),
  raw_size: z.number(),
  permissions: SectionPermissionsSchema,
  sha256: z.string(),
})

export const SegmentInfoSchema = z.object({
  name: z.string().nullable(),
  virtual_address: z.number(),
  virtual_size: z.number(),
  file_offset: z.number(),
  file_size: z.number(),
  permissions: SectionPermissionsSchema,
})

export const FormatAnomalySchema = z.union([
  z.string(),
  z.record(z.string(), z.unknown()),
])

export const PeDllCharacteristicsSchema = z.object({
  aslr: z.boolean(),
  dep: z.boolean(),
  cfg: z.boolean(),
  no_seh: z.boolean(),
  force_integrity: z.boolean(),
})

export const PeInfoSchema = z.object({
  image_base: z.number(),
  subsystem: z.string(),
  dll_characteristics: PeDllCharacteristicsSchema,
  timestamp: z.number(),
  linker_version: z.string(),
  tls_callback_count: z.number(),
  has_overlay: z.boolean(),
  overlay_size: z.number(),
  rich_header_present: z.boolean(),
})

export const ElfInfoSchema = z.object({
  os_abi: z.string(),
  elf_type: z.string(),
  interpreter: z.string().nullable(),
  gnu_relro: z.boolean(),
  bind_now: z.boolean(),
  stack_executable: z.boolean(),
  needed_libraries: z.array(z.string()),
})

export const MachOInfoSchema = z.object({
  file_type: z.string(),
  cpu_subtype: z.string(),
  is_universal: z.boolean(),
  has_code_signature: z.boolean(),
  min_os_version: z.string().nullable(),
  sdk_version: z.string().nullable(),
  dylibs: z.array(z.string()),
  has_function_starts: z.boolean(),
})

export const FormatResultSchema = z.object({
  format: BinaryFormatSchema,
  architecture: ArchitectureSchema,
  bits: z.number(),
  endianness: EndiannessSchema,
  entry_point: z.number(),
  is_stripped: z.boolean(),
  is_pie: z.boolean(),
  has_debug_info: z.boolean(),
  sections: z.array(SectionInfoSchema),
  segments: z.array(SegmentInfoSchema),
  anomalies: z.array(FormatAnomalySchema),
  pe_info: PeInfoSchema.nullable(),
  elf_info: ElfInfoSchema.nullable(),
  macho_info: MachOInfoSchema.nullable(),
  function_hints: z.array(z.number()).default([]),
})

export const ImportEntrySchema = z.object({
  library: z.string(),
  function: z.string(),
  address: z.number().nullable(),
  ordinal: z.number().nullable(),
  is_suspicious: z.boolean(),
  threat_tags: z.array(z.string()),
})

export const ExportEntrySchema = z.object({
  name: z.string().nullable(),
  address: z.number(),
  ordinal: z.number().nullable(),
  is_forwarded: z.boolean(),
  forward_target: z.string().nullable(),
})

export const SuspiciousCombinationSchema = z.object({
  name: z.string(),
  description: z.string(),
  apis: z.array(z.string()),
  mitre_id: z.string(),
  severity: SeveritySchema,
})

export const ImportMitreMappingSchema = z.object({
  technique_id: z.string(),
  api: z.string(),
  tag: z.string(),
})

export const ImportStatisticsSchema = z.object({
  total_imports: z.number(),
  total_exports: z.number(),
  suspicious_count: z.number(),
  library_count: z.number(),
})

export const ImportResultSchema = z.object({
  imports: z.array(ImportEntrySchema),
  exports: z.array(ExportEntrySchema),
  libraries: z.array(z.string()),
  suspicious_combinations: z.array(SuspiciousCombinationSchema),
  mitre_mappings: z.array(ImportMitreMappingSchema),
  statistics: ImportStatisticsSchema,
})

export const ExtractedStringSchema = z.object({
  value: z.string(),
  offset: z.number(),
  encoding: StringEncodingSchema,
  length: z.number(),
  category: StringCategorySchema,
  is_suspicious: z.boolean(),
  section: z.string().nullable(),
})

export const StringStatisticsSchema = z.object({
  total: z.number(),
  by_encoding: z.record(z.string(), z.number()),
  by_category: z.record(z.string(), z.number()),
  suspicious_count: z.number(),
})

export const StringResultSchema = z.object({
  strings: z.array(ExtractedStringSchema),
  statistics: StringStatisticsSchema,
})

export const SectionEntropySchema = z.object({
  name: z.string(),
  entropy: z.number(),
  size: z.number(),
  classification: EntropyClassificationSchema,
  virtual_to_raw_ratio: z.number(),
  is_anomalous: z.boolean(),
  flags: z.array(EntropyFlagSchema),
})

export const PackingIndicatorSchema = z.object({
  indicator_type: z.string(),
  description: z.string(),
  evidence: z.string(),
  packer_name: z.string().nullable(),
})

export const EntropyResultSchema = z.object({
  overall_entropy: z.number(),
  sections: z.array(SectionEntropySchema),
  packing_detected: z.boolean(),
  packer_name: z.string().nullable(),
  packing_indicators: z.array(PackingIndicatorSchema),
})

export const InstructionInfoSchema = z.object({
  address: z.number(),
  bytes: z.array(z.number()),
  mnemonic: z.string(),
  operands: z.string(),
  size: z.number(),
  flow_control: FlowControlTypeSchema,
})

export const BasicBlockInfoSchema = z.object({
  start_address: z.number(),
  end_address: z.number(),
  instruction_count: z.number(),
  instructions: z.array(InstructionInfoSchema),
  successors: z.array(z.number()),
  predecessors: z.array(z.number()),
})

export const CfgNodeSchema = z.object({
  id: z.number(),
  label: z.string(),
  instruction_count: z.number(),
  instructions_preview: z.string(),
})

export const CfgEdgeSchema = z.object({
  from: z.number(),
  to: z.number(),
  edge_type: CfgEdgeTypeSchema,
})

export const FunctionCfgSchema = z.object({
  nodes: z.array(CfgNodeSchema),
  edges: z.array(CfgEdgeSchema),
})

export const FunctionInfoSchema = z.object({
  address: z.number(),
  name: z.string().nullable(),
  size: z.number(),
  instruction_count: z.number(),
  basic_blocks: z.array(BasicBlockInfoSchema),
  is_entry_point: z.boolean(),
  cfg: FunctionCfgSchema,
})

export const DisassemblyResultSchema = z.object({
  functions: z.array(FunctionInfoSchema),
  total_instructions: z.number(),
  total_functions: z.number(),
  architecture_bits: z.number(),
  entry_function_address: z.number(),
})

export const ScoringDetailSchema = z.object({
  rule: z.string(),
  points: z.number(),
  evidence: z.string(),
})

export const ScoringCategorySchema = z.object({
  name: z.string(),
  score: z.number(),
  max_score: z.number(),
  details: z.array(ScoringDetailSchema),
})

export const ThreatMitreMappingSchema = z.object({
  technique_id: z.string(),
  technique_name: z.string(),
  tactic: z.string(),
  evidence: z.string(),
})

export const YaraMetadataSchema = z.object({
  description: z.string().nullable(),
  category: z.string().nullable(),
  severity: z.string().nullable(),
})

export const YaraStringMatchSchema = z.object({
  identifier: z.string(),
  match_count: z.number(),
})

export const YaraMatchSchema = z.object({
  rule_name: z.string(),
  tags: z.array(z.string()),
  metadata: YaraMetadataSchema,
  matched_strings: z.array(YaraStringMatchSchema),
})

export const ThreatResultSchema = z.object({
  total_score: z.number(),
  risk_level: RiskLevelSchema,
  categories: z.array(ScoringCategorySchema),
  mitre_techniques: z.array(ThreatMitreMappingSchema),
  yara_matches: z.array(YaraMatchSchema),
  summary: z.string(),
})

export const AnalysisPassesSchema = z.object({
  format: FormatResultSchema.optional(),
  imports: ImportResultSchema.optional(),
  strings: StringResultSchema.optional(),
  entropy: EntropyResultSchema.optional(),
  disassembly: DisassemblyResultSchema.optional(),
  threat: ThreatResultSchema.optional(),
})

export const AnalysisResponseSchema = z.object({
  id: z.string(),
  sha256: z.string(),
  file_name: z.string(),
  file_size: z.number(),
  format: z.string(),
  architecture: z.string(),
  entry_point: z.number().nullable(),
  threat_score: z.number().nullable(),
  risk_level: z.string().nullable(),
  slug: z.string(),
  created_at: z.string(),
  passes: AnalysisPassesSchema,
})

export const UploadResponseSchema = z.object({
  slug: z.string(),
  cached: z.boolean(),
})

export const ApiErrorBodySchema = z.object({
  error: z.object({
    code: z.string(),
    message: z.string(),
  }),
})
