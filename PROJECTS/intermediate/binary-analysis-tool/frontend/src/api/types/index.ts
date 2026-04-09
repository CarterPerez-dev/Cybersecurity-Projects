// ===================
// © AngelaMos | 2026
// index.ts
//
// Inferred TypeScript types derived from Zod schemas
// via z.infer
//
// Exports ~45 types covering every domain model in the
// analysis pipeline: enums (BinaryFormat, Architecture,
// Endianness, RiskLevel, Severity, StringEncoding,
// StringCategory, EntropyClassification, EntropyFlag,
// FlowControlType, CfgEdgeType), format structures
// (SectionPermissions, SectionInfo, SegmentInfo,
// FormatAnomaly, PeDllCharacteristics, PeInfo, ElfInfo,
// MachOInfo, FormatResult), import structures (Import
// Entry, ExportEntry, SuspiciousCombination, Import
// MitreMapping, ImportStatistics, ImportResult), string
// structures (ExtractedString, StringStatistics,
// StringResult), entropy structures (SectionEntropy,
// PackingIndicator, EntropyResult), disassembly
// structures (InstructionInfo, BasicBlockInfo, CfgNode,
// CfgEdge, FunctionCfg, FunctionInfo, Disassembly
// Result), threat structures (ScoringDetail, Scoring
// Category, ThreatMitreMapping, YaraMetadata, Yara
// StringMatch, YaraMatch, ThreatResult), and top-level
// composites (AnalysisPasses, AnalysisResponse, Upload
// Response, ApiErrorBody)
//
// Connects to:
//   api/schemas  - source schemas for z.infer
//   api/hooks    - UploadResponse, ApiErrorBody
//   pages/       - all analysis result types consumed
//                  by tab components
// ===================

import type { z } from 'zod'
import type {
  AnalysisPassesSchema,
  AnalysisResponseSchema,
  ApiErrorBodySchema,
  ArchitectureSchema,
  BasicBlockInfoSchema,
  BinaryFormatSchema,
  CfgEdgeSchema,
  CfgEdgeTypeSchema,
  CfgNodeSchema,
  DisassemblyResultSchema,
  ElfInfoSchema,
  EndiannessSchema,
  EntropyClassificationSchema,
  EntropyFlagSchema,
  EntropyResultSchema,
  ExportEntrySchema,
  ExtractedStringSchema,
  FlowControlTypeSchema,
  FormatAnomalySchema,
  FormatResultSchema,
  FunctionCfgSchema,
  FunctionInfoSchema,
  ImportEntrySchema,
  ImportMitreMappingSchema,
  ImportResultSchema,
  ImportStatisticsSchema,
  InstructionInfoSchema,
  MachOInfoSchema,
  PackingIndicatorSchema,
  PeDllCharacteristicsSchema,
  PeInfoSchema,
  RiskLevelSchema,
  ScoringCategorySchema,
  ScoringDetailSchema,
  SectionEntropySchema,
  SectionInfoSchema,
  SectionPermissionsSchema,
  SegmentInfoSchema,
  SeveritySchema,
  StringCategorySchema,
  StringEncodingSchema,
  StringResultSchema,
  StringStatisticsSchema,
  SuspiciousCombinationSchema,
  ThreatMitreMappingSchema,
  ThreatResultSchema,
  UploadResponseSchema,
  YaraMatchSchema,
  YaraMetadataSchema,
  YaraStringMatchSchema,
} from '../schemas'

export type BinaryFormat = z.infer<typeof BinaryFormatSchema>
export type Architecture = z.infer<typeof ArchitectureSchema>
export type Endianness = z.infer<typeof EndiannessSchema>
export type RiskLevel = z.infer<typeof RiskLevelSchema>
export type Severity = z.infer<typeof SeveritySchema>
export type StringEncoding = z.infer<typeof StringEncodingSchema>
export type StringCategory = z.infer<typeof StringCategorySchema>
export type EntropyClassification = z.infer<typeof EntropyClassificationSchema>
export type EntropyFlag = z.infer<typeof EntropyFlagSchema>
export type FlowControlType = z.infer<typeof FlowControlTypeSchema>
export type CfgEdgeType = z.infer<typeof CfgEdgeTypeSchema>

export type SectionPermissions = z.infer<typeof SectionPermissionsSchema>
export type SectionInfo = z.infer<typeof SectionInfoSchema>
export type SegmentInfo = z.infer<typeof SegmentInfoSchema>
export type FormatAnomaly = z.infer<typeof FormatAnomalySchema>
export type PeDllCharacteristics = z.infer<typeof PeDllCharacteristicsSchema>
export type PeInfo = z.infer<typeof PeInfoSchema>
export type ElfInfo = z.infer<typeof ElfInfoSchema>
export type MachOInfo = z.infer<typeof MachOInfoSchema>
export type FormatResult = z.infer<typeof FormatResultSchema>

export type ImportEntry = z.infer<typeof ImportEntrySchema>
export type ExportEntry = z.infer<typeof ExportEntrySchema>
export type SuspiciousCombination = z.infer<typeof SuspiciousCombinationSchema>
export type ImportMitreMapping = z.infer<typeof ImportMitreMappingSchema>
export type ImportStatistics = z.infer<typeof ImportStatisticsSchema>
export type ImportResult = z.infer<typeof ImportResultSchema>

export type ExtractedString = z.infer<typeof ExtractedStringSchema>
export type StringStatistics = z.infer<typeof StringStatisticsSchema>
export type StringResult = z.infer<typeof StringResultSchema>

export type SectionEntropy = z.infer<typeof SectionEntropySchema>
export type PackingIndicator = z.infer<typeof PackingIndicatorSchema>
export type EntropyResult = z.infer<typeof EntropyResultSchema>

export type InstructionInfo = z.infer<typeof InstructionInfoSchema>
export type BasicBlockInfo = z.infer<typeof BasicBlockInfoSchema>
export type CfgNode = z.infer<typeof CfgNodeSchema>
export type CfgEdge = z.infer<typeof CfgEdgeSchema>
export type FunctionCfg = z.infer<typeof FunctionCfgSchema>
export type FunctionInfo = z.infer<typeof FunctionInfoSchema>
export type DisassemblyResult = z.infer<typeof DisassemblyResultSchema>

export type ScoringDetail = z.infer<typeof ScoringDetailSchema>
export type ScoringCategory = z.infer<typeof ScoringCategorySchema>
export type ThreatMitreMapping = z.infer<typeof ThreatMitreMappingSchema>
export type YaraMetadata = z.infer<typeof YaraMetadataSchema>
export type YaraStringMatch = z.infer<typeof YaraStringMatchSchema>
export type YaraMatch = z.infer<typeof YaraMatchSchema>
export type ThreatResult = z.infer<typeof ThreatResultSchema>

export type AnalysisPasses = z.infer<typeof AnalysisPassesSchema>
export type AnalysisResponse = z.infer<typeof AnalysisResponseSchema>
export type UploadResponse = z.infer<typeof UploadResponseSchema>
export type ApiErrorBody = z.infer<typeof ApiErrorBodySchema>
