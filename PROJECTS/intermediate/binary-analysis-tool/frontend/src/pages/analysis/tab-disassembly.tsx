// ===================
// © AngelaMos | 2026
// tab-disassembly.tsx
//
// Disassembly tab with function sidebar, instruction
// table, and dagre-layouted control flow graph
//
// Renders a two-panel layout: a left sidebar listing
// all disassembled functions (address, name or sub_hex
// fallback, instruction count) with entry point
// highlighting and click-to-select via selectedAddr
// state; and a main panel showing the selected
// function's header (name, address, size, instruction
// count, block count), an InstructionTable with per-
// basic-block rows (address, hex bytes, mnemonic,
// operands) with block boundary markers, and a CfgGraph
// SVG visualization. layoutCfg uses @dagrejs/dagre for
// top-to-bottom hierarchical layout with CFG_NODE_WIDTH
// (160), CFG_NODE_HEIGHT (40), CFG_RANK_SEP (60), and
// CFG_NODE_SEP (30). CfgGraph renders nodes as labeled
// rectangles and edges as colored lines with arrowhead
// markers: Fallthrough gray, ConditionalTrue green,
// ConditionalFalse red, Unconditional blue, Call purple
//
// Connects to:
//   api/types         - AnalysisResponse, CfgEdge,
//                        CfgEdgeType, CfgNode,
//                        FunctionInfo
//   core/lib          - formatHex
//   @dagrejs/dagre    - Graph, layout for CFG
//                        positioning
//   analysis/index    - mounted in renderTab switch
//   analysis.module
//     .scss           - disasmLayout, fnSidebar,
//                        cfgContainer, cfgSvg styles
// ===================

import { layout as dagreLayout, Graph } from '@dagrejs/dagre'
import { useMemo, useState } from 'react'
import type {
  AnalysisResponse,
  CfgEdge,
  CfgEdgeType,
  CfgNode,
  FunctionInfo,
} from '@/api'
import { formatHex } from '@/core/lib'
import styles from './analysis.module.scss'

const CFG_NODE_WIDTH = 160
const CFG_NODE_HEIGHT = 40
const CFG_RANK_SEP = 60
const CFG_NODE_SEP = 30

const CFG_EDGE_COLORS: Record<CfgEdgeType, string> = {
  Fallthrough: '#6b7280',
  ConditionalTrue: '#22c55e',
  ConditionalFalse: '#ef4444',
  Unconditional: '#3b82f6',
  Call: '#a855f7',
}

interface LayoutNode {
  id: number
  x: number
  y: number
  label: string
  instructionCount: number
}

interface LayoutEdge {
  from: { x: number; y: number }
  to: { x: number; y: number }
  color: string
}

interface CfgLayout {
  nodes: LayoutNode[]
  edges: LayoutEdge[]
  width: number
  height: number
}

function layoutCfg(nodes: CfgNode[], edges: CfgEdge[]): CfgLayout {
  const g = new Graph()
  g.setGraph({
    rankdir: 'TB',
    ranksep: CFG_RANK_SEP,
    nodesep: CFG_NODE_SEP,
  })
  g.setDefaultEdgeLabel(() => ({}))

  for (const node of nodes) {
    g.setNode(String(node.id), {
      width: CFG_NODE_WIDTH,
      height: CFG_NODE_HEIGHT,
    })
  }

  for (const edge of edges) {
    g.setEdge(String(edge.from), String(edge.to))
  }

  dagreLayout(g)

  const layoutNodes: LayoutNode[] = nodes.map((node) => {
    const pos = g.node(String(node.id))
    return {
      id: node.id,
      x: pos.x,
      y: pos.y,
      label: node.label,
      instructionCount: node.instruction_count,
    }
  })

  const layoutEdges: LayoutEdge[] = edges.map((edge) => {
    const fromPos = g.node(String(edge.from))
    const toPos = g.node(String(edge.to))
    return {
      from: { x: fromPos.x, y: fromPos.y + CFG_NODE_HEIGHT / 2 },
      to: { x: toPos.x, y: toPos.y - CFG_NODE_HEIGHT / 2 },
      color: CFG_EDGE_COLORS[edge.edge_type],
    }
  })

  const graphInfo = g.graph()
  return {
    nodes: layoutNodes,
    edges: layoutEdges,
    width: (graphInfo.width ?? 400) + CFG_NODE_WIDTH,
    height: (graphInfo.height ?? 300) + CFG_NODE_HEIGHT,
  }
}

function CfgGraph({
  nodes,
  edges,
}: {
  nodes: CfgNode[]
  edges: CfgEdge[]
}): React.ReactElement {
  const layout = useMemo(() => layoutCfg(nodes, edges), [nodes, edges])
  const padX = CFG_NODE_WIDTH / 2
  const padY = CFG_NODE_HEIGHT / 2

  return (
    <div className={styles.cfgContainer}>
      <svg
        className={styles.cfgSvg}
        viewBox={`0 0 ${layout.width} ${layout.height}`}
        preserveAspectRatio="xMidYMid meet"
        role="img"
        aria-label="Control flow graph"
      >
        <title>Control flow graph</title>
        <defs>
          <marker
            id="arrowhead"
            markerWidth="8"
            markerHeight="6"
            refX="8"
            refY="3"
            orient="auto"
          >
            <polygon points="0 0, 8 3, 0 6" fill="#6b7280" />
          </marker>
        </defs>

        {layout.edges.map((edge, i) => (
          <line
            key={`edge-${i.toString()}`}
            x1={edge.from.x + padX}
            y1={edge.from.y + padY}
            x2={edge.to.x + padX}
            y2={edge.to.y + padY}
            stroke={edge.color}
            strokeWidth={1.5}
            markerEnd="url(#arrowhead)"
          />
        ))}

        {layout.nodes.map((node) => (
          <g key={node.id} transform={`translate(${node.x},${node.y})`}>
            <rect
              width={CFG_NODE_WIDTH}
              height={CFG_NODE_HEIGHT}
              fill="hsl(0, 0%, 12%)"
              stroke="hsl(0, 0%, 22%)"
              strokeWidth={1}
            />
            <text
              x={CFG_NODE_WIDTH / 2}
              y={CFG_NODE_HEIGHT / 2 - 4}
              textAnchor="middle"
              fill="hsl(0, 0%, 98%)"
              fontSize={10}
              fontFamily="monospace"
            >
              {node.label}
            </text>
            <text
              x={CFG_NODE_WIDTH / 2}
              y={CFG_NODE_HEIGHT / 2 + 10}
              textAnchor="middle"
              fill="hsl(0, 0%, 54%)"
              fontSize={9}
              fontFamily="monospace"
            >
              {node.instructionCount} insn
            </text>
          </g>
        ))}
      </svg>
    </div>
  )
}

function InstructionTable({ fn }: { fn: FunctionInfo }): React.ReactElement {
  return (
    <div className={styles.tableWrap}>
      <table className={styles.dataTable}>
        <thead>
          <tr>
            <th>ADDRESS</th>
            <th>BYTES</th>
            <th>MNEMONIC</th>
            <th>OPERANDS</th>
          </tr>
        </thead>
        <tbody>
          {fn.basic_blocks.map((block, blockIdx) => (
            <>
              {block.instructions.map((insn, i) => (
                <tr
                  key={insn.address}
                  className={`${styles.tableRow} ${i === 0 && blockIdx > 0 ? styles.blockBoundary : ''}`}
                >
                  <td className={styles.cellMono}>{formatHex(insn.address)}</td>
                  <td className={styles.cellMono}>
                    {insn.bytes
                      .map((b) => b.toString(16).padStart(2, '0'))
                      .join(' ')}
                  </td>
                  <td className={styles.cellMnemonic}>{insn.mnemonic}</td>
                  <td className={styles.cellMono}>{insn.operands}</td>
                </tr>
              ))}
            </>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function TabDisassembly({
  data,
}: {
  data: AnalysisResponse
}): React.ReactElement {
  const disasm = data.passes.disassembly
  const [selectedAddr, setSelectedAddr] = useState<number | null>(null)

  if (!disasm) {
    return (
      <div className={styles.tabPanel}>
        <span className={styles.noData}>
          Disassembly is only available for x86 and x86_64 binaries
        </span>
      </div>
    )
  }

  const selectedFn =
    disasm.functions.find((f) => f.address === selectedAddr) ??
    disasm.functions[0] ??
    null

  return (
    <div className={styles.tabPanel}>
      <div className={styles.disasmLayout}>
        <aside className={styles.fnSidebar}>
          <span className={styles.sectionLabel}>
            FUNCTIONS ({disasm.total_functions})
          </span>
          <div className={styles.fnList}>
            {disasm.functions.map((fn) => (
              <button
                key={fn.address}
                type="button"
                className={`${styles.fnItem} ${fn.address === selectedFn?.address ? styles.fnActive : ''} ${fn.is_entry_point ? styles.fnEntry : ''}`}
                onClick={() => setSelectedAddr(fn.address)}
              >
                <span className={styles.fnAddr}>{formatHex(fn.address)}</span>
                <span className={styles.fnName}>
                  {fn.name ?? `sub_${fn.address.toString(16)}`}
                </span>
                <span className={styles.fnMeta}>{fn.instruction_count} insn</span>
              </button>
            ))}
          </div>
        </aside>

        <div className={styles.disasmMain}>
          {selectedFn ? (
            <>
              <div className={styles.fnHeader}>
                <span className={styles.fnHeaderName}>
                  {selectedFn.name ?? `sub_${selectedFn.address.toString(16)}`}
                </span>
                <span className={styles.fnHeaderMeta}>
                  {formatHex(selectedFn.address)} / {selectedFn.size} bytes /{' '}
                  {selectedFn.instruction_count} instructions /{' '}
                  {selectedFn.basic_blocks.length} blocks
                </span>
              </div>
              <InstructionTable fn={selectedFn} />
              {selectedFn.cfg.nodes.length > 0 && (
                <section className={styles.overviewSection}>
                  <span className={styles.sectionLabel}>CONTROL FLOW GRAPH</span>
                  <CfgGraph
                    nodes={selectedFn.cfg.nodes}
                    edges={selectedFn.cfg.edges}
                  />
                </section>
              )}
            </>
          ) : (
            <span className={styles.noData}>No functions found</span>
          )}
        </div>
      </div>
    </div>
  )
}
