// ©AngelaMos | 2026
// disasm.rs
//
// Recursive descent disassembly and CFG construction pass
//
// DisasmPass depends on format and performs recursive
// descent disassembly of x86 and x86_64 binaries using
// the iced-x86 decoder with Intel syntax formatting.
// Non-x86 architectures receive an empty result.
// disassemble seeds a function queue from the entry point
// and format-provided function hints, then iterates
// through function addresses with caps of 1000 functions
// and 50000 total instructions. disassemble_function
// performs worklist-driven linear sweep within a single
// function, decoding instructions and tracking block
// leaders from branch targets and fallthroughs.
// Conditional branches split into taken/fallthrough
// successors, unconditional branches follow the target,
// and returns/interrupts terminate the block. Call
// instructions discover new function entry points added
// to the outer queue. build_basic_blocks partitions
// decoded instructions by block leaders and terminators,
// computing successor and predecessor edges.
// finalize_block determines successors from branch targets
// and fallthroughs. build_cfg emits CfgNode and CfgEdge
// structs with ConditionalTrue/ConditionalFalse/
// Unconditional/Fallthrough edge types, limited to
// functions with 500 or fewer instructions.
// vaddr_to_offset translates virtual addresses to file
// offsets via section mappings. disassemble_code provides
// a standalone linear disassembly API. Unit tests verify
// simple function disassembly, basic block splitting on
// conditional branches, CFG edge generation, non-x86
// empty results, ELF disassembly, and context population.
//
// Connects to:
//   pass.rs        - AnalysisPass trait, Sealed
//   context.rs     - AnalysisContext
//   formats/mod.rs - SectionInfo
//   types.rs       - Architecture, CfgEdgeType,
//                     FlowControlType
//   error.rs       - EngineError

use std::collections::{
    BTreeMap, HashMap, HashSet, VecDeque,
};

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter,
    Instruction, IntelFormatter,
};
use serde::{Deserialize, Serialize};

use crate::context::AnalysisContext;
use crate::error::EngineError;
use crate::formats::SectionInfo;
use crate::pass::{AnalysisPass, Sealed};
use crate::types::{
    Architecture, CfgEdgeType, FlowControlType,
};

const MAX_FUNCTIONS: usize = 1000;
const MAX_INSTRUCTIONS: usize = 50_000;
const CFG_INSTRUCTION_LIMIT: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyResult {
    pub functions: Vec<FunctionInfo>,
    pub total_instructions: usize,
    pub total_functions: usize,
    pub architecture_bits: u8,
    pub entry_function_address: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionInfo {
    pub address: u64,
    pub name: Option<String>,
    pub size: u64,
    pub instruction_count: usize,
    pub basic_blocks: Vec<BasicBlockInfo>,
    pub is_entry_point: bool,
    pub cfg: FunctionCfg,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlockInfo {
    pub start_address: u64,
    pub end_address: u64,
    pub instruction_count: usize,
    pub instructions: Vec<InstructionInfo>,
    pub successors: Vec<u64>,
    pub predecessors: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionInfo {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub size: u8,
    pub flow_control: FlowControlType,
}

#[derive(
    Debug, Clone, Default, Serialize, Deserialize,
)]
pub struct FunctionCfg {
    pub nodes: Vec<CfgNode>,
    pub edges: Vec<CfgEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgNode {
    pub id: u64,
    pub label: String,
    pub instruction_count: usize,
    pub instructions_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgEdge {
    pub from: u64,
    pub to: u64,
    pub edge_type: CfgEdgeType,
}

pub struct DisasmPass;

impl Sealed for DisasmPass {}

impl AnalysisPass for DisasmPass {
    fn name(&self) -> &'static str {
        "disasm"
    }

    fn dependencies(&self) -> &[&'static str] {
        &["format"]
    }

    fn run(
        &self,
        ctx: &mut AnalysisContext,
    ) -> Result<(), EngineError> {
        let format_result = ctx
            .format_result
            .as_ref()
            .ok_or_else(|| EngineError::MissingDependency {
                pass: "disasm".into(),
                dependency: "format".into(),
            })?;

        let arch = &format_result.architecture;
        let bits = match arch {
            Architecture::X86 => 32u32,
            Architecture::X86_64 => 64,
            _ => {
                ctx.disassembly_result =
                    Some(empty_result(
                        format_result.bits,
                        format_result.entry_point,
                    ));
                return Ok(());
            }
        };

        let data = ctx.data();
        let sections = &format_result.sections;
        let entry_point = format_result.entry_point;

        let mut seeds = vec![entry_point];
        seeds.extend_from_slice(
            &format_result.function_hints,
        );

        let result = disassemble(
            data,
            sections,
            bits,
            entry_point,
            &seeds,
        );
        ctx.disassembly_result = Some(result);
        Ok(())
    }
}

fn empty_result(
    bits: u8,
    entry_point: u64,
) -> DisassemblyResult {
    DisassemblyResult {
        functions: Vec::new(),
        total_instructions: 0,
        total_functions: 0,
        architecture_bits: bits,
        entry_function_address: entry_point,
    }
}

fn disassemble(
    data: &[u8],
    sections: &[SectionInfo],
    bits: u32,
    entry_point: u64,
    seeds: &[u64],
) -> DisassemblyResult {
    let exec_sections: Vec<&SectionInfo> = sections
        .iter()
        .filter(|s| s.permissions.execute && s.raw_size > 0)
        .collect();

    let mut functions = Vec::new();
    let mut visited_functions = HashSet::new();
    let mut total_instructions = 0;
    let mut function_queue: VecDeque<u64> =
        seeds.iter().copied().collect();

    while let Some(func_addr) = function_queue.pop_front()
    {
        if functions.len() >= MAX_FUNCTIONS
            || total_instructions >= MAX_INSTRUCTIONS
        {
            break;
        }
        if !visited_functions.insert(func_addr) {
            continue;
        }
        if vaddr_to_offset(sections, func_addr).is_none()
        {
            continue;
        }

        let (func_info, discovered_calls) =
            disassemble_function(
                data,
                sections,
                &exec_sections,
                bits,
                func_addr,
                func_addr == entry_point,
                MAX_INSTRUCTIONS - total_instructions,
            );

        total_instructions += func_info.instruction_count;
        functions.push(func_info);

        for call_target in discovered_calls {
            if !visited_functions.contains(&call_target) {
                function_queue.push_back(call_target);
            }
        }
    }

    let total_functions = functions.len();

    DisassemblyResult {
        functions,
        total_instructions,
        total_functions,
        architecture_bits: bits as u8,
        entry_function_address: entry_point,
    }
}

fn disassemble_function(
    data: &[u8],
    all_sections: &[SectionInfo],
    exec_sections: &[&SectionInfo],
    bits: u32,
    func_addr: u64,
    is_entry_point: bool,
    instruction_budget: usize,
) -> (FunctionInfo, Vec<u64>) {
    let mut decoded: BTreeMap<u64, DecodedInstruction> =
        BTreeMap::new();
    let mut block_leaders: HashSet<u64> = HashSet::new();
    let mut worklist: VecDeque<u64> = VecDeque::new();
    let mut visited: HashSet<u64> = HashSet::new();
    let mut discovered_calls: Vec<u64> = Vec::new();
    let mut formatter = IntelFormatter::new();

    block_leaders.insert(func_addr);
    worklist.push_back(func_addr);

    while let Some(addr) = worklist.pop_front() {
        if !visited.insert(addr) {
            continue;
        }
        if decoded.len() >= instruction_budget {
            break;
        }

        let offset = match vaddr_to_offset(
            all_sections,
            addr,
        ) {
            Some(o) => o as usize,
            None => continue,
        };

        if !is_in_exec_section(exec_sections, addr) {
            continue;
        }

        let remaining = data.len().saturating_sub(offset);
        if remaining == 0 {
            continue;
        }

        let slice = &data[offset..];
        let mut decoder = Decoder::with_ip(
            bits,
            slice,
            addr,
            DecoderOptions::NONE,
        );
        let mut instr = Instruction::default();

        while decoder.can_decode()
            && decoded.len() < instruction_budget
        {
            decoder.decode_out(&mut instr);
            let ip = instr.ip();

            if ip != addr && visited.contains(&ip) {
                break;
            }

            if ip != addr
                && block_leaders.contains(&ip)
            {
                break;
            }

            let fc = instr.flow_control();
            let mnemonic = format!("{:?}", instr.mnemonic())
                .to_ascii_lowercase();

            let mut operands_str = String::new();
            formatter
                .format(&instr, &mut operands_str);
            let operands = operands_str
                .split_once(' ')
                .map_or(String::new(), |(_, ops)| {
                    ops.to_string()
                });

            let instr_bytes = &data
                [offset + (ip - addr) as usize
                    ..offset
                        + (ip - addr) as usize
                        + instr.len()];

            let flow_type = map_flow_control(fc);

            decoded.insert(
                ip,
                DecodedInstruction {
                    info: InstructionInfo {
                        address: ip,
                        bytes: instr_bytes.to_vec(),
                        mnemonic,
                        operands,
                        size: instr.len() as u8,
                        flow_control: flow_type,
                    },
                    next_ip: instr.next_ip(),
                    branch_target: None,
                    fallthrough: None,
                },
            );

            match fc {
                FlowControl::ConditionalBranch => {
                    let target =
                        instr.near_branch_target();
                    let fall = instr.next_ip();

                    if let Some(di) =
                        decoded.get_mut(&ip)
                    {
                        di.branch_target = Some(target);
                        di.fallthrough = Some(fall);
                    }

                    block_leaders.insert(target);
                    block_leaders.insert(fall);
                    worklist.push_back(target);
                    worklist.push_back(fall);
                    break;
                }
                FlowControl::UnconditionalBranch => {
                    let target =
                        instr.near_branch_target();
                    if let Some(di) =
                        decoded.get_mut(&ip)
                    {
                        di.branch_target = Some(target);
                    }
                    block_leaders.insert(target);
                    worklist.push_back(target);
                    break;
                }
                FlowControl::Return
                | FlowControl::Interrupt
                | FlowControl::IndirectBranch
                | FlowControl::Exception => {
                    break;
                }
                FlowControl::Call => {
                    let target =
                        instr.near_branch_target();
                    if target != 0 {
                        discovered_calls.push(target);
                    }
                }
                FlowControl::IndirectCall => {}
                FlowControl::Next
                | FlowControl::XbeginXabortXend => {}
            }
        }
    }

    let basic_blocks = build_basic_blocks(
        &decoded,
        &block_leaders,
    );
    let instruction_count: usize = basic_blocks
        .iter()
        .map(|bb| bb.instruction_count)
        .sum();

    let size = if let (Some(first), Some(last)) = (
        decoded.keys().next(),
        decoded.keys().next_back(),
    ) {
        if let Some(last_instr) = decoded.get(last) {
            last_instr.info.address
                + last_instr.info.size as u64
                - first
        } else {
            0
        }
    } else {
        0
    };

    let cfg = if instruction_count <= CFG_INSTRUCTION_LIMIT
    {
        build_cfg(&basic_blocks)
    } else {
        FunctionCfg::default()
    };

    let func = FunctionInfo {
        address: func_addr,
        name: None,
        size,
        instruction_count,
        basic_blocks,
        is_entry_point,
        cfg,
    };

    (func, discovered_calls)
}

struct DecodedInstruction {
    info: InstructionInfo,
    next_ip: u64,
    branch_target: Option<u64>,
    fallthrough: Option<u64>,
}

fn build_basic_blocks(
    decoded: &BTreeMap<u64, DecodedInstruction>,
    leaders: &HashSet<u64>,
) -> Vec<BasicBlockInfo> {
    if decoded.is_empty() {
        return Vec::new();
    }

    let mut blocks: Vec<BasicBlockInfo> = Vec::new();
    let mut current_instrs: Vec<InstructionInfo> =
        Vec::new();
    let mut block_start: Option<u64> = None;

    for (&addr, di) in decoded {
        if leaders.contains(&addr)
            && !current_instrs.is_empty()
        {
            let bb = finalize_block(
                &current_instrs,
                block_start.unwrap_or(addr),
                decoded,
                leaders,
            );
            blocks.push(bb);
            current_instrs.clear();
            block_start = None;
        }

        if block_start.is_none() {
            block_start = Some(addr);
        }
        current_instrs.push(di.info.clone());

        let is_terminator = matches!(
            di.info.flow_control,
            FlowControlType::Branch
                | FlowControlType::ConditionalBranch
                | FlowControlType::Return
                | FlowControlType::Interrupt
        );
        if is_terminator {
            let bb = finalize_block(
                &current_instrs,
                block_start.unwrap_or(addr),
                decoded,
                leaders,
            );
            blocks.push(bb);
            current_instrs.clear();
            block_start = None;
        }
    }

    if !current_instrs.is_empty() {
        if let Some(start) = block_start {
            let bb = finalize_block(
                &current_instrs,
                start,
                decoded,
                leaders,
            );
            blocks.push(bb);
        }
    }

    let block_starts: HashSet<u64> =
        blocks.iter().map(|b| b.start_address).collect();

    for block in &mut blocks {
        block
            .successors
            .retain(|s| block_starts.contains(s));
    }

    let predecessor_map: HashMap<u64, Vec<u64>> = {
        let mut map: HashMap<u64, Vec<u64>> =
            HashMap::new();
        for block in &blocks {
            for &succ in &block.successors {
                map.entry(succ)
                    .or_default()
                    .push(block.start_address);
            }
        }
        map
    };

    for block in &mut blocks {
        block.predecessors = predecessor_map
            .get(&block.start_address)
            .cloned()
            .unwrap_or_default();
    }

    blocks
}

fn finalize_block(
    instructions: &[InstructionInfo],
    start: u64,
    decoded: &BTreeMap<u64, DecodedInstruction>,
    leaders: &HashSet<u64>,
) -> BasicBlockInfo {
    let last = instructions.last().unwrap();
    let end_address =
        last.address + last.size as u64 - 1;

    let mut successors = Vec::new();
    let last_addr = last.address;
    if let Some(di) = decoded.get(&last_addr) {
        if let Some(target) = di.branch_target {
            successors.push(target);
        }
        if let Some(fall) = di.fallthrough {
            successors.push(fall);
        } else if !matches!(
            di.info.flow_control,
            FlowControlType::Branch
                | FlowControlType::Return
                | FlowControlType::Interrupt
        ) {
            let next = di.next_ip;
            if leaders.contains(&next)
                || decoded.contains_key(&next)
            {
                successors.push(next);
            }
        }
    }

    BasicBlockInfo {
        start_address: start,
        end_address,
        instruction_count: instructions.len(),
        instructions: instructions.to_vec(),
        successors,
        predecessors: Vec::new(),
    }
}

fn build_cfg(
    blocks: &[BasicBlockInfo],
) -> FunctionCfg {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    for block in blocks {
        let preview = if block.instructions.is_empty() {
            String::new()
        } else if block.instructions.len() == 1 {
            block.instructions[0].mnemonic.clone()
        } else {
            format!(
                "{} ... {}",
                block.instructions[0].mnemonic,
                block.instructions.last().unwrap().mnemonic
            )
        };

        nodes.push(CfgNode {
            id: block.start_address,
            label: format!(
                "0x{:x}",
                block.start_address
            ),
            instruction_count: block.instruction_count,
            instructions_preview: preview,
        });

        let last_instr = block.instructions.last();
        for &succ in &block.successors {
            let edge_type =
                if let Some(last) = last_instr {
                    match last.flow_control {
                        FlowControlType::ConditionalBranch => {
                            if succ
                                == block
                                    .successors
                                    .first()
                                    .copied()
                                    .unwrap_or(0)
                            {
                                CfgEdgeType::ConditionalTrue
                            } else {
                                CfgEdgeType::ConditionalFalse
                            }
                        }
                        FlowControlType::Branch => {
                            CfgEdgeType::Unconditional
                        }
                        _ => CfgEdgeType::Fallthrough,
                    }
                } else {
                    CfgEdgeType::Fallthrough
                };

            edges.push(CfgEdge {
                from: block.start_address,
                to: succ,
                edge_type,
            });
        }
    }

    FunctionCfg { nodes, edges }
}

fn vaddr_to_offset(
    sections: &[SectionInfo],
    vaddr: u64,
) -> Option<u64> {
    sections.iter().find_map(|s| {
        if s.raw_size > 0
            && vaddr >= s.virtual_address
            && vaddr
                < s.virtual_address + s.virtual_size
        {
            Some(
                s.raw_offset
                    + (vaddr - s.virtual_address),
            )
        } else {
            None
        }
    })
}

fn is_in_exec_section(
    exec_sections: &[&SectionInfo],
    vaddr: u64,
) -> bool {
    exec_sections.iter().any(|s| {
        vaddr >= s.virtual_address
            && vaddr
                < s.virtual_address + s.virtual_size
    })
}

fn map_flow_control(
    fc: FlowControl,
) -> FlowControlType {
    match fc {
        FlowControl::Next
        | FlowControl::XbeginXabortXend => {
            FlowControlType::Next
        }
        FlowControl::UnconditionalBranch
        | FlowControl::IndirectBranch => {
            FlowControlType::Branch
        }
        FlowControl::ConditionalBranch => {
            FlowControlType::ConditionalBranch
        }
        FlowControl::Call
        | FlowControl::IndirectCall => {
            FlowControlType::Call
        }
        FlowControl::Return => FlowControlType::Return,
        FlowControl::Interrupt
        | FlowControl::Exception => {
            FlowControlType::Interrupt
        }
    }
}

pub fn disassemble_code(
    code: &[u8],
    base_addr: u64,
    bits: u32,
) -> Vec<InstructionInfo> {
    let mut decoder = Decoder::with_ip(
        bits,
        code,
        base_addr,
        DecoderOptions::NONE,
    );
    let mut formatter = IntelFormatter::new();
    let mut instr = Instruction::default();
    let mut result = Vec::new();

    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        let mnemonic = format!(
            "{:?}",
            instr.mnemonic()
        )
        .to_ascii_lowercase();

        let mut full = String::new();
        formatter.format(&instr, &mut full);
        let operands = full
            .split_once(' ')
            .map_or(String::new(), |(_, ops)| {
                ops.to_string()
            });

        let start =
            (instr.ip() - base_addr) as usize;
        let bytes =
            code[start..start + instr.len()].to_vec();

        result.push(InstructionInfo {
            address: instr.ip(),
            bytes,
            mnemonic,
            operands,
            size: instr.len() as u8,
            flow_control: map_flow_control(
                instr.flow_control(),
            ),
        });
    }

    result
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::context::BinarySource;
    use crate::types::SectionPermissions;

    fn load_fixture(name: &str) -> Vec<u8> {
        let path = format!(
            "{}/tests/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR"),
        );
        std::fs::read(&path).unwrap_or_else(|e| {
            panic!("fixture {path}: {e}")
        })
    }

    fn make_ctx(data: Vec<u8>) -> AnalysisContext {
        let size = data.len() as u64;
        AnalysisContext::new(
            BinarySource::Buffered(Arc::from(data)),
            "deadbeef".into(),
            "test.bin".into(),
            size,
        )
    }

    #[test]
    fn disassemble_simple_function() {
        let code: &[u8] = &[
            0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0,
            0x5D, 0xC3,
        ];
        let instrs =
            disassemble_code(code, 0x1000, 64);
        assert_eq!(instrs.len(), 5);
        assert_eq!(instrs[0].mnemonic, "push");
        assert_eq!(instrs[4].mnemonic, "ret");
        assert_eq!(
            instrs[4].flow_control,
            FlowControlType::Return
        );
    }

    #[test]
    fn basic_block_split_on_branch() {
        let code: &[u8] = &[
            0x31, 0xC0, 0x85, 0xC0, 0x74, 0x02,
            0x31, 0xC9, 0xC3,
        ];

        let sections = vec![SectionInfo {
            name: ".text".into(),
            virtual_address: 0x1000,
            virtual_size: code.len() as u64,
            raw_offset: 0,
            raw_size: code.len() as u64,
            permissions: SectionPermissions {
                read: true,
                write: false,
                execute: true,
            },
            sha256: String::new(),
        }];

        let result = disassemble(
            code,
            &sections,
            64,
            0x1000,
            &[0x1000],
        );
        assert!(!result.functions.is_empty());
        let func = &result.functions[0];
        assert!(
            func.basic_blocks.len() >= 2,
            "conditional branch should create multiple blocks, got {}",
            func.basic_blocks.len()
        );
    }

    #[test]
    fn cfg_edges_conditional() {
        let code: &[u8] = &[
            0x31, 0xC0, 0x85, 0xC0, 0x74, 0x02,
            0x31, 0xC9, 0xC3,
        ];

        let sections = vec![SectionInfo {
            name: ".text".into(),
            virtual_address: 0x1000,
            virtual_size: code.len() as u64,
            raw_offset: 0,
            raw_size: code.len() as u64,
            permissions: SectionPermissions {
                read: true,
                write: false,
                execute: true,
            },
            sha256: String::new(),
        }];

        let result = disassemble(
            code,
            &sections,
            64,
            0x1000,
            &[0x1000],
        );
        let func = &result.functions[0];
        assert!(
            !func.cfg.edges.is_empty(),
            "CFG should have edges"
        );
        assert!(
            !func.cfg.nodes.is_empty(),
            "CFG should have nodes"
        );
    }

    #[test]
    fn non_x86_returns_empty() {
        let data = vec![0u8; 64];
        let mut ctx = make_ctx(data);
        ctx.format_result =
            Some(crate::formats::FormatResult {
                format: crate::types::BinaryFormat::Elf,
                architecture: Architecture::Aarch64,
                bits: 64,
                endianness:
                    crate::types::Endianness::Little,
                entry_point: 0x1000,
                is_stripped: false,
                is_pie: false,
                has_debug_info: false,
                sections: Vec::new(),
                segments: Vec::new(),
                anomalies: Vec::new(),
                pe_info: None,
                elf_info: None,
                macho_info: None,
                function_hints: Vec::new(),
            });

        DisasmPass.run(&mut ctx).unwrap();
        let result = ctx.disassembly_result.unwrap();
        assert!(result.functions.is_empty());
        assert_eq!(result.total_instructions, 0);
    }

    #[test]
    fn elf_disassembly() {
        let data = load_fixture("hello_elf");
        let mut ctx = make_ctx(data);

        crate::passes::format::FormatPass
            .run(&mut ctx)
            .unwrap();
        DisasmPass.run(&mut ctx).unwrap();

        let result =
            ctx.disassembly_result.as_ref().unwrap();
        assert!(
            result.total_functions > 0,
            "should find at least one function"
        );
        assert!(result.total_instructions > 0);

        let entry_func = result.functions.iter().find(
            |f| {
                f.address
                    == result.entry_function_address
            },
        );
        assert!(
            entry_func.is_some()
                || !result.functions.is_empty(),
            "should have disassembled functions"
        );
    }

    #[test]
    fn disasm_pass_populates_context() {
        let data = load_fixture("hello_elf");
        let mut ctx = make_ctx(data);

        crate::passes::format::FormatPass
            .run(&mut ctx)
            .unwrap();
        assert!(ctx.disassembly_result.is_none());

        DisasmPass.run(&mut ctx).unwrap();
        assert!(ctx.disassembly_result.is_some());
    }
}
