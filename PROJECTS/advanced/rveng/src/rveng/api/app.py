"""
©AngelaMos | 2026
app.py
"""

from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from rveng.api import schemas
from rveng.api.limits import (
    DEFAULT_SESSION,
    DEV_ORIGIN_REGEX,
    MAX_BODY_BYTES,
    MAX_DISASM_BYTES,
    MAX_HEX_BYTES,
    MAX_SESSION_LEN,
)
from rveng.api.middleware import BodySizeLimitMiddleware
from rveng.api.store import (
    ChallengeStore,
    ProgressStore,
    SqliteProgress,
    load_store,
)
from rveng.engine import cfg as cfgmod
from rveng.engine import disasm, hex as hexmod, strings, xref
from rveng.engine.challenge import Challenge, grade
from rveng.engine.discover import discover_functions
from rveng.engine.elf import ElfImage, NotAnElf
from rveng.engine.plt import plt_map


CHALLENGES_ROOT = Path(__file__).resolve().parents[3] / "challenges"


def create_app(
    store: ChallengeStore | None = None,
    progress: ProgressStore | None = None
) -> FastAPI:
    """
    Build the rveng API over a challenge store and progress store
    """
    store = store or load_store(CHALLENGES_ROOT)
    progress = progress or SqliteProgress()
    app = FastAPI(title = "rveng")
    app.add_middleware(BodySizeLimitMiddleware, max_bytes = MAX_BODY_BYTES)
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex = DEV_ORIGIN_REGEX,
        allow_methods = ["GET",
                         "POST"],
        allow_headers = ["*"],
    )

    def require(cid: str) -> Challenge:
        challenge = store.get(cid)
        if challenge is None:
            raise HTTPException(404, "challenge not found")
        return challenge

    def elf_of(challenge: Challenge) -> ElfImage:
        try:
            return ElfImage(challenge.binary)
        except NotAnElf as exc:
            raise HTTPException(422, f"not an ELF: {exc}")

    def instructions_for(image: ElfImage,
                         symbol: str | None,
                         address: int | None) -> tuple[list[disasm.Instruction],
                                                       str]:
        if symbol:
            sym = image.symbol(symbol)
            if sym is None:
                raise HTTPException(404, "symbol not found")
            if sym.size > MAX_DISASM_BYTES:
                raise HTTPException(413, "symbol too large to disassemble")
            try:
                return disasm.disassemble_symbol(image, sym), symbol
            except ValueError as exc:
                raise HTTPException(422, str(exc))
        if address is not None:
            try:
                return disasm.disassemble_at(image, address), f"sub_{address:x}"
            except ValueError as exc:
                raise HTTPException(422, str(exc))
        raise HTTPException(422, "provide a symbol or an address")

    @app.get("/api/challenges")
    def list_challenges() -> list[schemas.ChallengeSummary]:
        return [
            schemas.ChallengeSummary(id = c.id,
                                     module = c.module,
                                     title = c.title) for c in store.list()
        ]

    @app.get("/api/challenges/{cid}")
    def get_challenge(cid: str) -> schemas.ChallengeDetail:
        c = require(cid)
        return schemas.ChallengeDetail(
            id = c.id,
            module = c.module,
            title = c.title,
            mission = c.mission,
            category = c.category,
            size = len(c.binary)
        )

    @app.get("/api/challenges/{cid}/hex")
    def hex_view(
        cid: str,
        offset: int = Query(0,
                            ge = 0),
        length: int = Query(256,
                            ge = 1)
    ) -> schemas.HexView:
        c = require(cid)
        start = min(offset, len(c.binary))
        take = min(length, MAX_HEX_BYTES)
        chunk = c.binary[start : start + take]
        return schemas.HexView(
            base = start,
            length = len(chunk),
            lines = hexmod.hexdump(chunk,
                                   base = start).splitlines()
        )

    @app.get("/api/challenges/{cid}/elf")
    def elf_view(cid: str) -> schemas.ElfView:
        c = require(cid)
        image = elf_of(c)
        return schemas.ElfView(
            type = image.header.e_type,
            machine = image.header.e_machine,
            entry = image.header.e_entry,
            sections = [
                schemas.SectionView(
                    index = s.index,
                    name = s.name,
                    type = s.type_name,
                    addr = s.addr,
                    offset = s.offset,
                    size = s.size,
                    flags = s.flag_str
                ) for s in image.sections
            ],
            functions = [
                schemas.FunctionView(name = f.name,
                                     value = f.value,
                                     size = f.size) for f in image.functions() if f.name
            ],
            discovered = [
                schemas.DiscoveredFunctionView(address = d.address,
                                               label = d.label)
                for d in discover_functions(image)
            ]
        )

    @app.get("/api/challenges/{cid}/disasm")
    def disasm_view(
        cid: str,
        symbol: str | None = Query(None),
        address: int | None = Query(None,
                                    ge = 0),
        session: str = Query(DEFAULT_SESSION,
                             max_length = MAX_SESSION_LEN)
    ) -> schemas.DisasmView:
        c = require(cid)
        image = elf_of(c)
        instructions, label = instructions_for(image, symbol, address)
        imports = plt_map(image)
        solved = c.id in progress.solved(session)
        gate = disasm.find_gate(instructions) if solved else None
        gate_addr = gate.address if gate else None
        return schemas.DisasmView(
            symbol = label,
            gate_address = gate_addr,
            instructions = [
                schemas.InstructionView(
                    address = i.address,
                    mnemonic = i.mnemonic,
                    op_str = i.op_str,
                    bytes = i.raw.hex(),
                    immediate = i.immediate,
                    branch_target = i.branch_target,
                    rip_target = i.rip_target,
                    call_name = (
                        imports.get(i.branch_target) if i.mnemonic == "call" else None
                    ),
                    is_gate = (i.address == gate_addr)
                ) for i in instructions
            ]
        )

    @app.get("/api/challenges/{cid}/cfg")
    def cfg_view(
        cid: str,
        symbol: str | None = Query(None),
        address: int | None = Query(None,
                                    ge = 0)
    ) -> schemas.CfgView:
        c = require(cid)
        image = elf_of(c)
        instructions, label = instructions_for(image, symbol, address)
        graph = cfgmod.build_cfg(instructions)
        return schemas.CfgView(
            symbol = label,
            blocks = [
                schemas.CfgBlockView(
                    start = b.start,
                    end = b.end,
                    instructions = list(b.instructions)
                ) for b in graph.blocks
            ],
            edges = [
                schemas.CfgEdgeView(src = e.src,
                                    dst = e.dst,
                                    kind = e.kind) for e in graph.edges
            ]
        )

    @app.get("/api/challenges/{cid}/xrefs")
    def xrefs_view(cid: str, target: int = Query(..., ge = 0)) -> schemas.XrefsView:
        c = require(cid)
        image = elf_of(c)
        refs = xref.xrefs_to(disasm.disassemble_text(image), target)
        return schemas.XrefsView(
            target = target,
            references = [
                schemas.XrefView(
                    from_addr = r.from_addr,
                    to_addr = r.to_addr,
                    kind = r.kind
                ) for r in refs
            ]
        )

    @app.get("/api/challenges/{cid}/strings")
    def strings_view(
        cid: str,
        min_length: int = Query(4,
                                ge = 1,
                                le = 64)
    ) -> schemas.StringsView:
        c = require(cid)
        found = strings.extract(c.binary, min_length = min_length)
        return schemas.StringsView(
            strings = [
                schemas.StringView(offset = s.offset,
                                   text = s.text) for s in found
            ]
        )

    @app.post("/api/challenges/{cid}/submit")
    def submit(cid: str, body: schemas.SubmitRequest) -> schemas.SubmitResult:
        c = require(cid)
        if not body.within_limits():
            raise HTTPException(413, "answer too long")
        result = grade(c, body.answer)
        if result.correct:
            progress.mark_solved(body.session, c.id)
        return schemas.SubmitResult(
            correct = result.correct,
            message = result.message,
            revealed_source = result.revealed_source
        )

    @app.get("/api/progress")
    def get_progress(
        session: str = Query(DEFAULT_SESSION,
                             max_length = MAX_SESSION_LEN)
    ) -> schemas.ProgressView:
        solved = progress.solved(session)
        return schemas.ProgressView(
            session = session,
            solved = sorted(solved),
            total = len(store.list())
        )

    return app
