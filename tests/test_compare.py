from reveng_nexus.compare import Observation, compare_observations, decompile_features, disassembly_features

GHIDRA_MAIN = (
    "undefined8 main(void)\n{\n  uVar1 = add_numbers(2,3);\n  check_key(uVar1);\n  get_greeting();\n  return 0;\n}\n"
)
IDA_MAIN = "__int64 main()\n{\n  unsigned int v0 = add_numbers(2LL, 3LL);\n  check_key(v0);\n  get_greeting();\n  return 0LL;\n}\n"
ALT_MAIN = "int main(void)\n{\n  int r = add_numbers(2, 3);\n  validate_key(r);\n  return 0;\n}\n"


def obs(pid, family, code=None, address=0x400119, base=0x400000, kind="engine_derived", size=None, instructions=None):
    return Observation(
        evidence_id=f"ev_{pid}",
        provider_id=pid,
        engine_family=family,
        evidence_kind=kind,
        address=address,
        name="main",
        image_base=base,
        size=size,
        code=code,
        instructions=instructions,
    )


def test_features_ignore_types_keywords_and_own_name():
    f = decompile_features(GHIDRA_MAIN, "main")
    assert f["calls"] == {"add_numbers", "check_key", "get_greeting"}
    assert f["constants"] == {2, 3}
    assert f["param_count"] == 0
    assert f["control"]["return"] == 1


def test_independent_families_agree():
    result = compare_observations(
        [obs("ghidra", "ghidra", GHIDRA_MAIN), obs("ida", "ida", GHIDRA_MAIN)], reference_image_base=0x400000
    )
    assert result["assessment"] == "independent_agreement" and result["confidence"] == "high"
    assert not result["disagreements"]


def test_same_family_is_consistency_not_corroboration():
    result = compare_observations(
        [obs("remcp", "ghidra", GHIDRA_MAIN), obs("mcpy", "ghidra", GHIDRA_MAIN)], reference_image_base=0x400000
    )
    assert result["assessment"] == "same_family_consistency"
    assert "not independent" in " ".join(result["rationale"])


def test_callee_disagreement_is_preserved():
    result = compare_observations(
        [obs("ghidra", "ghidra", GHIDRA_MAIN), obs("other", "binaryninja", ALT_MAIN)], reference_image_base=0x400000
    )
    assert result["assessment"] == "disagreement" and result["confidence"] == "low"
    callees = next(d for d in result["disagreements"] if d["aspect"] == "callees")
    assert callees["values"]["ghidra"] == ["check_key", "get_greeting"]
    assert callees["values"]["other"] == ["validate_key"]


def test_rebasing_handles_engines_with_different_load_addresses():
    # e.g. a PIE loaded at 0x100000 by one engine and at 0 by another
    a = obs("ghidra", "ghidra", GHIDRA_MAIN, address=0x101119, base=0x100000)
    b = obs("ida", "ida", GHIDRA_MAIN, address=0x1119, base=0x0)
    result = compare_observations([a, b], reference_image_base=0)
    assert result["assessment"] == "independent_agreement"
    assert {row["rva"] for row in result["identity"]} == {0x1119}


def test_unrebased_start_mismatch_is_a_high_severity_disagreement():
    a = obs("ghidra", "ghidra", GHIDRA_MAIN, address=0x400119)
    b = obs("ida", "ida", GHIDRA_MAIN, address=0x40011D)  # boundary recovered 4 bytes later
    result = compare_observations([a, b], reference_image_base=0x400000)
    start = next(d for d in result["disagreements"] if d["aspect"] == "function_start")
    assert start["severity"] == "high" and result["assessment"] == "disagreement"


def test_unknown_base_is_reported_as_a_limitation():
    a = obs("ghidra", "ghidra", GHIDRA_MAIN, base=None)
    b = obs("ida", "ida", GHIDRA_MAIN)
    result = compare_observations([a, b], reference_image_base=0x400000)
    assert any("image base unknown" in lim for lim in result["limitations"])


def test_size_disagreement_against_symbol_table():
    sym = obs("file_symbol_table", "nexus-formats", None, size=38, kind="direct_observation")
    eng = obs("remcp", "ghidra", GHIDRA_MAIN, size=1)
    result = compare_observations([sym, eng], reference_image_base=0x400000, reference_bounds={"size": 38})
    size = next(d for d in result["disagreements"] if d["aspect"] == "function_size")
    assert size["values"]["remcp"] == 1 and size["values"]["file_symbol_table"] == 38


def test_identity_only_rows_do_not_inflate_content_agreement():
    sym = obs("file_symbol_table", "nexus-formats", None, kind="direct_observation")
    result = compare_observations(
        [sym, obs("remcp", "ghidra", GHIDRA_MAIN), obs("mcpy", "ghidra", GHIDRA_MAIN)], reference_image_base=0x400000
    )
    assert result["assessment"] == "same_family_consistency"


def test_ai_output_never_raises_confidence_and_is_checked():
    engines = [obs("ghidra", "ghidra", GHIDRA_MAIN)]
    ai = obs("llm", "llm4decompile", ALT_MAIN, kind="ai_generated")
    result = compare_observations([*engines, ai], reference_image_base=0x400000)
    assert result["assessment"] == "single_source"
    check = result["ai_checks"][0]
    assert check["calls_not_seen_in_engines"] == ["validate_key"]
    assert "unsupported" in check["interpretation"]


def test_disassembly_call_targets_are_rebased():
    insn_a = [{"address": 0x400127, "mnemonic": "call", "op_str": "0x400100"}]
    insn_b = [{"address": 0x401127, "mnemonic": "call", "op_str": "0x401100"}]
    assert (
        disassembly_features(insn_a, 0x400000)["call_targets"] == disassembly_features(insn_b, 0x401000)["call_targets"]
    )
    result = compare_observations(
        [
            obs("a", "ghidra", instructions=insn_a),
            obs("b", "capstone", instructions=insn_b, address=0x401119, base=0x401000),
        ],
        reference_image_base=0x400000,
    )
    assert not [d for d in result["disagreements"] if d["aspect"] == "instruction_call_targets"]


def test_ida_style_numeric_suffixes_compare_with_ghidra():
    result = compare_observations(
        [obs("ghidra", "ghidra", GHIDRA_MAIN), obs("ida", "ida", IDA_MAIN)], reference_image_base=0x400000
    )
    assert not [d for d in result["disagreements"] if d["aspect"] in {"callees", "constants"}]
    assert decompile_features("x = f(0x10u, 7ULL);")["constants"] == {0x10, 7}


def test_capstone_listing_does_not_upgrade_same_family_pseudocode():
    """Regression for the live run: two Ghidra wrappers + Capstone were rated 'independent_agreement'."""
    insns = [{"address": 0x400127, "mnemonic": "call", "op_str": "0x400100"}]
    result = compare_observations(
        [
            obs("remcp", "ghidra", GHIDRA_MAIN),
            obs("mcpy", "ghidra", GHIDRA_MAIN),
            obs("remcp:disasm", "ghidra", instructions=insns),
            obs("builtin:disasm", "capstone", instructions=insns),
        ],
        reference_image_base=0x400000,
    )
    assert result["by_group"]["decompilation"]["assessment"] == "same_family_consistency"
    assert result["by_group"]["disassembly"]["assessment"] == "independent_agreement"
    assert result["assessment"] == "same_family_consistency" and result["confidence"] == "medium"
