from reveng_nexus.workflows import build_analysis_plan


def test_android_plan_prefers_mobile_static_capabilities():
    plan = build_analysis_plan(
        "android_apk",
        [
            {"id": "jadx", "enabled": True, "capabilities": ["android", "apk"]},
            {"id": "ida", "enabled": True, "capabilities": ["native", "ida"]},
        ],
        [{"name": "jadx__get_manifest", "description": "Read the manifest"}],
    )
    assert plan["target_kind"] == "android_apk"
    assert plan["available_provider_ids"] == ["jadx"]
    assert any(step["step"] == "runtime" for step in plan["suggested_steps"])


def test_unknown_type_falls_back_safely():
    plan = build_analysis_plan("made_up", [], [])
    assert plan["target_kind"] == "unknown"
    assert plan["mode"] == "read-only-first"
    assert plan["available_provider_ids"] == []
