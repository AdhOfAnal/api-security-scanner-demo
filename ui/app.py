from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import streamlit as st

from ui.helpers import PROJECT_ROOT, get_diff_summary, run_scan_with_managed_testbed


def _list_config_files() -> list[str]:
    config_dir = PROJECT_ROOT / "configs"
    return sorted(str(path.relative_to(PROJECT_ROOT)) for path in config_dir.glob("*.yaml"))


def _default_mode_values(mode: str) -> tuple[str, bool, bool]:
    if mode == "漏洞版扫描":
        return "configs/targets_vulnerable.yaml", False, False
    return "configs/targets_fixed.yaml", True, True


def _build_finding_rows(findings: List[Dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for idx, finding in enumerate(findings):
        rows.append(
            {
                "index": idx,
                "rule_id": finding.get("rule_id"),
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "endpoint": finding.get("endpoint"),
                "method": finding.get("method"),
            }
        )
    return rows


def main() -> None:
    st.set_page_config(page_title="API Security Scanner Demo", layout="wide")
    st.title("API Security Scanner Demo GUI")
    st.caption("本地演示界面：复用现有扫描引擎，不改核心规则。")

    mode = st.radio("扫描模式", ["漏洞版扫描", "修复版扫描"], horizontal=True)
    default_config, default_fix_users, default_fix_admin = _default_mode_values(mode)

    config_files = _list_config_files()
    default_index = config_files.index(default_config) if default_config in config_files else 0
    selected_config = st.selectbox("选择配置文件", config_files, index=default_index)
    custom_config = st.text_input("自定义配置路径（可选，留空使用上方选择）", "")
    config_path = custom_config.strip() or selected_config

    col1, col2 = st.columns(2)
    with col1:
        fix_users_auth = st.checkbox("FIX_USERS_AUTH", value=default_fix_users)
    with col2:
        fix_admin_role = st.checkbox("FIX_ADMIN_ROLE", value=default_fix_admin)

    run_clicked = st.button("执行扫描", type="primary")
    if run_clicked:
        with st.spinner("正在启动靶场并执行扫描..."):
            try:
                report = run_scan_with_managed_testbed(
                    config_path=config_path,
                    fix_users_auth=fix_users_auth,
                    fix_admin_role=fix_admin_role,
                )
            except Exception as exc:
                st.error(f"扫描失败：{exc}")
            else:
                st.success("扫描完成")
                st.session_state["last_report"] = report

    report = st.session_state.get("last_report")
    if report:
        meta = report.get("meta", {})
        findings = report.get("findings", [])

        st.subheader("扫描结果")
        st.write(
            {
                "total_findings": meta.get("total_findings", len(findings)),
                "report_path": meta.get("report_path"),
                "base_url": meta.get("base_url"),
                "generated_at": meta.get("generated_at"),
            }
        )

        rows = _build_finding_rows(findings)
        st.subheader("Findings 列表")
        st.dataframe(rows, use_container_width=True, hide_index=True)

        if rows:
            selected_idx = st.selectbox(
                "查看单条 finding 详情",
                options=[row["index"] for row in rows],
                format_func=lambda i: f"#{i} - {rows[i]['rule_id']} {rows[i]['endpoint']}",
            )
            selected_finding = findings[selected_idx]
            st.subheader("Finding 详情")
            st.write(
                {
                    "title": selected_finding.get("title"),
                    "recommendation": selected_finding.get("recommendation"),
                }
            )
            st.json(selected_finding.get("evidence", {}))

    st.subheader("报告 Diff Summary")
    if st.button("刷新 Diff Summary"):
        try:
            diff_summary = get_diff_summary()
        except Exception as exc:
            st.warning(f"无法生成 diff summary：{exc}")
        else:
            st.json(diff_summary)

    st.info(
        "提示：GUI 会临时启动本地 testbed（127.0.0.1:8000）。"
        "如果该端口已被占用，请先停止占用进程后再执行。"
    )


if __name__ == "__main__":
    main()
