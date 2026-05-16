"""RadioRecon Opus V1 — Report Generation (HTML/JSON/CSV) with rich managerial reports."""
from __future__ import annotations
import json, csv, os, html as html_mod
from datetime import datetime
from collections import Counter


def generate_report(state, report_type: str = "technical", output_dir: str = "reports", selected_macs: list = None) -> dict:
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"bleak_{report_type}_{ts}"
    devices = state.discovered_devices
    vulns = _consolidate_findings(state, devices)
    allowed_macs = {_norm_mac(d.get("mac")) for d in devices if d.get("mac")}
    if allowed_macs:
        vulns = [v for v in vulns if _norm_mac(v.get("mac")) in allowed_macs]
    else:
        vulns = []
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in vulns:
        s = v.get("severity", "LOW")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    if report_type == "managerial":
        html_file = os.path.join(output_dir, f"{base}.html")
        note = f" ({len(selected_macs)} selecionados)" if selected_macs else ""
        html = _build_managerial_html(devices, vulns, sev_counts, ts, state, selected_note=note)
    else:
        html_file = os.path.join(output_dir, f"{base}.html")
        html = _build_technical_html(devices, vulns, state.enum_results, sev_counts, ts)

    with open(html_file, "w") as f:
        f.write(html)

    json_file = os.path.join(output_dir, f"{base}.json")
    # Collect audio exploit evidence from STATE
    audio_evidence = []
    try:
        if hasattr(state, "_wp_jobs") and state._wp_jobs:
            for jid, job in state._wp_jobs.items():
                if job.get("status") == "done" and job.get("verdict") in ("VULNERABLE",):
                    audio_evidence.append({
                        "type": jid.split("_")[0],
                        "mac": job.get("mac"),
                        "verdict": job.get("verdict"),
                        "details": job.get("details","")[:300],
                        "cves": job.get("cves", []),
                    })
        if hasattr(state, "_rec_jobs") and state._rec_jobs:
            for jid, job in state._rec_jobs.items():
                if job.get("status") == "done" and job.get("file"):
                    audio_evidence.append({
                        "type": "recording",
                        "mac": job.get("mac"),
                        "file": job.get("file"),
                        "size": job.get("size"),
                        "source": job.get("source"),
                    })
        for rec in getattr(state, "audio_evidence_archive", []) or []:
            audio_evidence.append(rec)
    except Exception:
        pass

    with open(json_file, "w") as f:
        json.dump({"report_type": report_type, "generated": ts, "version": "BLEAK_V16",
                    "summary": {"total_devices": len(devices), "total_vulnerabilities": len(vulns),
                                "severity": sev_counts, "audio_exploits": len(audio_evidence)},
                    "devices": devices, "vulnerabilities": vulns,
                    "audio_evidence": audio_evidence}, f, indent=2, default=str)

    csv_file = os.path.join(output_dir, f"{base}_findings.csv")
    with open(csv_file, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Check ID", "Name", "Severity", "Status", "Confidence", "MAC", "Device", "Evidence", "CVE", "Category", "Phase"])
        for v in vulns:
            w.writerow([v.get("check_id"), v.get("name"), v.get("severity"), v.get("status", ""),
                        v.get("confidence", ""), v.get("mac"), v.get("device_name"), v.get("evidence"),
                        v.get("cve", ""), v.get("category", ""), v.get("phase", "")])

    return {"files": [html_file, json_file, csv_file],
            "summary": {"total_devices": len(devices), "total_vulns": len(vulns), "severity": sev_counts},
            "report_type": report_type, "timestamp": ts}


def _norm_mac(mac):
    return str(mac or "").strip().upper()


def _device_for_mac(devices, mac):
    mac_u = _norm_mac(mac)
    return next((d for d in devices if _norm_mac(d.get("mac")) == mac_u), {})


def _severity_from_verdict(verdict, default="LOW"):
    v = str(verdict or "").upper()
    if v in ("VULNERABLE", "EXPLOITABLE", "CONFIRMED"):
        return "HIGH"
    if v in ("ERROR", "UNCERTAIN", "NO_RESPONSE"):
        return "MEDIUM"
    return default


def _add_finding(out, seen, finding):
    mac = _norm_mac(finding.get("mac"))
    if not mac:
        return
    check = str(finding.get("check_id") or finding.get("name") or "UNKNOWN")
    phase = str(finding.get("phase") or finding.get("category") or "general")
    evidence = str(finding.get("evidence") or "")
    key = (mac, check, phase, evidence[:120])
    if key in seen:
        return
    seen.add(key)
    finding["mac"] = mac
    finding.setdefault("severity", "LOW")
    finding.setdefault("category", phase)
    finding.setdefault("status", "VULNERABLE")
    finding.setdefault("confidence", "confirmed")
    out.append(finding)


def _consolidate_findings(state, devices):
    """Merge findings from scanners, audio jobs, exploit tabs and enumeration.

    Reports must reflect all tabs, not only the classic vulnerability scanner.
    The output is a deduplicated list using the same shape expected by the
    existing technical/managerial templates.
    """
    findings, seen = [], set()

    for v in getattr(state, "vuln_results", []) or []:
        item = dict(v)
        item.setdefault("phase", item.get("category", "vuln_scan"))
        _add_finding(findings, seen, item)

    # Audio tab jobs: WhisperPair, KBP, Find Hub, BlueSpy, RACE, recording.
    for jid, job in (getattr(state, "_wp_jobs", {}) or {}).items():
        verdict = str(job.get("verdict") or "").upper()
        if not verdict or verdict in ("PATCHED", "NOT_APPLICABLE", "SAFE"):
            continue
        mac = _norm_mac(job.get("mac"))
        dev = _device_for_mac(devices, mac)
        details = job.get("details") or "Audio security test completed"
        test_name = (job.get("test_name") or jid.split("_")[0] or "Audio").replace("-", " ").title()
        check_id = job.get("check_id") or ("AUDIO-" + test_name.upper().replace(" ", "-")[:40])
        severity = job.get("severity") or _severity_from_verdict(verdict, "MEDIUM")
        detail_l = details.lower()
        if ("whisper" in jid.lower() or "kbp" in jid.lower() or
                "kbp" in detail_l or "passkey" in detail_l or "fast pair" in detail_l):
            check_id = job.get("check_id") or "AUDIO-WHISPERPAIR-KBP"
            test_name = "WhisperPair / Fast Pair KBP"
            severity = "HIGH" if verdict == "VULNERABLE" else severity
        elif "bluespy" in jid.lower():
            check_id = job.get("check_id") or "AUDIO-BLUESPY"
            test_name = "BlueSpy Audio Pairing"
        elif "race" in jid.lower():
            check_id = job.get("check_id") or "AUDIO-RACE"
            test_name = "RACE / Airoha"
        _add_finding(findings, seen, {
            "check_id": check_id,
            "name": test_name,
            "severity": severity,
            "mac": mac,
            "device_name": job.get("device_name") or dev.get("name", "Unknown"),
            "evidence": details,
            "cve": ", ".join(job.get("cves", [])) if isinstance(job.get("cves"), list) else job.get("cve", ""),
            "category": "audio",
            "phase": "audio",
            "verdict": verdict,
            "job_id": jid,
            "steps": job.get("steps", []),
        })

    for rec in getattr(state, "audio_evidence_archive", []) or []:
        verdict = str(rec.get("verdict") or "").upper()
        if not verdict or verdict in ("PATCHED", "NOT_APPLICABLE", "SAFE"):
            continue
        mac = _norm_mac(rec.get("mac"))
        dev = _device_for_mac(devices, mac)
        test_name = rec.get("type") or "Audio Evidence"
        cves = rec.get("cves", [])
        if isinstance(cves, list):
            cves = ", ".join(c.get("cve", str(c)) if isinstance(c, dict) else str(c) for c in cves)
        _add_finding(findings, seen, {
            "check_id": rec.get("check_id") or "AUDIO-ARCHIVE-" + str(test_name).upper().replace(" ", "-")[:32],
            "name": test_name,
            "severity": rec.get("severity") or _severity_from_verdict(verdict, "MEDIUM"),
            "mac": mac,
            "device_name": rec.get("device_name") or dev.get("name", "Archived audio asset"),
            "evidence": rec.get("details") or rec.get("evidence") or "Archived audio evidence",
            "cve": cves,
            "category": "audio",
            "phase": "audio",
            "verdict": verdict,
            "job_id": rec.get("job_id"),
            "archive_id": rec.get("archive_id"),
            "steps": rec.get("steps", []),
        })

    for jid, job in (getattr(state, "_rec_jobs", {}) or {}).items():
        if not job.get("file"):
            continue
        mac = _norm_mac(job.get("mac"))
        dev = _device_for_mac(devices, mac)
        _add_finding(findings, seen, {
            "check_id": "AUDIO-RECORDING",
            "name": "Audio Capture Evidence",
            "severity": "HIGH",
            "mac": mac,
            "device_name": dev.get("name", "Unknown"),
            "evidence": "Recording captured: {} (source: {}, size: {})".format(job.get("file"), job.get("source"), job.get("size")),
            "category": "audio",
            "phase": "audio_recording",
            "job_id": jid,
        })

    for ex in (getattr(state, "exploit_results", []) or []):
        if str(ex.get("status") or "").upper() not in ("VULNERABLE", "EXPLOITABLE", "CONFIRMED"):
            continue
        macs = []
        if ex.get("mac"):
            macs.append(ex.get("mac"))
        for t in ex.get("targets", []) or []:
            if isinstance(t, dict) and t.get("mac"):
                macs.append(t.get("mac"))
        if not macs and ex.get("started"):
            continue
        for mac in macs:
            dev = _device_for_mac(devices, mac)
            _add_finding(findings, seen, {
                "check_id": ex.get("check_id") or "ATTACK-RESULT",
                "name": ex.get("test_name") or ex.get("attack") or "Attack/Exploit Result",
                "severity": ex.get("severity") or _severity_from_verdict(ex.get("status"), "HIGH"),
                "mac": mac,
                "device_name": dev.get("name", "Unknown"),
                "evidence": ex.get("evidence", ""),
                "category": ex.get("category", "exploit"),
                "phase": "exploit",
                "status": ex.get("status", "VULNERABLE"),
                "confidence": "confirmed",
                "cve": ex.get("cve", ""),
                "timestamp": ex.get("timestamp", ""),
            })

    for ex in (getattr(state, "attack_results", []) or []):
        if not ex.get("started") or ex.get("error"):
            continue
        for t in ex.get("targets", []) or []:
            if not isinstance(t, dict) or not t.get("mac"):
                continue
            mac = t.get("mac")
            dev = _device_for_mac(devices, mac)
            _add_finding(findings, seen, {
                "check_id": ex.get("check_id") or "ATTACK-EXECUTED",
                "name": ex.get("attack") or "Attack/Exploit Executed",
                "severity": "LOW",
                "mac": mac,
                "device_name": dev.get("name", "Unknown"),
                "evidence": "Attack phase executed via {}. Treat as operator evidence, not a confirmed vulnerability by itself.".format(
                    ex.get("engine", "?")),
                "category": "attack",
                "phase": "attack",
                "status": "EXECUTED",
                "confidence": "operator-evidence",
                "timestamp": ex.get("timestamp", ""),
            })

    # Enumeration is not necessarily a vulnerability, but risky exposure should
    # be visible beside other phases in the device timeline.
    for e in getattr(state, "enum_results", []) or []:
        score = int(e.get("exposure_score") or 0)
        if score < 40 and not e.get("error"):
            continue
        mac = _norm_mac(e.get("mac"))
        dev = _device_for_mac(devices, mac)
        sev = "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW"
        _add_finding(findings, seen, {
            "check_id": "ENUM-EXPOSURE",
            "name": "GATT Exposure / Enumeration",
            "severity": sev,
            "mac": mac,
            "device_name": dev.get("name", "Unknown"),
            "evidence": "Exposure score {}. Services: {}. Readable characteristics: {}. {}".format(
                score, len(e.get("services", []) or []), e.get("readable_count", 0), e.get("error", "")),
            "category": "enumeration",
            "phase": "enumeration",
        })

    return findings


def _esc(v):
    return html_mod.escape(str(v)) if v else ""


def _sev_badge(sev):
    colors = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#f59e0b", "LOW": "#3b82f6"}
    c = colors.get(sev, "#64748b")
    return f'<span style="background:{c};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600">{sev}</span>'


def _build_managerial_html(devices, vulns, sev_counts, ts, state, selected_note=""):
    total = len(devices)
    total_vulns = len(vulns)

    # Risk score
    risk_score = sev_counts.get("CRITICAL", 0) * 10 + sev_counts.get("HIGH", 0) * 6 + sev_counts.get("MEDIUM", 0) * 3 + sev_counts.get("LOW", 0)
    if risk_score == 0:
        risk_label, risk_color = "BAIXO", "#22c55e"
    elif risk_score <= 15:
        risk_label, risk_color = "MÉDIO", "#f59e0b"
    elif risk_score <= 40:
        risk_label, risk_color = "ALTO", "#f97316"
    else:
        risk_label, risk_color = "CRÍTICO", "#ef4444"

    # Domain breakdown
    domain_counts = Counter(d.get("domain", "unknown") for d in devices)
    domain_vulns = {}
    for v in vulns:
        mac = v.get("mac", "")
        dev = next((d for d in devices if d.get("mac") == mac), {})
        dom = dev.get("domain", "unknown")
        domain_vulns.setdefault(dom, {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0})
        domain_vulns[dom][v.get("severity", "LOW").lower()] = domain_vulns[dom].get(v.get("severity", "LOW").lower(), 0) + 1
        domain_vulns[dom]["total"] += 1

    # Priority actions from vulns
    recommendations = []
    seen_recs = set()
    for v in sorted(vulns, key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(x.get("severity", "LOW"))):
        rec = _get_recommendation(v)
        if rec and rec not in seen_recs:
            recommendations.append({"action": rec, "severity": v["severity"], "check": v["check_id"]})
            seen_recs.add(rec)

    # Business impact areas
    domains_found = set(d.get("domain", "") for d in devices)
    biz_impacts = []
    if "vehicle" in domains_found:
        veh_vulns = sum(1 for v in vulns if any(d.get("mac") == v.get("mac") and d.get("domain") == "vehicle" for d in devices))
        biz_impacts.append(("🚗 Continuidade Operacional (Veicular)", "CRITICAL",
                            f"{veh_vulns} achados em dispositivos veiculares. Risco de comprometimento de sistemas IVI/TCU."))
    if "iot_home" in domains_found:
        iot_vulns = sum(1 for v in vulns if any(d.get("mac") == v.get("mac") and d.get("domain") == "iot_home" for d in devices))
        biz_impacts.append(("🏠 Segurança IoT / Smart Home", "HIGH",
                            f"{iot_vulns} achados em dispositivos IoT. Risco de controle não autorizado de dispositivos inteligentes."))
    if "wearable" in domains_found:
        w_vulns = sum(1 for v in vulns if any(d.get("mac") == v.get("mac") and d.get("domain") == "wearable" for d in devices))
        biz_impacts.append(("⌚ Privacidade de Dados de Saúde", "HIGH",
                            f"{w_vulns} achados em wearables. Dados biométricos expostos — risco LGPD/GDPR."))
    if sev_counts.get("CRITICAL", 0) + sev_counts.get("HIGH", 0) > 0:
        biz_impacts.append(("🔐 Proteção de Dados (LGPD/GDPR)", "HIGH",
                            f"{sev_counts['CRITICAL'] + sev_counts['HIGH']} achados críticos/altos. Exposição de dados pessoais via BLE."))
    if total_vulns > 0:
        biz_impacts.append(("💰 Risco Financeiro e Reputacional", "MEDIUM",
                            f"{total_vulns} vulnerabilidades identificadas. Custo médio de incidente BLE: $50K–$500K."))

    # Critical findings table
    critical_findings = [v for v in vulns if v.get("severity") in ("CRITICAL", "HIGH")]
    crit_rows = ""
    for v in critical_findings[:20]:
        dev = next((d for d in devices if d.get("mac") == v.get("mac")), {})
        crit_rows += f"""<tr>
            <td>{_sev_badge(v['severity'])}</td>
            <td><strong>{_esc(v.get('device_name','?'))}</strong><br><small style="color:#94a3b8">{_esc(v['mac'])}</small><br>
            <span style="background:#1e3a5f;color:#7dd3fc;padding:1px 6px;border-radius:3px;font-size:10px">{_esc(dev.get('domain',''))}</span></td>
            <td style="font-size:11px;color:#7dd3fc">{_esc(v['check_id'])}<br><small>{_esc(v.get('phase', v.get('category','')))} • {_esc(v['name'][:50])}</small></td>
            <td style="font-size:12px">{_esc(v['evidence'][:180])}</td>
            <td style="font-size:11px;color:#fde68a">{_esc(_get_recommendation(v))}</td>
        </tr>"""
    if not crit_rows:
        crit_rows = '<tr><td colspan="5" style="color:#22c55e;text-align:center;padding:16px">✅ Nenhum achado crítico ou alto</td></tr>'

    # Device status rows
    dev_rows = ""
    for d in devices:
        d_vulns = [v for v in vulns if v.get("mac") == d.get("mac")]
        crit = sum(1 for v in d_vulns if v.get("severity") == "CRITICAL")
        high = sum(1 for v in d_vulns if v.get("severity") == "HIGH")
        med = sum(1 for v in d_vulns if v.get("severity") == "MEDIUM")
        low = sum(1 for v in d_vulns if v.get("severity") == "LOW")
        total_dv = crit + high + med + low
        status = "🔴 CRÍTICO" if crit > 0 else "🟠 ALTO" if high > 0 else "🟡 ATENÇÃO" if med > 0 else "🟢 OK"
        status_color = "#ef4444" if crit else "#f97316" if high else "#f59e0b" if med else "#22c55e"
        top_rec = _get_recommendation(d_vulns[0]) if d_vulns else "—"
        dev_rows += f"""<tr>
            <td><strong>{_esc(d.get('name','Unknown'))}</strong><br><small style="color:#94a3b8">{_esc(d['mac'])}</small></td>
            <td><span style="background:#1e3a5f;color:#7dd3fc;padding:2px 8px;border-radius:4px;font-size:11px">{_esc(d.get('domain',''))}</span></td>
            <td style="color:{status_color};font-weight:600">{status}</td>
            <td style="color:#f87171">{crit}</td><td style="color:#f97316">{high}</td><td style="color:#fbbf24">{med}</td><td style="color:#34d399">{low}</td>
            <td style="text-align:center;font-weight:600">{total_dv}</td>
            <td style="font-size:11px;color:#94a3b8">{_esc(top_rec[:120])}</td>
        </tr>"""

    # Domain risk rows
    domain_rows = ""
    for dom, counts in sorted(domain_vulns.items(), key=lambda x: -x[1]["total"]):
        pct = min(round(counts["total"] / max(total_vulns, 1) * 100), 100)
        domain_rows += f"""<tr>
            <td><strong>{_esc(dom)}</strong> ({domain_counts.get(dom,0)} devices)</td>
            <td style="color:#f87171">{counts.get('critical',0)}</td>
            <td style="color:#f97316">{counts.get('high',0)}</td>
            <td style="color:#fbbf24">{counts.get('medium',0)}</td>
            <td>{counts['total']}</td>
            <td><div style="background:#1e293b;border-radius:4px;height:8px;width:100%">
            <div style="background:#ef4444;border-radius:4px;height:8px;width:{pct}%"></div></div></td>
        </tr>"""

    # Priority actions
    prio_rows = ""
    for i, rec in enumerate(recommendations[:10], 1):
        prazo = "Imediato" if i <= 3 else "30 dias" if i <= 6 else "90 dias"
        urg = "Alta" if i <= 3 else "Média" if i <= 6 else "Baixa"
        prio_rows += f"""<tr>
            <td style="text-align:center;font-weight:700;color:#f59e0b">P{i}</td>
            <td>{_sev_badge(rec['severity'])} <span style="color:#7dd3fc;font-size:11px">{_esc(rec['check'])}</span></td>
            <td style="font-size:12px">{_esc(rec['action'])}</td>
            <td style="font-size:11px;color:#94a3b8">{prazo}</td>
            <td style="font-size:11px;color:#94a3b8">{urg}</td>
        </tr>"""
    if not prio_rows:
        prio_rows = '<tr><td colspan="5" style="color:#22c55e;text-align:center">Nenhuma ação corretiva necessária</td></tr>'

    # Business impact rows
    biz_rows = ""
    for area, sev, desc in biz_impacts:
        biz_rows += f'<tr><td style="font-size:13px">{area}</td><td>{_sev_badge(sev)}</td><td style="font-size:12px;color:#cbd5e1">{_esc(desc)}</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>BLEAK v0.1 — Relatório Gerencial BLE</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Inter',sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}}
.cover{{background:linear-gradient(135deg,#0f172a 0%,#1e1b4b 50%,#0f172a 100%);padding:60px 50px;border-bottom:3px solid #3b82f6;position:relative;overflow:hidden}}
.cover::before{{content:'';position:absolute;top:-50%;right:-20%;width:500px;height:500px;border-radius:50%;background:radial-gradient(circle,rgba(59,130,246,.15),transparent 70%);pointer-events:none}}
.cover h1{{font-size:36px;font-weight:700;color:#fff;margin-bottom:10px}} .cover h1 span{{color:#60a5fa}}
.cover-sub{{font-size:15px;color:#94a3b8;margin-bottom:30px}}
.cover-meta{{display:flex;gap:30px;flex-wrap:wrap}} .cover-meta-item{{font-size:12px;color:#64748b}} .cover-meta-item strong{{color:#94a3b8;display:block;font-size:13px}}
.risk-hero{{background:rgba(0,0,0,.3);border:2px solid {risk_color};border-radius:12px;padding:20px 28px;display:inline-flex;align-items:center;gap:18px;margin-top:24px}}
.risk-score-val{{font-size:42px;font-weight:900;color:{risk_color};line-height:1}} .risk-level{{font-size:22px;font-weight:700;color:{risk_color};letter-spacing:2px;text-transform:uppercase}}
.container{{max-width:1100px;margin:0 auto;padding:40px 30px}}
.section{{margin-bottom:40px}} .section-title{{font-size:20px;font-weight:600;color:#f8fafc;margin-bottom:18px;padding-bottom:10px;border-bottom:1px solid #1e293b}}
.kpi-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:16px;margin-bottom:24px}}
.kpi{{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:20px;text-align:center}}
.kpi-val{{font-size:36px;font-weight:800;line-height:1;margin-bottom:6px}} .kpi-lbl{{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:1px}}
.kpi.red .kpi-val{{color:#f87171}} .kpi.amber .kpi-val{{color:#fbbf24}} .kpi.green .kpi-val{{color:#34d399}} .kpi.blue .kpi-val{{color:#60a5fa}}
table{{width:100%;border-collapse:collapse}} th{{background:#1e293b;color:#94a3b8;text-align:left;padding:10px 14px;font-size:11px;letter-spacing:1px;text-transform:uppercase;border-bottom:1px solid #334155}}
td{{padding:10px 14px;border-bottom:1px solid #1e293b;font-size:13px;vertical-align:top}} tr:last-child td{{border-bottom:none}}
.card{{background:#1e293b;border:1px solid #334155;border-radius:12px;overflow:hidden;margin-bottom:20px}}
.card-header{{background:#0f172a;padding:14px 20px;border-bottom:1px solid #334155;font-size:13px;font-weight:600;color:#e2e8f0}}
.notice{{background:rgba(59,130,246,.1);border:1px solid rgba(59,130,246,.3);border-radius:8px;padding:14px 18px;font-size:12px;color:#93c5fd;margin-bottom:20px}}
.disclaimer{{background:#0f172a;border-top:1px solid #1e293b;padding:20px 30px;text-align:center;font-size:11px;color:#475569;margin-top:40px}}
@media print{{body{{background:#fff;color:#000}}.cover{{background:#fff;border-bottom:2px solid #000}}}}
</style></head><body>
<div class="cover">
<div style="display:inline-block;background:rgba(59,130,246,.2);border:1px solid #3b82f6;color:#93c5fd;padding:4px 14px;border-radius:20px;font-size:11px;letter-spacing:2px;text-transform:uppercase;margin-bottom:20px">🔐 Relatório Gerencial — Segurança BLE</div>
<h1>Diagnóstico de Risco<br><span>Bluetooth Low Energy</span></h1>
<div class="cover-sub">Avaliação de segurança de dispositivos BLE • Destinado à liderança executiva e gerencial</div>
<div class="cover-meta">
<div class="cover-meta-item"><strong>Data</strong>{ts}</div>
<div class="cover-meta-item"><strong>Dispositivos</strong>{total}{selected_note}</div>
<div class="cover-meta-item"><strong>Domínios</strong>{', '.join(domain_counts.keys())}</div>
<div class="cover-meta-item"><strong>Versão</strong>BLEAK v0.1</div>
</div>
<div class="risk-hero">
<div><div class="risk-score-val">{risk_score}</div><div style="font-size:13px;color:#94a3b8">RISK SCORE</div></div>
<div><div class="risk-level">{risk_label}</div><div style="font-size:13px;color:#94a3b8;margin-top:4px">{sev_counts.get('CRITICAL',0)} achado(s) crítico(s)</div></div>
</div></div>
<div class="container">
<div class="section"><div class="section-title">📊 Sumário Executivo</div>
<div class="notice">Este relatório apresenta os resultados da auditoria BLE em linguagem de negócio, com foco na priorização de ações corretivas e impacto organizacional.</div>
<div class="kpi-grid">
<div class="kpi blue"><div class="kpi-val">{total}</div><div class="kpi-lbl">Dispositivos</div></div>
<div class="kpi red"><div class="kpi-val">{sev_counts.get('CRITICAL',0)}</div><div class="kpi-lbl">Críticos</div></div>
<div class="kpi amber"><div class="kpi-val">{sev_counts.get('HIGH',0)}</div><div class="kpi-lbl">Alto Risco</div></div>
<div class="kpi {'amber' if sev_counts.get('MEDIUM',0) else 'green'}"><div class="kpi-val">{sev_counts.get('MEDIUM',0)}</div><div class="kpi-lbl">Médio</div></div>
<div class="kpi green"><div class="kpi-val">{sev_counts.get('LOW',0)}</div><div class="kpi-lbl">Baixo</div></div>
<div class="kpi blue"><div class="kpi-val">{len(recommendations)}</div><div class="kpi-lbl">Ações Corretivas</div></div>
</div></div>
<div class="section"><div class="section-title">⚠️ Riscos de Negócio Identificados</div>
<div class="card"><div class="card-header">ÁREAS DE IMPACTO ORGANIZACIONAL</div>
<table><thead><tr><th>Área de Negócio</th><th>Prioridade</th><th>Descrição do Risco</th></tr></thead>
<tbody>{biz_rows}</tbody></table></div></div>
<div class="section"><div class="section-title">🎯 Achados Críticos e de Alto Risco</div>
<div class="card"><div class="card-header">TOP {min(len(critical_findings),20)} ACHADOS PRIORITÁRIOS</div>
<table><thead><tr><th>Severidade</th><th>Dispositivo</th><th>Check</th><th>Evidência</th><th>Ação Recomendada</th></tr></thead>
<tbody>{crit_rows}</tbody></table></div></div>
<div class="section"><div class="section-title">📋 Plano de Ação Priorizado</div>
<div class="card"><div class="card-header">RECOMENDAÇÕES POR PRIORIDADE</div>
<table><thead><tr><th style="width:50px">P#</th><th>Severidade</th><th>Ação Corretiva</th><th style="width:80px">Prazo</th><th style="width:70px">Urgência</th></tr></thead>
<tbody>{prio_rows}</tbody></table></div></div>
<div class="section"><div class="section-title">📱 Status por Dispositivo</div>
<div class="card"><div class="card-header">VISÃO CONSOLIDADA</div>
<table><thead><tr><th>Dispositivo</th><th>Domínio</th><th>Status</th><th>Crítico</th><th>Alto</th><th>Médio</th><th>Baixo</th><th>Total</th><th>Ação Principal</th></tr></thead>
<tbody>{dev_rows}</tbody></table></div></div>
<div class="section"><div class="section-title">🗺️ Risco por Domínio</div>
<div class="card"><div class="card-header">EXPOSIÇÃO POR ÁREA TECNOLÓGICA</div>
<table><thead><tr><th>Domínio</th><th>Crítico</th><th>Alto</th><th>Médio</th><th>Total</th><th>Exposição</th></tr></thead>
<tbody>{domain_rows}</tbody></table></div></div>
</div>
<div class="disclaimer">Relatório gerado pela plataforma BLEAK v0.1 — BLE Security Assessment.<br>
Gerado em {ts} • Framework: NIST CSF | OWASP IoT</div>
</body></html>"""


def _build_technical_html(devices, vulns, enum_results, sev_counts, ts):
    sev_colors = {"CRITICAL": "#ff3b5c", "HIGH": "#ff6b35", "MEDIUM": "#ffb800", "LOW": "#00d4ff"}
    vuln_rows = ""
    for v in sorted(vulns, key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(x.get("severity", "LOW"))):
        color = sev_colors.get(v.get("severity"), "#ccc")
        vuln_rows += f"""<tr><td>{_esc(v.get('check_id'))}</td><td>{_esc(v.get('phase', v.get('category','')))}</td><td>{_esc(v.get('name'))}</td>
        <td style="color:{color};font-weight:bold">{_esc(v.get('severity'))}</td>
        <td><code>{_esc(v.get('mac'))}</code></td><td>{_esc(v.get('device_name'))}</td>
        <td>{_esc(v.get('evidence'))}</td><td>{_esc(v.get('cve') or '—')}</td>
        <td style="font-size:11px">{_esc(_get_recommendation(v))}</td></tr>"""
    dev_rows = ""
    for d in devices:
        dev_rows += f"""<tr><td><code>{_esc(d.get('mac'))}</code></td><td>{_esc(d.get('name','Unknown'))}</td>
        <td>{_esc(d.get('domain'))}</td><td>{_esc(d.get('vendor',''))}</td><td>{d.get('rssi','')}</td></tr>"""

    # Exploit/Spam results
    exploit_rows = ""
    exploit_results = []
    for ex in exploit_results:
        exploit_rows += f"""<tr><td>{_esc(ex.get('check_id',''))}</td><td>{_esc(ex.get('test_name', ex.get('attack','')))}</td>
        <td>{_esc(ex.get('status',''))}</td><td><code>{_esc(ex.get('mac',''))}</code></td>
        <td>{_esc(ex.get('evidence','')[:200])}</td><td>{_esc(ex.get('timestamp',''))}</td></tr>"""
    exploit_section = ""
    if exploit_rows:
        exploit_section = f"""<h2>Exploit & Attack Results ({len(exploit_results)})</h2>
<table><tr><th>ID</th><th>Test</th><th>Status</th><th>Target</th><th>Evidence</th><th>Timestamp</th></tr>{exploit_rows}</table>"""

    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>RadioRecon — Technical Report</title>
<style>body{{font-family:system-ui;background:#0a0e14;color:#c8ddf0;margin:0;padding:20px}}
h1{{color:#00d4ff;border-bottom:2px solid #1a2f4a;padding-bottom:10px}} h2{{color:#00ff88;margin-top:30px}}
table{{width:100%;border-collapse:collapse;margin:15px 0}} th,td{{border:1px solid #1a2f4a;padding:8px 12px;text-align:left}}
th{{background:#111c2a;color:#00d4ff}} tr:nth-child(even){{background:#0d1520}}
code{{background:#111c2a;padding:2px 6px;border-radius:3px;font-size:0.9em}}
.sg{{display:grid;grid-template-columns:repeat(4,1fr);gap:15px;margin:20px 0}}
.sc{{background:#111c2a;border:1px solid #1a2f4a;border-radius:8px;padding:20px;text-align:center}}
.sc .n{{font-size:2em;font-weight:bold}}</style></head><body>
<h1>📡 RadioRecon — Technical Report</h1><p>Generated: {ts}</p>
<div class="sg">
<div class="sc"><div class="n" style="color:#00d4ff">{len(devices)}</div>Devices</div>
<div class="sc"><div class="n" style="color:#ff3b5c">{sev_counts['CRITICAL']}</div>Critical</div>
<div class="sc"><div class="n" style="color:#ff6b35">{sev_counts['HIGH']}</div>High</div>
<div class="sc"><div class="n" style="color:#ffb800">{sev_counts['MEDIUM']}</div>Medium</div></div>
<h2>Discovered Devices ({len(devices)})</h2>
<table><tr><th>MAC</th><th>Name</th><th>Domain</th><th>Vendor</th><th>RSSI</th></tr>{dev_rows}</table>
<h2>Vulnerability Findings ({len(vulns)})</h2>
<table><tr><th>ID</th><th>Phase/Tab</th><th>Name</th><th>Severity</th><th>MAC</th><th>Device</th><th>Evidence</th><th>CVE</th><th>Recommendation</th></tr>{vuln_rows}</table>
{exploit_section}
<div style="margin-top:40px;padding-top:15px;border-top:1px solid #1a2f4a;color:#5a7a9a;font-size:0.9em">📡 RadioRecon — BLE Security Assessment Platform</div>
</body></html>"""


def _get_recommendation(vuln):
    recs = {
        "BLE-001": "Implementar pairing com autenticação (Passkey/OOB). Desabilitar Just Works.",
        "BLE-002": "Habilitar encryption obrigatório para todas as características sensíveis.",
        "BLE-003": "Adicionar autenticação para características write. Implementar ACLs GATT.",
        "BLE-004": "Alterar auth key padrão. Implementar key provisioning seguro.",
        "BLE-007": "Minimizar dados no advertising. Remover manufacturer data desnecessário.",
        "BLE-008": "Habilitar MAC address randomization (RPA).",
        "BLE-010": "Habilitar LE Secure Connections com ECDH P-256.",
        "BLE-012": "Proteger DFU com autenticação e assinatura de firmware.",
        "BLE-013": "Remover debug services em builds de produção.",
        "CB-BBN-001": "Atualizar kernel Linux para versão com patch BlueBorne.",
        "CB-BBN-002": "Verificar patch level Android. Security patch ≥ Setembro 2017.",
        "CB-KNB-001": "Aplicar patches KNOB. Forçar entropy mínimo de 7 bytes.",
        "CB-PLT-001": "Atualizar iOS para versão ≥ 17.1 com patch CVE-2023-45866.",
        "DS-HOM-003": "Implementar autenticação BLE para controle de dispositivos smart home.",
        "DS-BLB-001": "Adicionar autenticação para controle de lâmpadas via GATT.",
        "DS-BLB-002": "Habilitar encryption para comandos de controle de lâmpadas.",
        "DS-BLB-003": "Implementar nonce/timestamp para prevenir replay de comandos.",
        "DS-BLB-004": "Implementar verificação de assinatura para atualizações de firmware.",
    }
    check_id = vuln.get("check_id", "")
    return recs.get(check_id, f"Mitigar vulnerabilidade {check_id}: {vuln.get('name', '')}")
