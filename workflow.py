from __future__ import annotations

import asyncio
import hashlib
import platform
import re
import shutil
import socket
import subprocess
import time
from collections import Counter
from typing import Dict, List, Tuple

from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

from checks import CHECK_CATALOG, CHECK_PROFILES, enrich_device, execute_check, local_posture_findings
from models import AuditContext, AttackPlan, DeviceAnalysisResult, DeviceInventory, ExecutionPlan
from attacks import (
    ATTACK_CATALOG,
    ATTACK_PROFILES,
    AttackResult,
    execute_attack,
    show_attack_results,
)

console = Console()

try:
    from bleak import BleakScanner
except Exception:  # pragma: no cover
    BleakScanner = None


def run_cmd(cmd: List[str], timeout: int = 10) -> Tuple[int, str, str]:
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return cp.returncode, cp.stdout.strip(), cp.stderr.strip()
    except Exception as exc:
        return 1, "", f"{type(exc).__name__}: {exc}"


def have_tool(name: str) -> bool:
    return shutil.which(name) is not None


def manufacturer_name_from_id(company_id: int) -> str:
    """Resolve company ID to manufacturer name. Uses Nordic BT DB (109 entries) as primary."""
    # Try Nordic DB first (most complete)
    try:
        from nordic_ble_db import NORDIC_COMPANIES
        name = NORDIC_COMPANIES.get(company_id)
        if name:
            return name
    except ImportError:
        pass
    # Fallback minimal map
    known = {
        0x004C: "Apple Inc.",
        0x0006: "Microsoft",
        0x000F: "Broadcom",
        0x0075: "Samsung Electronics",
        0x0131: "Xiaomi Inc.",
        0x0059: "Nordic Semiconductor",
        0x00E0: "Google LLC",
        0x0171: "Amazon.com Services",
        0x000A: "CSR (Cambridge Silicon Radio)",
        0x038F: "Texas Instruments",
        0x0157: "Fitbit Inc.",
        0x01FF: "Tesla Inc.",
        0x004B: "Taiyo Yuden",
        0x01B7: "Huawei Technologies",
        0x02B0: "Amazfit / Huami",
    }
    return known.get(company_id, f"0x{company_id:04X}")


def safe_hex(data: bytes | bytearray | None, max_len: int = 64) -> str:
    if not data:
        return ""
    s = data.hex()
    return s[:max_len] + ("..." if len(s) > max_len else "")


def build_device_id(name: str, mac: str) -> str:
    base = f"{name}|{mac}".encode("utf-8")
    return hashlib.sha1(base).hexdigest()[:12].upper()


def primary_uuid(service_uuids: List[str]) -> str:
    return service_uuids[0] if service_uuids else "UNKNOWN"


def collect_local_bt_info() -> Dict[str, object]:
    info: Dict[str, object] = {
        "bluez_version": None,
        "adapter_present": False,
        "powered": None,
        "discoverable": None,
        "pairable": None,
        "bluetoothctl_raw": "",
        "btmgmt_raw": "",
        "rfkill_raw": "",
    }

    if have_tool("bluetoothctl"):
        rc, out, _ = run_cmd(["bluetoothctl", "--version"])
        if rc == 0 and out:
            info["bluez_version"] = out

        rc, out, err = run_cmd(["bluetoothctl", "show"], timeout=8)
        text = out or err
        info["bluetoothctl_raw"] = text
        if rc == 0 and out:
            info["adapter_present"] = "Controller" in out
            for key in ["Powered", "Discoverable", "Pairable"]:
                match = re.search(rf"{key}:\s+(yes|no)", out, re.I)
                if match:
                    info[key.lower()] = match.group(1).lower() == "yes"

    if have_tool("btmgmt"):
        _, out, err = run_cmd(["btmgmt", "info"], timeout=8)
        info["btmgmt_raw"] = out or err

    if have_tool("rfkill"):
        _, out, err = run_cmd(["rfkill", "list", "bluetooth"], timeout=8)
        info["rfkill_raw"] = out or err

    return info


async def discover_ble_devices(timeout: int = 12) -> List[DeviceInventory]:
    if BleakScanner is None:
        raise RuntimeError("Biblioteca bleak não encontrada. Instale os requisitos do projeto.")

    found = await BleakScanner.discover(timeout=timeout, return_adv=True)
    devices: List[DeviceInventory] = []

    for addr, (device, adv) in found.items():
        manufacturer_data = {
            manufacturer_name_from_id(company_id): safe_hex(payload)
            for company_id, payload in (adv.manufacturer_data or {}).items()
        }
        service_data = {key: safe_hex(value) for key, value in (adv.service_data or {}).items()}
        name = device.name or adv.local_name or "UNKNOWN"
        uuid = primary_uuid(list(adv.service_uuids or []))
        manufacturer = next(iter(manufacturer_data.keys()), "UNKNOWN")
        model = name if name != "UNKNOWN" else manufacturer

        dev = DeviceInventory(
            device_id=build_device_id(name, device.address or addr),
            uuid=uuid,
            model=model,
            mac=device.address or addr,
            name=name,
            manufacturer=manufacturer,
            rssi=adv.rssi,
            connectable=getattr(adv, "connectable", None),
            service_uuids=list(adv.service_uuids or []),
            manufacturer_data=manufacturer_data,
            service_data=service_data,
            metadata={
                "tx_power": getattr(adv, "tx_power", None),
                "local_name": adv.local_name,
            },
        )
        devices.append(enrich_device(dev))

    return sorted(devices, key=lambda d: (d.domain, d.asset_type, d.name or "", d.mac))


def parse_selection(text: str, max_index: int) -> List[int]:
    text = text.strip()
    if not text:
        return []
    if text == "*":
        return list(range(1, max_index + 1))

    selected = set()
    parts = [p.strip() for p in text.split(",") if p.strip()]
    for part in parts:
        if "-" in part:
            start, end = part.split("-", 1)
            start_i = int(start)
            end_i = int(end)
            for index in range(start_i, end_i + 1):
                if 1 <= index <= max_index:
                    selected.add(index)
        else:
            index = int(part)
            if 1 <= index <= max_index:
                selected.add(index)
    return sorted(selected)


def show_discovered_devices(devices: List[DeviceInventory]) -> None:
    table = Table(title="Discovery BLE")
    table.add_column("#", style="cyan", no_wrap=True)
    table.add_column("ID Device", style="magenta")
    table.add_column("Domínio")
    table.add_column("Ativo")
    table.add_column("Ecossistema")
    table.add_column("UUID")
    table.add_column("Modelo")
    table.add_column("MAC")
    table.add_column("Nome")
    table.add_column("RSSI")
    table.add_column("Conn")
    for idx, dev in enumerate(devices, 1):
        table.add_row(
            str(idx),
            dev.device_id,
            dev.domain,
            dev.asset_type,
            dev.ecosystem,
            dev.uuid,
            dev.model,
            dev.mac,
            dev.name,
            str(dev.rssi) if dev.rssi is not None else "-",
            "yes" if dev.connectable else "no" if dev.connectable is not None else "?",
        )
    console.print(table)


def show_checks() -> List[str]:
    table = Table(title="Validações Disponíveis")
    table.add_column("#", style="cyan")
    table.add_column("Check ID", style="magenta")
    table.add_column("Descrição")
    keys = list(CHECK_CATALOG.keys())
    for idx, key in enumerate(keys, 1):
        table.add_row(str(idx), key, CHECK_CATALOG[key])
    console.print(table)
    return keys


def show_profiles() -> List[str]:
    table = Table(title="Perfis de Validação")
    table.add_column("#", style="cyan")
    table.add_column("Perfil", style="magenta")
    table.add_column("Checks")
    profiles = list(CHECK_PROFILES.keys())
    for idx, profile in enumerate(profiles, 1):
        preview = ", ".join(CHECK_PROFILES[profile][:8])
        suffix = "..." if len(CHECK_PROFILES[profile]) > 8 else ""
        table.add_row(str(idx), profile, preview + suffix)
    console.print(table)
    return profiles


def build_audit_context() -> AuditContext:
    local_stack = collect_local_bt_info()
    return AuditContext(
        local_stack=local_stack,
        generated_at_epoch=int(time.time()),
        hostname=socket.gethostname(),
        platform={
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        global_findings=local_posture_findings(local_stack),
    )


def phase_discovery(plan: ExecutionPlan) -> None:
    raw = Prompt.ask("[cyan]Tempo de discovery em segundos[/cyan]", default="12")
    timeout = max(5, min(int(raw), 60))
    console.print("[cyan]Executando discovery BLE passivo...[/cyan]")
    plan.discovered_devices = asyncio.run(discover_ble_devices(timeout=timeout))
    if not plan.discovered_devices:
        console.print("[yellow]Nenhum dispositivo encontrado.[/yellow]")
        return
    show_discovered_devices(plan.discovered_devices)


def phase_select_targets(plan: ExecutionPlan) -> None:
    if not plan.discovered_devices:
        console.print("[yellow]Nenhum dispositivo descoberto ainda.[/yellow]")
        return
    show_discovered_devices(plan.discovered_devices)
    raw = Prompt.ask("[cyan]Selecione os dispositivos (* para todos, ex: 1,3-5)[/cyan]")
    indexes = parse_selection(raw, len(plan.discovered_devices))
    plan.selected_devices = [plan.discovered_devices[i - 1] for i in indexes]
    console.print(f"[green]{len(plan.selected_devices)} dispositivo(s) selecionado(s).[/green]")


def phase_select_checks(plan: ExecutionPlan) -> None:
    keys = show_checks()
    raw = Prompt.ask("[cyan]Selecione os testes (* para todos, ex: 1,2,5-7)[/cyan]")
    indexes = parse_selection(raw, len(keys))
    plan.selected_checks = [keys[i - 1] for i in indexes]
    console.print(f"[green]{len(plan.selected_checks)} validação(ões) selecionada(s).[/green]")


def phase_select_profile(plan: ExecutionPlan) -> None:
    profiles = show_profiles()
    raw = Prompt.ask("[cyan]Selecione o perfil[/cyan]")
    idx = int(raw) - 1
    profile = profiles[idx]
    plan.selected_checks = CHECK_PROFILES[profile][:]
    console.print(f"[green]Perfil '{profile}' carregado com {len(plan.selected_checks)} checks.[/green]")


def show_plan(plan: ExecutionPlan) -> None:
    console.print("\n[bold cyan]Plano Atual[/bold cyan]")
    console.print(f"Devices descobertos: {len(plan.discovered_devices)}")
    console.print(f"Devices selecionados: {len(plan.selected_devices)}")
    console.print(f"Validações selecionadas: {len(plan.selected_checks)}")
    if plan.selected_devices:
        console.print("[bold]Dispositivos:[/bold]")
        for device in plan.selected_devices:
            console.print(f" - {device.device_id} | {device.domain} | {device.asset_type} | {device.model} | {device.mac}")
    if plan.selected_checks:
        console.print("[bold]Checks:[/bold]")
        for check_id in plan.selected_checks:
            console.print(f" - {check_id} | {CHECK_CATALOG.get(check_id, check_id)}")
    if plan.executed_results:
        console.print("[bold]Resultados executados:[/bold]")
        for result in plan.executed_results:
            console.print(f" - {result.device_id} | {result.domain} | {result.asset_type} | {result.mac} | {result.overall_result}")


def clear_plan(plan: ExecutionPlan) -> None:
    plan.selected_devices.clear()
    plan.selected_checks.clear()
    plan.executed_results.clear()
    console.print("[green]Seleções e resultados limpos. Discovery mantido.[/green]")


def _count_findings(results: List[DeviceAnalysisResult]) -> Counter:
    counter = Counter()
    for result in results:
        for validation in result.validations:
            if validation.status in {"warn", "fail", "inconclusive"}:
                counter[validation.severity] += 1
    return counter


def execute_plan(plan: ExecutionPlan) -> List[DeviceAnalysisResult]:
    if not plan.selected_devices:
        console.print("[red]Nenhum dispositivo selecionado.[/red]")
        return []
    if not plan.selected_checks:
        console.print("[red]Nenhuma validação selecionada.[/red]")
        return []

    results: List[DeviceAnalysisResult] = []
    total_steps = len(plan.selected_devices) * len(plan.selected_checks)
    step = 0

    for device in plan.selected_devices:
        device_result = DeviceAnalysisResult(
            device_id=device.device_id,
            uuid=device.uuid,
            model=device.model,
            mac=device.mac,
            domain=device.domain,
            asset_type=device.asset_type,
            ecosystem=device.ecosystem,
            overall_result="pass",
            validations=[],
        )
        for check_id in plan.selected_checks:
            step += 1
            console.print(f"[cyan]Executando {step}/{total_steps}[/cyan] - {device.device_id} - {check_id}")
            device_result.validations.append(execute_check(check_id, device))

        statuses = {validation.status for validation in device_result.validations}
        if "fail" in statuses:
            device_result.overall_result = "fail"
        elif "warn" in statuses:
            device_result.overall_result = "warn"
        elif "inconclusive" in statuses:
            device_result.overall_result = "inconclusive"
        elif statuses == {"not_applicable"}:
            device_result.overall_result = "not_applicable"

        results.append(device_result)

    plan.executed_results = results
    severities = _count_findings(results)
    overall = Counter(result.overall_result for result in results)
    console.print("[bold green]Análise realizada com sucesso.[/bold green]")
    console.print(f"Dispositivos analisados: {len(results)}")
    console.print(f"Validações executadas por dispositivo: {len(plan.selected_checks)}")
    console.print(f"Resultado geral: {', '.join(f'{k}={v}' for k, v in sorted(overall.items()))}")
    if severities:
        console.print("Achados relevantes: " + ", ".join(f"{sev}={count}" for sev, count in sorted(severities.items())))
    else:
        console.print("Achados relevantes: nenhum")
    console.print("Use a opção [bold]6[/bold] para revisar o plano e gerar relatórios.")
    return results


def print_main_menu() -> None:
    console.print(
        """
[bold bright_white]=== BLE Defensive Audit - Workflow por Fases ===[/bold bright_white]
[bold cyan]── Auditoria Defensiva ──[/bold cyan]
[cyan][1][/cyan] Discovery
[cyan][2][/cyan] Selecionar alvo(s)
[cyan][3][/cyan] Selecionar validações
[cyan][4][/cyan] Selecionar perfil de validação
[cyan][5][/cyan] Executar plano
[cyan][6][/cyan] Ver plano atual / gerar relatórios
[cyan][7][/cyan] Limpar plano
[bold red]── Ataques Ativos (Ambiente de Teste) ──[/bold red]
[red][A][/red] Selecionar alvos para ataque
[red][B][/red] Selecionar ataques
[red][C][/red] Selecionar perfil de ataque
[red][D][/red] Executar ataques
[red][E][/red] Ver resultados dos ataques
[red][F][/red] Limpar plano de ataques
[cyan][Q][/cyan] Sair
"""
    )


# ---------------------------------------------------------------------------
# Fases de ataques ativos
# ---------------------------------------------------------------------------

def show_attack_catalog() -> List[str]:
    table = Table(title="[bold red]Ataques Disponíveis[/bold red]")
    table.add_column("#",          style="red",     no_wrap=True)
    table.add_column("Attack ID",  style="magenta", no_wrap=True)
    table.add_column("Descrição")
    keys = list(ATTACK_CATALOG.keys())
    for idx, key in enumerate(keys, 1):
        table.add_row(str(idx), key, ATTACK_CATALOG[key])
    console.print(table)
    return keys


def show_attack_profiles() -> List[str]:
    table = Table(title="[bold red]Perfis de Ataque[/bold red]")
    table.add_column("#",       style="red",     no_wrap=True)
    table.add_column("Perfil",  style="magenta", no_wrap=True)
    table.add_column("Ataques")
    profiles = list(ATTACK_PROFILES.keys())
    for idx, profile in enumerate(profiles, 1):
        attacks = ATTACK_PROFILES[profile]
        preview = ", ".join(attacks[:6])
        suffix  = "..." if len(attacks) > 6 else ""
        table.add_row(str(idx), profile, preview + suffix)
    console.print(table)
    return profiles


def phase_attack_select_targets(attack_plan: "AttackPlan", discovery_plan: ExecutionPlan) -> None:
    """Fase A — Selecionar alvos para ataques."""
    if not discovery_plan.discovered_devices:
        console.print("[yellow]Nenhum dispositivo descoberto. Execute a fase de discovery primeiro (opção 1).[/yellow]")
        return

    show_discovered_devices(discovery_plan.discovered_devices)
    raw = Prompt.ask(
        "[red]Selecione os dispositivos para ataque (* para todos, ex: 1,3-5)[/red]"
    )
    indexes = parse_selection(raw, len(discovery_plan.discovered_devices))
    attack_plan.selected_devices = [discovery_plan.discovered_devices[i - 1] for i in indexes]
    console.print(f"[red]{len(attack_plan.selected_devices)} dispositivo(s) selecionado(s) para ataque.[/red]")


def phase_attack_select_attacks(attack_plan: "AttackPlan") -> None:
    """Fase B — Selecionar ataques individuais."""
    keys = show_attack_catalog()
    raw = Prompt.ask(
        "[red]Selecione os ataques (* para todos, ex: 1,4-7)[/red]"
    )
    indexes = parse_selection(raw, len(keys))
    attack_plan.selected_attacks = [keys[i - 1] for i in indexes]
    console.print(f"[red]{len(attack_plan.selected_attacks)} ataque(s) selecionado(s).[/red]")


def phase_attack_select_profile(attack_plan: "AttackPlan") -> None:
    """Fase C — Selecionar perfil de ataque."""
    profiles = show_attack_profiles()
    raw = Prompt.ask("[red]Selecione o perfil[/red]")
    idx = int(raw) - 1
    if idx < 0 or idx >= len(profiles):
        console.print("[red]Perfil inválido.[/red]")
        return
    profile = profiles[idx]
    attack_plan.selected_attacks = ATTACK_PROFILES[profile][:]
    console.print(
        f"[red]Perfil '{profile}' carregado com {len(attack_plan.selected_attacks)} ataque(s).[/red]"
    )


def phase_attack_execute(attack_plan: "AttackPlan") -> List[AttackResult]:
    """Fase D — Executar ataques."""
    from rich.prompt import Confirm

    if not attack_plan.selected_devices:
        console.print("[red]Nenhum dispositivo selecionado para ataque (Fase A).[/red]")
        return []
    if not attack_plan.selected_attacks:
        console.print("[red]Nenhum ataque selecionado (Fase B ou C).[/red]")
        return []

    # Aviso ético obrigatório
    console.print(
        "\n[bold red]⚠  AVISO LEGAL / ÉTICA ⚠[/bold red]\n"
        "[yellow]Ataques ativos devem ser executados SOMENTE em ambiente de teste controlado\n"
        "com autorização prévia e explícita do proprietário do sistema alvo.\n"
        "O uso não autorizado viola leis de acesso a sistemas computacionais.[/yellow]\n"
    )
    if not Confirm.ask("[red]Confirmo que tenho autorização para executar estes ataques[/red]", default=False):
        console.print("[yellow]Execução de ataques cancelada.[/yellow]")
        return []

    results: List[AttackResult] = []
    total = len(attack_plan.selected_devices) * len(attack_plan.selected_attacks)
    step  = 0

    for device in attack_plan.selected_devices:
        console.print(
            f"\n[bold red]>>> Alvo: {device.name} | {device.mac} | {device.domain}[/bold red]"
        )
        for attack_id in attack_plan.selected_attacks:
            step += 1
            desc = ATTACK_CATALOG.get(attack_id, attack_id)
            console.print(f"[red]  [{step}/{total}] {attack_id}[/red] — {desc}")
            res = execute_attack(attack_id, device)
            results.append(res)
            # Feedback rápido
            from attacks import STATUS_COLOR, AttackStatus
            color = STATUS_COLOR.get(res.status, "white")
            console.print(f"  Status: [{color}]{res.status.value}[/{color}] | {res.summary[:80]}")

    attack_plan.executed_results = results

    # Resumo
    from collections import Counter as _Counter
    status_count = _Counter(r.status.value for r in results)
    console.print("\n[bold red]=== Resumo dos Ataques ===[/bold red]")
    for status, count in sorted(status_count.items()):
        console.print(f"  {status}: {count}")
    console.print(f"  Total: {len(results)} resultado(s)")
    console.print("\nUse a opção [bold]E[/bold] para ver resultados detalhados.")
    return results


def phase_attack_show_results(attack_plan: "AttackPlan") -> None:
    """Fase E — Exibir resultados dos ataques."""
    if not attack_plan.executed_results:
        console.print("[yellow]Nenhum resultado de ataque disponível. Execute a Fase D primeiro.[/yellow]")
        return
    show_attack_results(attack_plan.executed_results)


def phase_attack_clear(attack_plan: "AttackPlan") -> None:
    """Fase F — Limpar plano de ataques."""
    attack_plan.selected_devices.clear()
    attack_plan.selected_attacks.clear()
    attack_plan.executed_results.clear()
    console.print("[red]Plano de ataques limpo.[/red]")
