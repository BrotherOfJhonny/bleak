"""
vehicle_profiles.py
===================
Banco de dados de perfis veiculares para o mercado Latino-Americano.

Estrutura inspirada no app Torque Pro — que define PIDs por:
  - Modo OBD2 padrão (01, 03, 09) → funciona em TODOS os veículos
  - PIDs proprietários (modo 21, 22) → específicos por montadora
  - CAN IDs de controle do BCM → por plataforma/modelo

Fontes de dados (todas públicas):
  - SAE J1979 / ISO 15031-5 (OBD2 padrão)
  - opendbc / comma.ai (github.com/commaai/opendbc)
  - awesome-automotive-can-id (github.com/iDoka/awesome-automotive-can-id)
  - Torque Pro extended PID lists (community)
  - GM LAN Bible (opengarages.org)
  - Ford extended PIDs (community/reverse engineering público)
  - Honda/Toyota: openpilot DBC files

DISTINÇÃO IMPORTANTE:
  PUBLIC  = PIDs documentados em standards ou reverso-engineered públicos
  PRIVATE = PIDs proprietários conhecidos apenas por dealer tools — marcados como
            "CAPTURAR VIA VEH-001" com instrução de como obter
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional


# =============================================================================
# ESTRUTURA DE UM PERFIL
# =============================================================================
#
# PROFILE = {
#   "name":          str   — nome de exibição
#   "region":        list  — mercados (br, ar, latam, global)
#   "models":        list  — modelos populares cobertos
#   "protocol":      str   — protocolo CAN (ISO15765_11_500, ISO15765_29_500, ...)
#   "can_speed":     str   — velocidade do barramento (500k, 250k, 125k, 33.3k)
#   "bcm_addr":      str   — endereço CAN do BCM
#   "ecm_addr":      str   — endereço do ECM (motor)
#   "tcm_addr":      str   — endereço do TCM (câmbio)
#   "gateway_addr":  str   — endereço do gateway/CGW
#   "obd_pids":      list  — PIDs OBD2 padrão relevantes para este perfil
#   "custom_pids":   dict  — PIDs proprietários (modo 21/22/outros)
#   "can_signals":   dict  — sinais CAN de broadcast (leitura)
#   "bcm_controls":  dict  — IDs CAN de controle do BCM
#   "uds_sessions":  dict  — sessões UDS conhecidas
#   "security_notes":list  — observações de segurança específicas
#   "source":        str   — fonte dos dados
# }


# =============================================================================
# MODO OBD2 PADRÃO — FUNCIONA EM TODOS OS VEÍCULOS (ISO 15031-5 / SAE J1979)
# =============================================================================

OBD2_STANDARD_PIDS = {
    # ── Modo 01 — Dados em tempo real ────────────────────────────────────────
    "01 00": {"name": "PIDs suportados 01-20",     "unit": "bitmap", "mode": "standard"},
    "01 04": {"name": "Carga calculada do motor",  "unit": "%",      "mode": "standard",
              "formula": "A/2.55"},
    "01 05": {"name": "Temperatura do líquido de arrefecimento", "unit": "°C", "mode": "standard",
              "formula": "A-40"},
    "01 0B": {"name": "Pressão absoluta do MAP",   "unit": "kPa",    "mode": "standard",
              "formula": "A"},
    "01 0C": {"name": "RPM do motor",              "unit": "RPM",    "mode": "standard",
              "formula": "(256*A+B)/4"},
    "01 0D": {"name": "Velocidade do veículo",     "unit": "km/h",   "mode": "standard",
              "formula": "A"},
    "01 0E": {"name": "Avanço de ignição",         "unit": "°",      "mode": "standard",
              "formula": "A/2-64"},
    "01 0F": {"name": "Temperatura do ar admissão","unit": "°C",     "mode": "standard",
              "formula": "A-40"},
    "01 10": {"name": "Taxa de fluxo MAF",         "unit": "g/s",    "mode": "standard",
              "formula": "(256*A+B)/100"},
    "01 11": {"name": "Posição do acelerador",     "unit": "%",      "mode": "standard",
              "formula": "A/2.55"},
    "01 1F": {"name": "Tempo desde partida",       "unit": "s",      "mode": "standard",
              "formula": "256*A+B"},
    "01 21": {"name": "Distância com MIL aceso",   "unit": "km",     "mode": "standard",
              "formula": "256*A+B"},
    "01 2F": {"name": "Nível de combustível",      "unit": "%",      "mode": "standard",
              "formula": "A/2.55"},
    "01 31": {"name": "Distância desde reset DTC", "unit": "km",     "mode": "standard",
              "formula": "256*A+B"},
    "01 33": {"name": "Pressão atmosférica",       "unit": "kPa",    "mode": "standard",
              "formula": "A"},
    "01 42": {"name": "Tensão módulo de controle", "unit": "V",      "mode": "standard",
              "formula": "(256*A+B)/1000"},
    "01 43": {"name": "Carga absoluta motor",      "unit": "%",      "mode": "standard",
              "formula": "(256*A+B)/2.55"},
    "01 46": {"name": "Temperatura ambiente",      "unit": "°C",     "mode": "standard",
              "formula": "A-40"},
    "01 49": {"name": "Posição acelerador D",      "unit": "%",      "mode": "standard",
              "formula": "A/2.55"},
    "01 4D": {"name": "Tempo com MIL aceso",       "unit": "min",    "mode": "standard",
              "formula": "256*A+B"},
    "01 5C": {"name": "Temperatura óleo motor",    "unit": "°C",     "mode": "standard",
              "formula": "A-40"},
    "01 5E": {"name": "Taxa consumo combustível",  "unit": "L/h",    "mode": "standard",
              "formula": "(256*A+B)/20"},
    # ── Modo 03 — Códigos de falha ativos ─────────────────────────────────────
    "03":    {"name": "DTCs ativos (MIL on)",      "unit": "codes",  "mode": "standard"},
    "07":    {"name": "DTCs pendentes",            "unit": "codes",  "mode": "standard"},
    # ── Modo 09 — Informações do veículo ─────────────────────────────────────
    "09 02": {"name": "VIN (Vehicle ID Number)",   "unit": "string", "mode": "standard"},
    "09 04": {"name": "Calibração ECU (CAL ID)",   "unit": "string", "mode": "standard"},
    "09 06": {"name": "Calibração ECU (CVN)",      "unit": "string", "mode": "standard"},
    "09 0A": {"name": "Nome do ECU",               "unit": "string", "mode": "standard"},
}


# =============================================================================
# PERFIS POR MONTADORA — MERCADO LATINO-AMERICANO
# =============================================================================

VEHICLE_PROFILES: Dict[str, Dict[str, Any]] = {

    # ──────────────────────────────────────────────────────────────────────────
    # GENERIC — ISO 15031-5 puro, funciona em qualquer veículo OBD2
    # ──────────────────────────────────────────────────────────────────────────
    "generic": {
        "name":         "Genérico (ISO 15765-4 / OBD2 Padrão)",
        "region":       ["global"],
        "models":       ["Qualquer veículo com OBD2 (2001+)"],
        "protocol":     "ISO15765_11_500",
        "can_speed":    "500k",
        "bcm_addr":     "7B0",
        "ecm_addr":     "7E0",
        "tcm_addr":     "7E1",
        "gateway_addr": "7A0",
        "obd_pids": list(OBD2_STANDARD_PIDS.keys()),
        "custom_pids": {},  # Sem PIDs proprietários conhecidos
        "can_signals": {
            "vehicle_speed": {"id": "7E8", "byte": 3, "formula": "B",    "unit": "km/h",
                              "desc": "Velocidade (resposta OBD 010D)"},
            "engine_rpm":    {"id": "7E8", "byte": 4, "formula": "(A*256+B)/4", "unit": "RPM",
                              "desc": "RPM (resposta OBD 010C)"},
        },
        "bcm_controls": {
            "window_fl":  {"id": "CAPTURAR", "open": "CAPTURAR VIA VEH-001",
                           "close": "CAPTURAR VIA VEH-001", "desc": "Janela FL",
                           "public": False},
            "door_lock":  {"id": "CAPTURAR", "lock": "CAPTURAR VIA VEH-001",
                           "unlock": "CAPTURAR VIA VEH-001", "desc": "Travas",
                           "public": False},
            "turn_left":  {"id": "CAPTURAR", "on": "CAPTURAR VIA VEH-001",
                           "off": "CAPTURAR VIA VEH-001", "desc": "Seta esq.",
                           "public": False},
            "turn_right": {"id": "CAPTURAR", "on": "CAPTURAR VIA VEH-001",
                           "off": "CAPTURAR VIA VEH-001", "desc": "Seta dir.",
                           "public": False},
        },
        "uds_sessions": {
            "default":     "10 01",
            "extended":    "10 03",
            "programming": "10 02",
            "security":    "27 01",
        },
        "security_notes": [
            "Perfil genérico — use VEH-001 (ATMA) para capturar IDs reais deste veículo",
            "Após captura passiva, substitua os valores 'CAPTURAR VIA VEH-001' pelos payloads reais",
        ],
        "source": "ISO 15031-5 / SAE J1979",
    },

    # ──────────────────────────────────────────────────────────────────────────
    # GM / CHEVROLET — Plataforma GEM (Brasil: Onix, Tracker, S10, Montana)
    # Referência: GM LAN Bible (opengarages.org), pcmhacking.net community
    # ──────────────────────────────────────────────────────────────────────────
    "gm": {
        "name":         "GM / Chevrolet (GEM Platform — Onix, Tracker, S10)",
        "region":       ["br", "ar", "latam"],
        "models":       ["Onix 2012+", "Onix Plus", "Tracker 2019+", "S10 2012+",
                         "Montana 2023+", "Cruze", "Spin", "Cobalt"],
        "protocol":     "ISO15765_11_500",
        "can_speed":    "500k",
        "bcm_addr":     "7B0",    # BCM GM padrão
        "ecm_addr":     "7E0",    # ECM GM
        "tcm_addr":     "7E1",    # TCM GM (câmbio automático)
        "gateway_addr": "7DF",    # OBD broadcast
        "obd_pids": list(OBD2_STANDARD_PIDS.keys()),
        "custom_pids": {
            # GM Extended PIDs (modo 22 — UDS ReadDataByIdentifier)
            # Referência: pcmhacking.net + opengarages GM LAN Bible
            "22 1A 90": {"name": "VIN GM estendido",           "unit": "string",
                         "desc": "VIN via UDS RDBI — mais confiável que modo 09",
                         "public": True, "source": "opengarages GM LAN"},
            "22 F1 90": {"name": "Número de calibração ECU",   "unit": "string",
                         "desc": "Calibration ID para identificar versão de firmware ECU",
                         "public": True, "source": "GM dealer docs community"},
            "22 F1 10": {"name": "Software ECU (SW Part No.)", "unit": "string",
                         "desc": "Part number do software instalado no ECU",
                         "public": True, "source": "GM dealer docs community"},
            "22 49 02": {"name": "Temperatura da transmissão", "unit": "°C",
                         "desc": "Temperatura do fluido de câmbio automático",
                         "formula": "A-40", "public": True,
                         "source": "pcmhacking.net community"},
            "22 04 22": {"name": "Nível óleo motor",           "unit": "%",
                         "desc": "Nível de óleo do motor (sistemas com sensor)",
                         "formula": "A", "public": True,
                         "source": "pcmhacking.net community"},
            "22 03 00": {"name": "Tensão bateria 12V",         "unit": "V",
                         "desc": "Tensão da bateria auxiliar",
                         "formula": "(A*256+B)/1000", "public": True,
                         "source": "opengarages"},
        },
        "can_signals": {
            # Sinais de broadcast CAN — GM GEM Platform
            # Referência: GM LAN Bible + opendbc gmlan
            "vehicle_speed": {"id": "3E9", "bits": "0:8",  "formula": "A*1.609", "unit": "km/h",
                              "desc": "Velocidade (VEHICLE_SPEED broadcast)", "public": True},
            "engine_rpm":    {"id": "0C9", "bits": "0:16", "formula": "(A*256+B)/4", "unit": "RPM",
                              "desc": "RPM motor (ENGINE_RPM broadcast)", "public": True},
            "engine_temp":   {"id": "1A1", "bits": "0:8",  "formula": "A-40",  "unit": "°C",
                              "desc": "Temperatura motor (broadcast)", "public": True},
            "throttle":      {"id": "0C9", "bits": "16:8", "formula": "A/2.55","unit": "%",
                              "desc": "Posição do acelerador", "public": True},
            "fuel_level":    {"id": "3A4", "bits": "0:8",  "formula": "A/2.55","unit": "%",
                              "desc": "Nível de combustível (instrumento)", "public": True},
            "brake_pressed": {"id": "0F1", "bits": "4:1",  "formula": "A",     "unit": "bool",
                              "desc": "Pedal de freio pressionado", "public": True},
            "door_status":   {"id": "3D1", "bits": "0:8",  "formula": "A",     "unit": "bitmap",
                              "desc": "Status de portas (bitmap)", "public": True},
            "odometer":      {"id": "3E9", "bits": "8:24", "formula": "(A*65536+B*256+C)*0.1",
                              "unit": "km", "desc": "Hodômetro", "public": True},
        },
        "bcm_controls": {
            # BCM GM — controles de carroceria
            # Referência: pcmhacking.net + GM LAN bible (opengarages.org)
            "window_fl":  {
                "id": "3B1", "public": True,
                "open":  "0000020000000000",   # bit 2 byte 2 = FL window open
                "close": "0000010000000000",   # bit 1 byte 2 = FL window close
                "desc":  "Janela FL — GM GEM (Onix/Tracker)",
                "source": "pcmhacking.net community"
            },
            "window_fr":  {
                "id": "3B1", "public": True,
                "open":  "0000000200000000",
                "close": "0000000100000000",
                "desc":  "Janela FR — GM GEM",
                "source": "pcmhacking.net community"
            },
            "window_rl":  {
                "id": "3B1", "public": True,
                "open":  "0000000020000000",
                "close": "0000000010000000",
                "desc":  "Janela RL — GM GEM",
                "source": "pcmhacking.net community"
            },
            "door_lock":  {
                "id": "3D1", "public": True,
                "lock":   "0100000000000000",  # GM: 0x01 = lock
                "unlock": "0200000000000000",  # GM: 0x02 = unlock
                "desc":   "Central lock — GM GEM (Onix/Tracker/S10)",
                "source": "opengarages GM LAN Bible"
            },
            "turn_left":  {
                "id": "291", "public": True,
                "on":  "0100000000000000",
                "off": "0000000000000000",
                "desc": "Seta/piscante esquerdo — GM",
                "source": "opengarages GM LAN Bible"
            },
            "turn_right": {
                "id": "291", "public": True,
                "on":  "0200000000000000",
                "off": "0000000000000000",
                "desc": "Seta/piscante direito — GM",
                "source": "opengarages GM LAN Bible"
            },
            "hazard":     {
                "id": "291", "public": True,
                "on":  "0300000000000000",
                "off": "0000000000000000",
                "desc": "Pisca-alerta — GM GEM",
                "source": "opengarages GM LAN Bible"
            },
            "horn":       {
                "id": "3D1", "public": False,
                "on":  "CAPTURAR VIA VEH-001",
                "off": "CAPTURAR VIA VEH-001",
                "desc": "Buzina — payload proprietário GM, requer captura",
            },
        },
        "uds_sessions": {
            "default":     "10 01",
            "extended":    "10 03",
            "programming": "10 02",
            "security_l1": "27 01",  # Seed para nível 1
            "security_l5": "27 05",  # Seed para nível 5 (programming)
        },
        "security_notes": [
            "GM usa autenticação Security Access 0x27 para programming session",
            "GM Onix Brasil (2012-2019): protocolo GM-LAN single-wire 33.3k (ATSP7)",
            "GM Onix Brasil (2020+): CAN ISO 15765-4 500k (ATSP6)",
            "BCM address 0x7B0 é padrão GM — confirme via ATDP antes",
            "PIDs do modo 22 requerem sessão Extended (10 03) aberta primeiro",
            "Sinal de odômetro exposto sem autenticação — risco de privacidade",
        ],
        "source": "GM LAN Bible (opengarages.org) + pcmhacking.net community",
    },

    # ──────────────────────────────────────────────────────────────────────────
    # FIAT — Plataforma FCA/Stellantis (Brasil: Uno, Palio, Argo, Cronos, Toro, Fiorino)
    # Referência: Fiat 500 research público + FCA diagnostic community
    # ──────────────────────────────────────────────────────────────────────────
    "fiat": {
        "name":         "Fiat / Stellantis (FCA — Argo, Cronos, Toro, Uno, Mobi)",
        "region":       ["br", "ar", "latam"],
        "models":       ["Argo 2017+", "Cronos 2018+", "Toro 2016+", "Mobi 2016+",
                         "Uno 2011+", "Palio 2012-2017", "Fiorino", "Ducato"],
        "protocol":     "ISO15765_11_500",
        "can_speed":    "500k",
        "bcm_addr":     "7BC",    # Fiat BCM (Body Control Module)
        "ecm_addr":     "7E0",    # ECM padrão OBD
        "tcm_addr":     "7E2",    # TCM Fiat (câmbio Aisin/Comfortmatic)
        "gateway_addr": "7A1",    # Gateway Fiat FCA
        "obd_pids": list(OBD2_STANDARD_PIDS.keys()),
        "custom_pids": {
            # Fiat Custom PIDs — modo 21 e 22
            # Referência: Fiat 500L research + FCA diagnostic manuals (community)
            "21 01": {"name": "Status sistema Fiat (modo 21)",  "unit": "bitmap",
                      "desc": "Status geral dos módulos Fiat", "public": True,
                      "source": "FCA diagnostic community"},
            "22 F1 90": {"name": "Part Number ECU Fiat",        "unit": "string",
                         "desc": "Número de peça do ECU instalado",
                         "public": True, "source": "FCA diagnostic docs"},
            "22 F1 A2": {"name": "Odômetro Fiat",              "unit": "km",
                         "desc": "Leitura do hodômetro via UDS",
                         "formula": "(A*65536+B*256+C)*0.1",
                         "public": True, "source": "FCA community"},
            "22 20 00": {"name": "Temperatura câmbio Fiat",    "unit": "°C",
                         "desc": "Temperatura do câmbio automático Comfortmatic",
                         "formula": "A-40", "public": True,
                         "source": "FCA diagnostic community"},
            "22 30 02": {"name": "Estado EOBD (emissões)",     "unit": "bitmap",
                         "desc": "Readiness monitors — pré-inspeção veicular",
                         "public": True, "source": "ISO 15031-5"},
        },
        "can_signals": {
            # Fiat FCA CAN signals — referência: Fiat 500L + opendbc chrysler
            "vehicle_speed": {"id": "1D0", "bits": "0:8",  "formula": "A",
                              "unit": "km/h", "desc": "Velocidade broadcast Fiat", "public": True},
            "engine_rpm":    {"id": "0E8", "bits": "0:16", "formula": "(A*256+B)/4",
                              "unit": "RPM", "desc": "RPM motor Fiat", "public": True},
            "engine_temp":   {"id": "2D2", "bits": "8:8",  "formula": "A-40",
                              "unit": "°C", "desc": "Temperatura motor", "public": True},
            "fuel_level":    {"id": "3A7", "bits": "0:8",  "formula": "A/2.55",
                              "unit": "%", "desc": "Nível combustível", "public": True},
            "throttle":      {"id": "0E8", "bits": "16:8", "formula": "A/2.55",
                              "unit": "%", "desc": "Posição acelerador", "public": True},
            "door_fl":       {"id": "2FA", "bits": "0:1",  "formula": "A",
                              "unit": "bool", "desc": "Porta FL aberta", "public": True},
            "gear_selected": {"id": "1F5", "bits": "0:4",  "formula": "A",
                              "unit": "gear", "desc": "Marcha selecionada", "public": True},
        },
        "bcm_controls": {
            # Fiat FCA BCM — referência: Fiat 500L community research
            "door_lock":  {
                "id": "3B0", "public": True,
                "lock":   "0100000000000000",
                "unlock": "0200000000000000",
                "desc":   "Travas portas — Fiat FCA",
                "source": "Fiat 500L community reverse engineering"
            },
            "window_fl":  {
                "id": "3B2", "public": True,
                "open":  "0001000000000000",
                "close": "0002000000000000",
                "desc":  "Janela FL — Fiat Argo/Cronos",
                "source": "FCA BCM community"
            },
            "window_fr":  {
                "id": "3B2", "public": True,
                "open":  "0010000000000000",
                "close": "0020000000000000",
                "desc":  "Janela FR — Fiat Argo/Cronos",
                "source": "FCA BCM community"
            },
            "turn_left":  {
                "id": "2A5", "public": True,
                "on":  "0100000000000000",
                "off": "0000000000000000",
                "desc": "Seta esquerda — Fiat FCA",
                "source": "FCA BCM community"
            },
            "turn_right": {
                "id": "2A5", "public": True,
                "on":  "0200000000000000",
                "off": "0000000000000000",
                "desc": "Seta direita — Fiat FCA",
                "source": "FCA BCM community"
            },
            "hazard":     {
                "id": "2A5", "public": True,
                "on":  "0300000000000000",
                "off": "0000000000000000",
                "desc": "Pisca-alerta — Fiat FCA",
                "source": "FCA BCM community"
            },
            "trunk":      {
                "id": "CAPTURAR", "public": False,
                "open":  "CAPTURAR VIA VEH-001",
                "close": "CAPTURAR VIA VEH-001",
                "desc":  "Porta-malas — proprietário Fiat, capturar com VEH-001",
            },
        },
        "uds_sessions": {
            "default":     "10 01",
            "extended":    "10 03",
            "programming": "10 02",
            "security_l1": "27 01",
            "security_l3": "27 03",  # Fiat usa nível 3 para acesso a funções avançadas
        },
        "security_notes": [
            "Fiat Uno/Palio (pre-2012): protocolo KW2000/ISO9141 — não CAN! Use ATSP3",
            "Fiat Argo/Cronos/Toro (2016+): CAN ISO 15765-4 500k",
            "Fiat Mobi (1.0 FireFly): CAN 500k — compatível com perfil FCA",
            "BCM address 0x7BC é específico Fiat — diferente do GM",
            "Modo 21 Fiat expõe dados sem autenticação em modelos 2016-2019",
            "Sistema Keyless Fiat (Toro AWD): superficie BLE+CAN similar ao Tesla attack",
        ],
        "source": "Fiat 500L community RE + FCA diagnostic docs (community)",
    },

    # ──────────────────────────────────────────────────────────────────────────
    # VOLKSWAGEN — Plataforma MQB/MEB (Brasil: Polo, Virtus, T-Cross, Nivus, Taos, ID.4)
    # Referência: opendbc vw_mqb_2010.dbc + Ross-Tech VCDS wiki
    # ──────────────────────────────────────────────────────────────────────────
    "volkswagen": {
        "name":         "Volkswagen / Audi / Skoda (MQB Platform — Polo, Virtus, T-Cross)",
        "region":       ["br", "ar", "latam", "global"],
        "models":       ["Polo 2018+", "Virtus 2018+", "T-Cross 2019+", "Nivus 2020+",
                         "Taos 2021+", "Amarok 2016+", "Golf 2013+", "Tiguan 2016+"],
        "protocol":     "ISO15765_29_500",  # VW usa 29-bit CAN!
        "can_speed":    "500k",
        "bcm_addr":     "7B0",    # BCM VW MQB (Modulares Querbaukasten)
        "ecm_addr":     "7E0",    # ECM VW
        "tcm_addr":     "7E2",    # DSG gearbox
        "gateway_addr": "7A0",    # CAN Gateway VW
        "obd_pids": list(OBD2_STANDARD_PIDS.keys()),
        "custom_pids": {
            # VW Extended PIDs — Ross-Tech VCDS public documentation
            "22 F1 90": {"name": "Part Number ECU",             "unit": "string",
                         "public": True, "source": "Ross-Tech VCDS"},
            "22 F1 A8": {"name": "Engine Code (Código motor)", "unit": "string",
                         "public": True, "source": "Ross-Tech VCDS"},
            "22 60 16": {"name": "Temperatura câmbio DSG",     "unit": "°C",
                         "formula": "A-100", "public": True,
                         "source": "VCDS Ross-Tech + VW forum"},
            "22 60 18": {"name": "Desgaste embreagem DSG 1",   "unit": "%",
                         "formula": "A/2.55", "public": True,
                         "source": "VW DSG diagnostic"},
            "22 60 19": {"name": "Desgaste embreagem DSG 2",   "unit": "%",
                         "formula": "A/2.55", "public": True,
                         "source": "VW DSG diagnostic"},
            "22 11 38": {"name": "Tensão bateria 12V",         "unit": "V",
                         "formula": "A/10", "public": True,
                         "source": "Ross-Tech VCDS"},
            "22 04 11": {"name": "Odômetro VW",               "unit": "km",
                         "formula": "(A*65536+B*256+C)*0.1", "public": True,
                         "source": "VCDS community"},
            "22 02 C0": {"name": "Status sistema Start/Stop",  "unit": "string",
                         "public": True, "source": "VCDS MQB community"},
        },
        "can_signals": {
            # VW MQB CAN signals — opendbc vw_mqb_2010.dbc (público)
            "vehicle_speed":   {"id": "0D6", "bits": "0:16", "formula": "A*256/256",
                               "unit": "km/h", "desc": "Velocidade MQB", "public": True,
                               "source": "opendbc vw_mqb_2010.dbc"},
            "engine_rpm":      {"id": "107", "bits": "8:16", "formula": "(A*256+B)/4",
                               "unit": "RPM", "desc": "RPM motor MQB", "public": True},
            "steering_angle":  {"id": "086", "bits": "0:16", "formula": "(A*256+B)/10-3276.8",
                               "unit": "°", "desc": "Ângulo direção — ADAS surface!",
                               "public": True, "source": "opendbc"},
            "brake_pressure":  {"id": "13B", "bits": "0:16", "formula": "A*256+B",
                               "unit": "hPa", "desc": "Pressão de frenagem", "public": True},
            "accel_pedal":     {"id": "107", "bits": "24:8", "formula": "A/2.55",
                               "unit": "%", "desc": "Pedal acelerador", "public": True},
            "engine_temp":     {"id": "3C0", "bits": "8:8",  "formula": "A-48",
                               "unit": "°C", "desc": "Temperatura motor", "public": True},
            "fuel_level":      {"id": "3C0", "bits": "24:8", "formula": "A/2.55",
                               "unit": "%", "desc": "Nível combustível", "public": True},
            "gear_dsg":        {"id": "22D", "bits": "0:4",  "formula": "A",
                               "unit": "gear", "desc": "Marcha DSG", "public": True},
            "door_status":     {"id": "03C1","bits": "0:8",  "formula": "A",
                               "unit": "bitmap","desc": "Status portas VW", "public": True},
        },
        "bcm_controls": {
            # VW MQB BCM — Ross-Tech + opendbc community
            "window_fl":  {
                "id": "02C1", "public": True,
                "open":  "0200000000000000",
                "close": "0100000000000000",
                "desc":  "Janela FL — VW MQB (Polo/Virtus/T-Cross)",
                "source": "opendbc + VCDS"
            },
            "window_fr":  {
                "id": "02C1", "public": True,
                "open":  "0020000000000000",
                "close": "0010000000000000",
                "desc":  "Janela FR — VW MQB",
                "source": "opendbc + VCDS"
            },
            "window_rl":  {
                "id": "02C1", "public": True,
                "open":  "0000020000000000",
                "close": "0000010000000000",
                "desc":  "Janela RL — VW MQB",
                "source": "opendbc"
            },
            "window_rr":  {
                "id": "02C1", "public": True,
                "open":  "0000000200000000",
                "close": "0000000100000000",
                "desc":  "Janela RR — VW MQB",
                "source": "opendbc"
            },
            "door_lock":  {
                "id": "03D1", "public": True,
                "lock":   "5400000000000000",   # VW: 0x54 = lock all
                "unlock": "4500000000000000",   # VW: 0x45 = unlock all
                "desc":   "Central lock VW MQB (Polo/Virtus/T-Cross)",
                "source": "Ross-Tech VCDS + opendbc"
            },
            "turn_left":  {
                "id": "00E0", "public": True,
                "on":  "0100000000000000",
                "off": "0000000000000000",
                "desc": "Seta esquerda — VW",
                "source": "opendbc"
            },
            "turn_right": {
                "id": "00E0", "public": True,
                "on":  "0200000000000000",
                "off": "0000000000000000",
                "desc": "Seta direita — VW",
                "source": "opendbc"
            },
            "hazard":     {
                "id": "00E0", "public": True,
                "on":  "0300000000000000",
                "off": "0000000000000000",
                "desc": "Pisca-alerta — VW",
                "source": "opendbc"
            },
            "windows_all_up": {
                "id": "02C1", "public": True,
                "on":  "1111111100000000",
                "off": "0000000000000000",
                "desc": "Todos os vidros — fecha todos simultaneamente",
                "source": "VCDS community"
            },
        },
        "uds_sessions": {
            "default":     "10 01",
            "extended":    "10 03",
            "programming": "10 02",
            "security_l1": "27 01",   # VW nível 1 (acesso básico)
            "security_l11": "27 0B",  # VW nível 11 (acesso programação)
            "security_l1F": "27 1F",  # VW nível 31 (dealer)
        },
        "security_notes": [
            "VW MQB usa CAN 29-bit (ISO 15765-4 extended): configurar ATSP B no ELM327",
            "Ross-Tech VCDS documenta extensamente os PIDs VW — fonte confiável",
            "VW usa Security Access com algoritmo seed-key proprietário",
            "Polo/Virtus Brasil têm BCM muito próximo ao VW global MQB",
            "Steering angle (CAN ID 086) é crítico — superfície de ADAS attack",
            "DSG gearbox: temperature > 130°C causa modo de proteção — DoS veicular",
            "Portas e janelas com CAN IDs bem documentados pelo opendbc",
        ],
        "source": "opendbc vw_mqb_2010.dbc + Ross-Tech VCDS wiki (público)",
    },

    # ──────────────────────────────────────────────────────────────────────────
    # FORD — Plataforma SYNC/CAN (Brasil: Ka, EcoSport, Ranger, Territory, Bronco Sport)
    # Referência: opendbc ford_cds.dbc + Ford extended PIDs community
    # ──────────────────────────────────────────────────────────────────────────
    "ford": {
        "name":         "Ford (SYNC Platform — Ka, EcoSport, Ranger, Territory)",
        "region":       ["br", "ar", "latam", "global"],
        "models":       ["Ka 2015+", "EcoSport 2013+", "Ranger 2012+", "Territory 2020+",
                         "Bronco Sport", "Maverick", "Fiesta 2011+", "Focus 2012+"],
        "protocol":     "ISO15765_11_500",
        "can_speed":    "500k",
        "bcm_addr":     "726",    # Ford GEM/BCM
        "ecm_addr":     "7E0",
        "tcm_addr":     "7E1",
        "gateway_addr": "7DF",
        "obd_pids": list(OBD2_STANDARD_PIDS.keys()),
        "custom_pids": {
            # Ford Extended PIDs — fonte: Ford pirate diagnostics + community
            "22 F1 90": {"name": "Calibration ID (CALID)",   "unit": "string",
                         "public": True, "source": "Ford diagnostics community"},
            "22 0D 47": {"name": "Temperatura transmissão",  "unit": "°C",
                         "formula": "A-40", "public": True,
                         "source": "Ford community reverse engineering"},
            "22 0D 3D": {"name": "Duty cycle alternador",    "unit": "%",
                         "formula": "A/2.55", "public": True,
                         "source": "Ford PID database community"},
            "22 0D 28": {"name": "Tensão bateria Ford",     "unit": "V",
                         "formula": "A/10", "public": True,
                         "source": "Ford PID database community"},
            "22 9D 40": {"name": "Posição câmbio Ford",     "unit": "string",
                         "public": True,
                         "source": "Ford PowerShift community"},
            "22 F0 20": {"name": "Odômetro Ford",           "unit": "km",
                         "formula": "(A*65536+B*256+C)*0.1",
                         "public": True, "source": "Ford community"},
        },
        "can_signals": {
            # Ford CAN signals — opendbc ford_cds.dbc
            "vehicle_speed":   {"id": "415", "bits": "0:8",  "formula": "A",
                               "unit": "km/h", "desc": "Velocidade Ford", "public": True,
                               "source": "opendbc ford_cds.dbc"},
            "engine_rpm":      {"id": "201", "bits": "0:16", "formula": "(A*256+B)*0.125",
                               "unit": "RPM", "desc": "RPM motor Ford", "public": True},
            "engine_temp":     {"id": "420", "bits": "0:8",  "formula": "A*0.75-48",
                               "unit": "°C", "desc": "Temperatura motor", "public": True},
            "steering_angle":  {"id": "202", "bits": "0:16", "formula": "(A*256+B)/10-1638.4",
                               "unit": "°", "desc": "Ângulo direção Ford", "public": True},
            "fuel_level":      {"id": "420", "bits": "8:8",  "formula": "A/2.55",
                               "unit": "%", "desc": "Nível combustível", "public": True},
            "brake_active":    {"id": "083", "bits": "0:1",  "formula": "A",
                               "unit": "bool", "desc": "Freio ativo", "public": True},
            "accel_pedal":     {"id": "090", "bits": "0:8",  "formula": "A/2.55",
                               "unit": "%", "desc": "Posição pedal acelerador", "public": True},
        },
        "bcm_controls": {
            # Ford GEM (Generic Electronic Module) / BCM
            # Referência: opendbc ford + Ford community
            "door_lock":  {
                "id": "3F3", "public": True,
                "lock":   "0100000000000000",
                "unlock": "0200000000000000",
                "desc":   "Central lock Ford (Ka/EcoSport/Ranger)",
                "source": "Ford community + opendbc"
            },
            "window_fl":  {
                "id": "3F5", "public": True,
                "open":  "0100000000000000",
                "close": "0200000000000000",
                "desc":  "Janela FL — Ford",
                "source": "Ford BCM community"
            },
            "window_fr":  {
                "id": "3F5", "public": True,
                "open":  "0010000000000000",
                "close": "0020000000000000",
                "desc":  "Janela FR — Ford",
                "source": "Ford BCM community"
            },
            "turn_left":  {
                "id": "2B3", "public": True,
                "on":  "0100000000000000",
                "off": "0000000000000000",
                "desc": "Seta esquerda Ford",
                "source": "Ford community"
            },
            "turn_right": {
                "id": "2B3", "public": True,
                "on":  "0200000000000000",
                "off": "0000000000000000",
                "desc": "Seta direita Ford",
                "source": "Ford community"
            },
            "hazard":     {
                "id": "2B3", "public": True,
                "on":  "0300000000000000",
                "off": "0000000000000000",
                "desc": "Pisca-alerta Ford",
                "source": "Ford community"
            },
            "horn":       {
                "id": "CAPTURAR", "public": False,
                "on":  "CAPTURAR VIA VEH-001",
                "off": "CAPTURAR VIA VEH-001",
                "desc": "Buzina — proprietário Ford"
            },
        },
        "uds_sessions": {
            "default":     "10 01",
            "extended":    "10 03",
            "programming": "10 02",
            "security_l1": "27 01",
            "security_l3": "27 03",
        },
        "security_notes": [
            "Ford Ka Brasil (2015+): protocolo ISO 15765-4 CAN 500k",
            "Ford GEM = Generic Electronic Module = BCM — endereço 0x726",
            "Ford PowerShift (câmbio de dupla embreagem): vulnerabilidades UDS conhecidas",
            "Ford SYNC (infotainment): superfície de ataque BLE + CAN bridge",
            "Steering angle broadcast (ID 202) sem autenticação — risco ADAS",
        ],
        "source": "opendbc ford_cds.dbc + Ford diagnostics community",
    },

    # ──────────────────────────────────────────────────────────────────────────
    # HONDA — Plataforma Honda Sensing (Brasil: City, Civic, HR-V, CR-V, WR-V)
    # Referência: opendbc honda_accord.dbc + Honda community
    # ──────────────────────────────────────────────────────────────────────────
    "honda": {
        "name":         "Honda / Acura (Honda Sensing — City, Civic, HR-V, CR-V, WR-V)",
        "region":       ["br", "ar", "latam", "global"],
        "models":       ["City 2014+", "Civic 2016+", "HR-V 2015+", "CR-V 2017+",
                         "WR-V 2017+", "Fit 2014+", "Accord 2013+"],
        "protocol":     "ISO15765_11_500",
        "can_speed":    "500k",
        "bcm_addr":     "7E4",    # Honda BCM / FSBF
        "ecm_addr":     "7E0",
        "tcm_addr":     "7E1",    # Honda CVT
        "gateway_addr": "7DF",
        "obd_pids": list(OBD2_STANDARD_PIDS.keys()),
        "custom_pids": {
            # Honda Extended PIDs — Honda Diagnostic System (HDS) community
            "21 01": {"name": "Status Honda (modo 21)",       "unit": "bitmap",
                      "public": True, "source": "Honda HDS community"},
            "22 F1 90": {"name": "Part Number ECU Honda",     "unit": "string",
                         "public": True, "source": "Honda HDS docs"},
            "22 00 35": {"name": "Temperatura CVT",           "unit": "°C",
                         "formula": "A-40", "public": True,
                         "source": "Honda CVT diagnostic community"},
            "22 00 2C": {"name": "Pressão ATF transmissão",   "unit": "kPa",
                         "formula": "A", "public": True,
                         "source": "Honda HDS community"},
            "22 F0 01": {"name": "Odômetro Honda",            "unit": "km",
                         "formula": "(A*65536+B*256+C)*0.1",
                         "public": True, "source": "Honda community"},
            "22 00 50": {"name": "Estado bateria IMA/híbrido","unit": "string",
                         "public": True, "source": "Honda Insight community"},
        },
        "can_signals": {
            # Honda CAN — opendbc honda_accord.dbc + honda_civic_ex.dbc
            "vehicle_speed":   {"id": "158", "bits": "0:8",  "formula": "A",
                               "unit": "km/h", "desc": "Velocidade Honda", "public": True,
                               "source": "opendbc honda_accord.dbc"},
            "engine_rpm":      {"id": "17C", "bits": "0:16", "formula": "(A*256+B)/4",
                               "unit": "RPM", "desc": "RPM Honda", "public": True},
            "engine_temp":     {"id": "158", "bits": "8:8",  "formula": "A*0.75-48",
                               "unit": "°C", "desc": "Temperatura motor Honda", "public": True},
            "steering_angle":  {"id": "18F", "bits": "0:16", "formula": "(A*256+B)/10-1638.4",
                               "unit": "°", "desc": "Ângulo direção Honda Sensing",
                               "public": True, "source": "opendbc"},
            "brake_pressure":  {"id": "17C", "bits": "16:8", "formula": "A*0.98",
                               "unit": "kPa", "desc": "Pressão freio", "public": True},
            "accel_pedal":     {"id": "17C", "bits": "24:8", "formula": "A/2.55",
                               "unit": "%", "desc": "Posição acelerador", "public": True},
            "steer_torque":    {"id": "18F", "bits": "16:16","formula": "(A*256+B)/100-16.384",
                               "unit": "Nm", "desc": "Torque direção EPS (Honda Sensing!)",
                               "public": True, "source": "opendbc — ADAS critical!"},
            "lkas_active":     {"id": "39F", "bits": "0:1",  "formula": "A",
                               "unit": "bool", "desc": "LKAS ativo (Honda Sensing)",
                               "public": True, "source": "opendbc — security critical"},
        },
        "bcm_controls": {
            "door_lock":  {
                "id": "3EF", "public": True,
                "lock":   "0100000000000000",
                "unlock": "0200000000000000",
                "desc":   "Central lock Honda",
                "source": "Honda community reverse engineering"
            },
            "window_fl":  {
                "id": "3F1", "public": True,
                "open":  "0100000000000000",
                "close": "0200000000000000",
                "desc":  "Janela FL — Honda City/Civic",
                "source": "Honda BCM community"
            },
            "window_fr":  {
                "id": "3F1", "public": True,
                "open":  "0010000000000000",
                "close": "0020000000000000",
                "desc":  "Janela FR — Honda",
                "source": "Honda BCM community"
            },
            "turn_left":  {
                "id": "296", "public": True,
                "on":  "0100000000000000",
                "off": "0000000000000000",
                "desc": "Seta esquerda Honda",
                "source": "Honda community"
            },
            "turn_right": {
                "id": "296", "public": True,
                "on":  "0200000000000000",
                "off": "0000000000000000",
                "desc": "Seta direita Honda",
                "source": "Honda community"
            },
            "hazard":     {
                "id": "296", "public": True,
                "on":  "0300000000000000",
                "off": "0000000000000000",
                "desc": "Pisca-alerta Honda",
                "source": "Honda community"
            },
            "lkas_control": {
                "id": "E4", "public": True,
                "steer_left":  "0080000000000000",   # Honda Sensing LKAS steer
                "steer_right": "0100000000000000",
                "neutral":     "0000000000000000",
                "desc":  "LKAS EPS Control — Honda Sensing (CRÍTICO!)",
                "source": "opendbc — ADAS safety critical"
            },
        },
        "uds_sessions": {
            "default":     "10 01",
            "extended":    "10 03",
            "programming": "10 02",
            "security_l1": "27 01",
            "security_l3": "27 03",
        },
        "security_notes": [
            "CRÍTICO: Honda Sensing LKAS usa CAN ID 0xE4 para controle de direção!",
            "Steering torque broadcast (ID 18F) exposto sem autenticação — ADAS surface",
            "Honda CVT: temperatura exposta via PID proprietário 22 00 35",
            "Honda City Brasil: CAN 500k ISO 15765-4 11-bit",
            "Honda WR-V: arquitetura semelhante ao HR-V 1ª geração",
            "opendbc tem DBC files completos para Civic, Accord, HR-V",
        ],
        "source": "opendbc honda_accord.dbc + Honda HDS community",
    },

    # ──────────────────────────────────────────────────────────────────────────
    # TOYOTA — Plataforma TNGA/TSS (Brasil: Corolla, Yaris, RAV4, Hilux, SW4)
    # Referência: opendbc toyota_rav4.dbc + Toyota Safety Sense research
    # ──────────────────────────────────────────────────────────────────────────
    "toyota": {
        "name":         "Toyota / Lexus (TNGA Platform — Corolla, Yaris, RAV4, Hilux)",
        "region":       ["br", "ar", "latam", "global"],
        "models":       ["Corolla 2019+", "Yaris 2018+", "RAV4 2019+", "Hilux 2016+",
                         "SW4 2016+", "Camry 2018+", "Prius 2016+", "C-HR"],
        "protocol":     "ISO15765_11_500",
        "can_speed":    "500k",
        "bcm_addr":     "750",    # Toyota BCM / Smart ECU
        "ecm_addr":     "7E0",
        "tcm_addr":     "7E1",
        "gateway_addr": "7DF",
        "obd_pids": list(OBD2_STANDARD_PIDS.keys()),
        "custom_pids": {
            # Toyota Extended PIDs — modo 21 e 22 (Toyota Techstream community)
            "21 01": {"name": "Status Toyota (modo 21)",      "unit": "bitmap",
                      "public": True, "source": "Toyota Techstream community"},
            "22 F1 90": {"name": "Calibration ID Toyota",     "unit": "string",
                         "public": True, "source": "Toyota Techstream"},
            "22 01 00": {"name": "Temperatura câmbio Toyota", "unit": "°C",
                         "formula": "A-40", "public": True,
                         "source": "Toyota diagnostic community"},
            "22 01 04": {"name": "Voltagem sistema Toyota",   "unit": "V",
                         "formula": "A*0.1", "public": True,
                         "source": "Toyota Techstream community"},
            "22 B1 00": {"name": "SOC bateria híbrido",       "unit": "%",
                         "formula": "A/2", "public": True,
                         "source": "Prius community + Techstream"},
            "22 B1 01": {"name": "Temperatura bateria HV",    "unit": "°C",
                         "formula": "A-40", "public": True,
                         "source": "Toyota hybrid community"},
            "22 F0 10": {"name": "Odômetro Toyota",           "unit": "km",
                         "formula": "(A*65536+B*256+C)*0.1",
                         "public": True, "source": "Toyota community"},
        },
        "can_signals": {
            # Toyota TNGA CAN — opendbc toyota_rav4_2019.dbc
            "vehicle_speed":   {"id": "0B4", "bits": "0:16", "formula": "(A*256+B)*0.01",
                               "unit": "km/h", "desc": "Velocidade Toyota TNGA", "public": True,
                               "source": "opendbc toyota_rav4_2019.dbc"},
            "engine_rpm":      {"id": "0AA", "bits": "0:16", "formula": "(A*256+B)/4",
                               "unit": "RPM", "desc": "RPM Toyota", "public": True},
            "steering_angle":  {"id": "025", "bits": "0:16", "formula": "(A*256+B)/100-5",
                               "unit": "°", "desc": "Ângulo direção Toyota Safety Sense!",
                               "public": True, "source": "opendbc — ADAS critical"},
            "accel_pedal":     {"id": "07B", "bits": "0:8",  "formula": "A/2.55",
                               "unit": "%", "desc": "Pedal acelerador Toyota", "public": True},
            "brake_active":    {"id": "224", "bits": "4:1",  "formula": "A",
                               "unit": "bool", "desc": "Freio ativo", "public": True},
            "engine_temp":     {"id": "0AA", "bits": "16:8", "formula": "A*0.75-48",
                               "unit": "°C", "desc": "Temperatura motor", "public": True},
            "fuel_level":      {"id": "3B6", "bits": "0:8",  "formula": "A/2.55",
                               "unit": "%", "desc": "Nível combustível", "public": True},
            "cruise_active":   {"id": "1D3", "bits": "5:1",  "formula": "A",
                               "unit": "bool", "desc": "Cruise Control ativo", "public": True},
            "lka_active":      {"id": "1D2", "bits": "0:1",  "formula": "A",
                               "unit": "bool", "desc": "LKA (Toyota Safety Sense) ativo",
                               "public": True, "source": "opendbc — security critical"},
            "steer_torque":    {"id": "260", "bits": "0:16", "formula": "(A*256+B)/100-163.84",
                               "unit": "Nm", "desc": "Torque EPS (controle ADAS!)",
                               "public": True, "source": "opendbc — ADAS safety critical"},
        },
        "bcm_controls": {
            # Toyota Smart ECU / BCM
            "door_lock":  {
                "id": "750", "public": True,
                "lock":   "4000000000000000",
                "unlock": "8000000000000000",
                "desc":   "Central lock Toyota (Corolla/Yaris/RAV4)",
                "source": "Toyota community reverse engineering"
            },
            "window_fl":  {
                "id": "025", "public": True,
                "open":  "0080000000000000",
                "close": "0040000000000000",
                "desc":  "Janela FL — Toyota",
                "source": "Toyota BCM community"
            },
            "window_fr":  {
                "id": "025", "public": True,
                "open":  "0008000000000000",
                "close": "0004000000000000",
                "desc":  "Janela FR — Toyota",
                "source": "Toyota BCM community"
            },
            "turn_left":  {
                "id": "0B4", "public": True,
                "on":  "0100000000000000",
                "off": "0000000000000000",
                "desc": "Seta esquerda Toyota",
                "source": "Toyota community"
            },
            "turn_right": {
                "id": "0B4", "public": True,
                "on":  "0200000000000000",
                "off": "0000000000000000",
                "desc": "Seta direita Toyota",
                "source": "Toyota community"
            },
            "hazard":     {
                "id": "0B4", "public": True,
                "on":  "0300000000000000",
                "off": "0000000000000000",
                "desc": "Pisca-alerta Toyota",
                "source": "Toyota community"
            },
            "lka_torque_cmd": {
                "id": "260", "public": True,
                "steer_left":  "00C0000000000000",   # Torque negativo = esquerda
                "steer_right": "0040000000000000",   # Torque positivo = direita
                "neutral":     "0000000000000000",
                "desc":  "EPS Torque Command — Toyota Safety Sense (CRÍTICO!)",
                "source": "opendbc — ADAS safety critical"
            },
        },
        "uds_sessions": {
            "default":     "10 01",
            "extended":    "10 03",
            "programming": "10 02",
            "security_l1": "27 01",
            "security_l11": "27 11",   # Toyota usa 0x11 para programming
        },
        "security_notes": [
            "CRÍTICO: Toyota Safety Sense EPS usa CAN ID 0x260 para comandos de torque!",
            "Steering angle (ID 025) e torque (ID 260) broadcast sem autenticação",
            "Toyota Prius: bateria híbrido SOC acessível via PID 22 B1 00",
            "Toyota Hilux Brasil: pode ter velocidade CAN diferente (250k em modelos antigos)",
            "opendbc tem arquivos DBC completos para RAV4, Corolla, Prius, Camry",
            "Toyota Smart ECU (BCM) em 0x750 — diferente do padrão 0x7B0",
        ],
        "source": "opendbc toyota_rav4_2019.dbc + Toyota Techstream community",
    },

    # ──────────────────────────────────────────────────────────────────────────
    # BYD — Plataforma e-Platform 3.0 / DMi (Brasil: Dolphin, Seal, Atto 3, Tan, Han)
    # NOTA: BYD tem protocolos proprietários — OBD2 padrão funciona parcialmente
    # PIDs específicos BYD são parcialmente documentados pela comunidade
    # ──────────────────────────────────────────────────────────────────────────
    "byd": {
        "name":         "BYD (e-Platform 3.0 / DMi — Dolphin, Seal, Atto 3, Tan, Han)",
        "region":       ["br", "ar", "latam", "global"],
        "models":       ["Dolphin 2023+", "Seal 2023+", "Atto 3 2022+",
                         "Tan 2023+", "Han 2023+", "Song Plus", "King"],
        "protocol":     "ISO15765_11_500",
        "can_speed":    "500k",
        "bcm_addr":     "7BC",    # BYD BCM (similar Fiat/FCA)
        "ecm_addr":     "7E0",
        "tcm_addr":     "7E1",
        "gateway_addr": "7DF",
        "bms_addr":     "7E4",    # BMS — Battery Management System BYD
        "vcu_addr":     "7E5",    # VCU — Vehicle Control Unit BYD EV
        "obd_pids": list(OBD2_STANDARD_PIDS.keys()),
        "custom_pids": {
            # BYD Custom PIDs — comunidade ABRP + SavvyCAN reverse engineering
            # NOTA: Muitos PIDs BYD são proprietários e não documentados publicamente
            "22 00 1A": {"name": "SOC bateria BYD",             "unit": "%",
                         "desc": "State of Charge — Blade Battery",
                         "formula": "A/2", "public": True,
                         "source": "ABRP community BYD integration"},
            "22 00 1B": {"name": "SOH bateria BYD",             "unit": "%",
                         "desc": "State of Health — Blade Battery",
                         "formula": "A/2", "public": True,
                         "source": "ABRP community BYD integration"},
            "22 00 28": {"name": "Temperatura máx. célula",     "unit": "°C",
                         "formula": "A-40", "public": True,
                         "source": "BYD community reverse engineering"},
            "22 00 29": {"name": "Temperatura mín. célula",     "unit": "°C",
                         "formula": "A-40", "public": True,
                         "source": "BYD community reverse engineering"},
            "22 00 2A": {"name": "Tensão total pack",           "unit": "V",
                         "formula": "(A*256+B)*0.1", "public": True,
                         "source": "BYD community reverse engineering"},
            "22 00 2B": {"name": "Corrente pack (A)",           "unit": "A",
                         "formula": "(A*256+B)*0.1-3000", "public": True,
                         "source": "BYD community reverse engineering"},
            "22 01 0A": {"name": "Range estimada",              "unit": "km",
                         "formula": "A*256+B", "public": True,
                         "source": "ABRP community BYD"},
            "22 01 0B": {"name": "Energia disponível bateria",  "unit": "kWh",
                         "formula": "(A*256+B)*0.1", "public": True,
                         "source": "ABRP community BYD"},
            "22 F1 90": {"name": "Calibration ID BYD",          "unit": "string",
                         "public": True, "source": "BYD community"},
            # PIDs proprietários BYD — não confirmados publicamente
            "22 02 00": {"name": "Status carregamento [?]",     "unit": "bitmap",
                         "desc": "PRIVADO — capturar e confirmar com VEH-001",
                         "public": False},
            "22 02 01": {"name": "Potência carregamento [?]",   "unit": "kW",
                         "desc": "PRIVADO — capturar e confirmar com VEH-001",
                         "public": False},
        },
        "can_signals": {
            # BYD CAN signals — parcialmente reverse-engineered pela comunidade
            "soc":           {"id": "373", "bits": "0:8",  "formula": "A/2",
                             "unit": "%", "desc": "SOC Blade Battery (broadcast)",
                             "public": True, "source": "BYD community SavvyCAN"},
            "vehicle_speed": {"id": "1F5", "bits": "0:16", "formula": "(A*256+B)*0.01",
                             "unit": "km/h", "desc": "Velocidade BYD",
                             "public": True, "source": "BYD community"},
            "hv_voltage":    {"id": "373", "bits": "16:16","formula": "(A*256+B)*0.1",
                             "unit": "V", "desc": "Tensão HV pack",
                             "public": True, "source": "BYD community"},
            "hv_current":    {"id": "373", "bits": "32:16","formula": "(A*256+B)*0.1-3000",
                             "unit": "A", "desc": "Corrente pack (+ = carga, - = descarga)",
                             "public": True, "source": "BYD community"},
            "motor_rpm":     {"id": "1F5", "bits": "16:16","formula": "(A*256+B)-20000",
                             "unit": "RPM", "desc": "RPM motor elétrico BYD",
                             "public": True, "source": "BYD community"},
            "charging":      {"id": "3B2", "bits": "0:1",  "formula": "A",
                             "unit": "bool", "desc": "Status carregamento",
                             "public": True, "source": "BYD community — não confirmado"},
        },
        "bcm_controls": {
            # BYD BCM — muito pouco documentado publicamente
            "door_lock":  {
                "id": "CAPTURAR", "public": False,
                "lock":   "CAPTURAR VIA VEH-001",
                "unlock": "CAPTURAR VIA VEH-001",
                "desc":   "Travas — BYD proprietário, requer captura passiva",
            },
            "window_fl":  {
                "id": "CAPTURAR", "public": False,
                "open":  "CAPTURAR VIA VEH-001",
                "close": "CAPTURAR VIA VEH-001",
                "desc":  "Janela FL — BYD proprietário",
            },
            "turn_left":  {
                "id": "CAPTURAR", "public": False,
                "on":  "CAPTURAR VIA VEH-001",
                "off": "CAPTURAR VIA VEH-001",
                "desc": "Seta esq. BYD — capturar com VEH-001",
            },
            "turn_right": {
                "id": "CAPTURAR", "public": False,
                "on":  "CAPTURAR VIA VEH-001",
                "off": "CAPTURAR VIA VEH-001",
                "desc": "Seta dir. BYD — capturar com VEH-001",
            },
            "hazard":     {
                "id": "CAPTURAR", "public": False,
                "on":  "CAPTURAR VIA VEH-001",
                "off": "CAPTURAR VIA VEH-001",
                "desc": "Pisca-alerta BYD — capturar com VEH-001",
            },
        },
        "uds_sessions": {
            "default":     "10 01",
            "extended":    "10 03",
            "programming": "10 02",
            "bms_default": "10 01",     # BMS em 0x7E4
            "vcu_default": "10 01",     # VCU em 0x7E5
        },
        "security_notes": [
            "BYD usa protocolos proprietários — OBD2 padrão funciona parcialmente",
            "Acessar BMS (0x7E4) e VCU (0x7E5) expõe dados da bateria Blade",
            "PIDs de SOC/SOH são parcialmente documentados (comunidade ABRP)",
            "BCM controls: usar VEH-001 (ATMA) para capturar payloads reais",
            "BYD não tem SDK público — dados via reverse engineering comunitário",
            "Dolphin/Seal: high voltage system acessível via UDS — risco crítico",
            "Referência: grupo BYD EV Owners + projeto ABRP integration",
        ],
        "source": "ABRP community + SavvyCAN BYD RE + BYD Owners community",
    },
}


# =============================================================================
# FUNÇÕES DE ACESSO AO BANCO DE PERFIS
# =============================================================================

def get_profile(make: str) -> Dict[str, Any]:
    """Retorna o perfil de uma montadora. Fallback para 'generic'."""
    return VEHICLE_PROFILES.get(make.lower(), VEHICLE_PROFILES["generic"])


def list_makes() -> List[Dict[str, str]]:
    """Retorna lista de montadoras com nome e região."""
    return [
        {
            "id": k,
            "name": v["name"],
            "region": v["region"],
            "models_count": len(v["models"]),
            "public_controls": sum(
                1 for ctrl in v.get("bcm_controls", {}).values()
                if ctrl.get("public", False)
            ),
            "custom_pids": len(v.get("custom_pids", {})),
            "can_signals": len(v.get("can_signals", {})),
        }
        for k, v in VEHICLE_PROFILES.items()
    ]


def get_pid_list(make: str, include_private: bool = False) -> List[Dict]:
    """
    Retorna lista completa de PIDs para uma montadora.
    Combina OBD2 padrão + PIDs proprietários.
    """
    profile = get_profile(make)
    pids = []

    # OBD2 padrão
    for cmd, info in OBD2_STANDARD_PIDS.items():
        pids.append({
            "cmd": cmd, "name": info["name"], "unit": info["unit"],
            "mode": "standard", "public": True, "source": "ISO 15031-5",
        })

    # Proprietários
    for cmd, info in profile.get("custom_pids", {}).items():
        if include_private or info.get("public", True):
            pids.append({
                "cmd": cmd, "name": info["name"],
                "unit": info.get("unit", "raw"),
                "mode": "proprietary",
                "public": info.get("public", True),
                "formula": info.get("formula", "A"),
                "source": info.get("source", ""),
                "desc": info.get("desc", ""),
            })

    return pids


def get_bcm_controls(make: str, include_private: bool = True) -> Dict[str, Any]:
    """
    Retorna controles BCM para uma montadora.
    Identifica controles com payload disponível vs. 'CAPTURAR VIA VEH-001'.
    """
    profile = get_profile(make)
    controls = {}
    for ctrl_name, ctrl in profile.get("bcm_controls", {}).items():
        if include_private or ctrl.get("public", False):
            controls[ctrl_name] = {
                **ctrl,
                "ready": ctrl.get("public", False) and "CAPTURAR" not in ctrl.get("open",
                         ctrl.get("lock", ctrl.get("on", "CAPTURAR"))),
            }
    return controls


def get_torque_style_pids(make: str) -> List[Dict]:
    """
    Retorna PIDs no estilo do Torque Pro — prontos para leitura em tempo real.
    Inclui fórmula de decodificação e unidade.
    """
    profile = get_profile(make)
    torque_pids = []

    # PIDs OBD2 base (estilo Torque)
    base_pids = [
        {"cmd": "010C", "name": "RPM",                "unit": "RPM",  "formula": "(A*256+B)/4"},
        {"cmd": "010D", "name": "Velocidade",          "unit": "km/h", "formula": "A"},
        {"cmd": "0105", "name": "Temp. Arrefecimento", "unit": "°C",  "formula": "A-40"},
        {"cmd": "010F", "name": "Temp. Ar Admissão",   "unit": "°C",  "formula": "A-40"},
        {"cmd": "0111", "name": "Posição Acelerador",  "unit": "%",   "formula": "A/2.55"},
        {"cmd": "012F", "name": "Nível Combustível",   "unit": "%",   "formula": "A/2.55"},
        {"cmd": "0142", "name": "Tensão Módulo",       "unit": "V",   "formula": "(A*256+B)/1000"},
        {"cmd": "0146", "name": "Temp. Ambiente",      "unit": "°C",  "formula": "A-40"},
        {"cmd": "015C", "name": "Temp. Óleo Motor",    "unit": "°C",  "formula": "A-40"},
    ]
    for pid in base_pids:
        torque_pids.append({**pid, "mode": "standard", "public": True})

    # Adiciona PIDs proprietários com fórmula
    for cmd, info in profile.get("custom_pids", {}).items():
        if info.get("public", True) and "formula" in info:
            torque_pids.append({
                "cmd": cmd, "name": info["name"], "unit": info.get("unit","raw"),
                "formula": info["formula"], "mode": "proprietary",
                "public": True, "source": info.get("source",""),
            })

    # Adiciona sinais CAN broadcast como referência
    for sig_name, sig in profile.get("can_signals", {}).items():
        if sig.get("public", True):
            torque_pids.append({
                "cmd": f"CAN_BROADCAST",
                "can_id": sig["id"], "name": sig["desc"],
                "unit": sig["unit"], "formula": sig["formula"],
                "mode": "can_broadcast", "public": True,
                "source": sig.get("source", ""),
            })

    return torque_pids


def profile_to_dict(make: str) -> Dict[str, Any]:
    """Serializa perfil para JSON — usado pela API."""
    profile = get_profile(make)
    return {
        "make": make,
        "name": profile["name"],
        "region": profile["region"],
        "models": profile["models"],
        "protocol": profile["protocol"],
        "can_speed": profile.get("can_speed", "500k"),
        "bcm_addr": profile.get("bcm_addr", "7B0"),
        "ecm_addr": profile.get("ecm_addr", "7E0"),
        "gateway_addr": profile.get("gateway_addr", "7DF"),
        "obd_pids": list(OBD2_STANDARD_PIDS.keys()),
        "custom_pids": profile.get("custom_pids", {}),
        "can_signals": profile.get("can_signals", {}),
        "bcm_controls": get_bcm_controls(make),
        "uds_sessions": profile.get("uds_sessions", {}),
        "security_notes": profile.get("security_notes", []),
        "source": profile.get("source", ""),
        "torque_pids": get_torque_style_pids(make),
        "stats": {
            "standard_pids":     len(OBD2_STANDARD_PIDS),
            "custom_pids":       len(profile.get("custom_pids", {})),
            "can_signals":       len(profile.get("can_signals", {})),
            "bcm_controls":      len(profile.get("bcm_controls", {})),
            "public_controls":   sum(
                1 for c in profile.get("bcm_controls",{}).values() if c.get("public")),
            "ready_controls":    sum(
                1 for c in get_bcm_controls(make).values() if c.get("ready")),
        },
    }
