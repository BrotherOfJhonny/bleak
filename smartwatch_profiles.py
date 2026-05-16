"""
smartwatch_profiles.py
======================
Perfis de seguranca para smartwatches -- cenÃ¡rio de demonstracao para conferÃªncias.

Foco principal: Xiaomi Mi Band 3 / Mi Band 4 + Zepp Life (ex-Mi Fit)
P->blico: Mindthesec, BSides, Ekoparty

ReferÃªncias tecnicas (todas pÃ->blicas):
  [1] BreakMi: Reversing, Exploiting and Fixing Xiaomi Fitness Tracking Ecosystem
      Casagrande et al. -- CHES 2022, EPFL HexHive Lab
      https://hexhive.epfl.ch/publications/files/22CHES.pdf

  [2] BlueDoor: Breaking the Secure Information Flow via BLE Vulnerability
      MobiSys 2020 -- Tsinghua University

  [3] Yogesh Ojha -- I hacked MiBand 3 (Medium, 2019)
      Reverse engineering pÃ->blico do protocolo Mi Band 3

  [4] Xiaomi Mi Band BLE Protocol Analysis (changy-.github.io)
      Mapeamento completo de servicos 0xFEE0/0xFEE1/0xFEE7

NOTA: Vulnerabilidades descritas aqui sao CONHECIDAS PUBLICAMENTE e foram
reportadas aos fabricantes. Use apenas para demonstracÃµes autorizadas e educacao.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple


# =============================================================================
# PERFIL Mi Band 3 / Mi Band 4 -- PROTOCOLO BLE (Zepp Life / Mi Fit)
# =============================================================================
# Fonte principal: BreakMi paper (2022) + Yogesh Ojha (2019) + changy- (2015-2018)
#
# ARQUITETURA DE COMUNICAÃÃO:
#
#   âââââââââââââââââââ         BLE (sem link-layer security!)         ââââââââââââââââââââ
#   â  Samsung A10    â ââââââââââââââââââââââââââââââââââââââââââââ-> â  Mi Band 3/4     â
#   â  Zepp Life app  â   Protocolo Xiaomi proprietÃ¡rio sobre GATT    â  (GATT server)   â
#   ââââââââââ¬âââââââââ                                               ââââââââââââââââââââ
#            â HTTPS/TLS
#            â<-
#   âââââââââââââââââââ
#   â  Backend Huami  â  (servidor Xiaomi na China)
#   âââââââââââââââââââ
#
# VULNERABILIDADE CENTRAL (BreakMi Â§4):
#   A Xiaomi DESABILITA intencionalmente os mecanismos de seguranca BLE (BLE pairing,
#   link-layer encryption, BLE Secure Connections) apesar de os dispositivos suportarem.
#   Em vez disso, usa protocolo de autenticacao proprietÃ¡rio com falhas:
#   - Autenticacao UNILATERAL (banda autentica app, mas app NÃO autentica banda)
#   - Chave AES-128 derivada do endereco Bluetooth (previsÃ­vel!)
#   - Sem protecao contra replay nas mensagens de autenticacao
# =============================================================================

MIBAND_SERVICES = {
    # ââ Servicos padrao SIG ââââââââââââââââââââââââââââââââââââââââââââââââââ
    "0000180a-0000-1000-8000-00805f9b34fb": {
        "name": "Device Information Service",
        "short": "180A",
        "description": "Firmware, modelo, serial -- leitura pÃ->blica sem auth",
        "auth_required": False,
        "risk": "medium",
    },
    "0000180d-0000-1000-8000-00805f9b34fb": {
        "name": "Heart Rate Service",
        "short": "180D",
        "description": "Leitura e notificacÃµes de BPM em tempo real",
        "auth_required": False,  # Mi Band 3/4 NÃO requer auth para leitura!
        "risk": "critical",
    },
    "00001800-0000-1000-8000-00805f9b34fb": {
        "name": "Generic Access",
        "short": "1800",
        "description": "Device name, appearance",
        "auth_required": False,
        "risk": "low",
    },
    "00001801-0000-1000-8000-00805f9b34fb": {
        "name": "Generic Attribute",
        "short": "1801",
        "description": "Service changed characteristic",
        "auth_required": False,
        "risk": "low",
    },
    # ââ Servicos PROPRIETÃRIOS Xiaomi (0xFEEx) ââââââââââââââââââââââââââââââââ
    "0000fee0-0000-1000-8000-00805f9b34fb": {
        "name": "Mi Band Main Service (0xFEE0)",
        "short": "FEE0",
        "description": "Servico principal Xiaomi -- activity data, steps, sleep, notifications",
        "auth_required": True,   # Requer auth do protocolo Xiaomi (nao BLE pairing)
        "risk": "critical",
        "characteristics": {
            "0000ff01-0000-1000-8000-00805f9b34fb": "Device Info (16 bytes: MAC, firmware, features)",
            "0000ff02-0000-1000-8000-00805f9b34fb": "Device Name",
            "0000ff03-0000-1000-8000-00805f9b34fb": "Notification / Alert",
            "0000ff04-0000-1000-8000-00805f9b34fb": "User Info (idade, peso, altura, gÃªnero)",
            "0000ff05-0000-1000-8000-00805f9b34fb": "Control Point (reset, factory reset, reboot)",
            "0000ff06-0000-1000-8000-00805f9b34fb": "Realtime Steps",
            "0000ff07-0000-1000-8000-00805f9b34fb": "Activity Data",
            "0000ff08-0000-1000-8000-00805f9b34fb": "Firmware Data (OTA upload!)",
            "0000ff0c-0000-1000-8000-00805f9b34fb": "Battery (level, charging, cycles)",
            "0000ff0f-0000-1000-8000-00805f9b34fb": "Test (hardware test trigger)",
            "0000ff17-0000-1000-8000-00805f9b34fb": "Display Settings",
            "0000ff20-0000-1000-8000-00805f9b34fb": "Wi-Fi Credentials (Mi Band 4)",
        },
    },
    "0000fee1-0000-1000-8000-00805f9b34fb": {
        "name": "Mi Band Auth Service (0xFEE1)",
        "short": "FEE1",
        "description": "Servico de autenticacao proprietÃ¡ria Xiaomi -- AES-128 chave fraca",
        "auth_required": False,  # AcessÃ­vel SEM auth para iniciar protocolo de auth!
        "risk": "critical",
        "characteristics": {
            "00000009-0000-3512-2118-0009af100700": "Auth Characteristic (AES-128 key exchange)",
            # Processo: 0x01 request â 0x10 random_number â 0x11 encrypted_response â 0x13 OK
        },
    },
    "0000fee7-0000-1000-8000-00805f9b34fb": {
        "name": "Mi Band DFU Service (0xFEE7)",
        "short": "FEE7",
        "description": "Device Firmware Update -- atualizacao OTA sem assinatura criptogrÃ¡fica",
        "auth_required": True,
        "risk": "critical",
    },
}


MIBAND_CHARACTERISTICS = {
    # ââ Heart Rate (0x180D) âââââââââââââââââââââââââââââââââââââââââââââââââââ
    "00002a37-0000-1000-8000-00805f9b34fb": {
        "name": "Heart Rate Measurement",
        "handle": "0x38",
        "properties": "NOTIFY",
        "format": "Byte[0]=flags, Byte[1]=BPM (uint8)",
        "auth_required": False,  # Mi Band 3/4: notificacÃµes abertas!
        "injectable": False,     # Read-only do ponto de vista do central
        "risk": "critical",
        "demo_value": bytes([0x00, 0x48]),  # 0x48 = 72 BPM
        "attack_value": bytes([0x00, 0xC8]),  # 0xC8 = 200 BPM (falsificado!)
    },
    "00002a39-0000-1000-8000-00805f9b34fb": {
        "name": "Heart Rate Control Point",
        "handle": "0x3A",
        "properties": "WRITE_NO_RESPONSE",
        "format": "Byte: 0x15=start continuous, 0x16=stop, 0x14=start manual, 0x19=start oneshot",
        "auth_required": False,  # Mi Band 3/4: controle sem auth!
        "injectable": True,      # ATACANTE PODE ESCREVER AQUI
        "risk": "critical",
        "payloads": {
            "start_continuous": bytes([0x15]),  # Ativa monitoramento contÃ­nuo
            "start_oneshot": bytes([0x19]),     # Leitura Ã->nica
            "stop": bytes([0x16]),              # Para monitoramento
        },
    },
    # ââ Device Information ââââââââââââââââââââââââââââââââââââââââââââââââââââ
    "00002a24-0000-1000-8000-00805f9b34fb": {
        "name": "Model Number",
        "handle": "0x12",
        "properties": "READ",
        "auth_required": False,
        "injectable": False,
        "risk": "medium",
        "demo_value": b"Mi Smart Band 4",
    },
    "00002a26-0000-1000-8000-00805f9b34fb": {
        "name": "Firmware Revision",
        "handle": "0x14",
        "properties": "READ",
        "auth_required": False,
        "injectable": False,
        "risk": "high",
        "demo_value": b"V1.0.9.74",
    },
    # ââ Mi Band Proprietary âââââââââââââââââââââââââââââââââââââââââââââââââââ
    "0000ff01-0000-1000-8000-00805f9b34fb": {
        "name": "Mi Band Device Info",
        "handle": "0x01",
        "properties": "READ",
        "format": "16 bytes: [0-5]=MAC reversed, [6-7]=firmware, [8]=BLE features, ...",
        "auth_required": False,  # Leitura livre!
        "injectable": False,
        "risk": "high",
    },
    "0000ff03-0000-1000-8000-00805f9b34fb": {
        "name": "Mi Band Alert/Notification",
        "handle": "0x07",
        "properties": "WRITE_NO_RESPONSE",
        "format": "Byte[0]=type (0x01=message, 0x02=phone call, 0x03=vibrate), ...",
        "auth_required": True,   # Requer auth Xiaomi (mas auth e bypassÃ¡vel!)
        "injectable": True,      # ATACANTE PODE INJETAR NOTIFICAÃÃES
        "risk": "critical",
        "payloads": {
            "phone_call": bytes([0x02]),               # Simula ligacao recebida
            "vibrate": bytes([0x01]),                  # Vibracao generica
            "message_alert": bytes([0x01, 0x00]),      # Alerta de mensagem
            "silent": bytes([0x00]),                   # Para alerta
        },
    },
    "0000ff05-0000-1000-8000-00805f9b34fb": {
        "name": "Mi Band Control Point",
        "handle": "0x0B",
        "properties": "WRITE_NO_RESPONSE",
        "format": "Byte[0]=command (0x01=alarm, 0x02=reboot, 0x03=user_info, ...)",
        "auth_required": True,
        "injectable": True,
        "risk": "critical",
        "payloads": {
            "factory_reset": bytes([0x06]),
            "reboot": bytes([0x02]),
            "set_goal": bytes([0x05, 0x00, 0x40, 0x0D, 0x00, 0x00]),  # 3500 steps
        },
    },
    "0000ff0c-0000-1000-8000-00805f9b34fb": {
        "name": "Mi Band Battery Info",
        "handle": "0x18",
        "properties": "READ",
        "format": "Byte[0]=level%, Byte[1-6]=last_charge_datetime, Byte[7]=charge_count, Byte[9]=status",
        "auth_required": False,
        "injectable": False,
        "risk": "medium",
        "demo_value": bytes([0x5A, 0x0F, 0x0A, 0x1A, 0x06, 0x04, 0x3B, 0x11, 0x00, 0x04]),
        # 0x5A = 90% | 2015-10-26 6:04:59 | 17 charges | status: not charging
    },
}


# =============================================================================
# PROTOCOLO DE AUTENTICAÃÃO XIAOMI (vulnerÃ¡vel)
# Fonte: BreakMi paper Â§3.2 + changy- RE analysis
# =============================================================================

XIAOMI_AUTH_PROTOCOL = {
    "version": "v2 (Mi Band 3/4 com Zepp Life)",
    "reference": "BreakMi Â§3.2, Figura 4",
    "vulnerabilities": [
        "UNILATERAL: App autentica Banda, mas Banda NÃO autentica App â Impersonation attack",
        "REPLAYABLE: Auth challenge pode ser respondida offline sem conhecer chave",
        "WEAK KEY: AES-128 key derivada de: SHA1(pub_k) + MAC address (pÃ->blico!)",
        "NO BLE SECURITY: Link-layer encryption desabilitada -- trÃ¡fego em plaintext",
    ],
    "steps": {
        1: "App envia Pairing Init â {0x01, 0x8, auth_key_index}",
        2: "Banda responde com pair_v2 + SHA1(pub_k)",
        3: "App solicita nÃ->mero aleatÃ³rio R (16 bytes)",
        4: "Banda responde com R",
        5: "Ambos computam Key = kdf(R, tracker_BLE_address)",
        6: "App envia SHA1(pub_k) + Key (base64) ao backend Huami",
        7: "Backend responde com Sig = sign_private_key(Key)",
        8: "App apresenta Sig a banda â banda verifica e confirma",
        9: "VULNERABILIDADE: Atacante ignora Sig, responde 0x10 Auth OK â banda aceita!",
    },
    "auth_characteristic": "00000009-0000-3512-2118-0009af100700",
    "auth_key_derivation": "AES-128(random_number, auth_key) onde auth_key = primeiros 16 bytes de MD5(BLE_MAC)",
}


# =============================================================================
# CENÃRIOS DE ATAQUE -- DEMONSTRAÃÃO MINDTHESEC/BSIDES/EKOPARTY
# =============================================================================

DEMO_ATTACK_SCENARIOS = {

    # ââ CENÃRIO 1: Impersonation (OTA Tracker Impersonation) âââââââââââââââââ
    "AT-MIB-001": {
        "name": "Mi Band Impersonation -- Tracker Falso",
        "conference_title": "Seu relÃ³gio estÃ¡ mentindo para vocÃª",
        "difficulty": "medio",
        "equipment": ["Kali Linux", "Adaptador BT (HCI)", "Python + bleak"],
        "reference": "BreakMi paper, Attack 1: OTA Tracker Impersonation",
        "time_to_execute": "~30 segundos apÃ³s setup",
        "detection_risk": "MÃ­nimo -- sem sintomas visuais no band/smartphone",

        "description": (
            "O atacante clona o endereco BLE MAC da Mi Band alvo e serve um GATT server falso. "
            "O Zepp Life (Samsung A10) identifica o dispositivo como confiÃ¡vel e conecta ao "
            "atacante. Auth e bypassada pois o protocolo Xiaomi e unilateral -- a banda autentica "
            "o app, mas o app NÃO autentica a banda. O atacante pode entao:\n"
            "  â¢ Injetar dados falsos de frequÃªncia cardÃ­aca (ex: 200 BPM)\n"
            "  â¢ Injetar notificacÃµes falsas (ligacao de 'CEO da empresa', 'alerta medico')\n"
            "  â¢ Recusar repassar dados reais â DoS de sincronizacao\n"
            "  â¢ Coletar auth tokens para ataques subsequentes"
        ),
        "attack_chain": [
            "1. Scan passivo BLE â identifica Mi Band alvo (MAC: C8:0F:10:XX:XX:XX e prefixo tÃ­pico)",
            "2. Captura advertising packets da Mi Band real",
            "3. Desconecta a Mi Band real (forca_disconnect ou jamming seletivo)",
            "4. Levanta GATT server falso com MAC clonado",
            "5. Zepp Life conecta ao atacante (reconhece como device confiÃ¡vel)",
            "6. Bypass da autenticacao Xiaomi (unilateral -- responder 0x10 Auth OK)",
            "7. Injetar dados no app â app salva dados falsos + sincroniza com servidor Huami",
        ],
        "impact_demo": [
            "ð± Samsung A10 mostra BPM falsificado (200 BPM â usuÃ¡rio em pÃ¢nico?)",
            "ð Notificacao falsa de ligacao â usuÃ¡rio interage",
            "ð¾ Dados falsos sincronizados com conta Mi Health/Zepp",
            "ð Dados de passos falsificados â distorcao de histÃ³rico medico",
        ],
        "mitigations": [
            "BLE Secure Connections (LESC) -- suportado pelo hardware, ignorado pela Xiaomi",
            "ECDH para autenticacao mutuatua",
            "Certificate Pinning no app + validacao de identidade da banda",
        ],
    },

    # ââ CENÃRIO 2: MiTM -- Interceptacao + Modificacao de Dados âââââââââââââââ
    "AT-MIB-002": {
        "name": "Mi Band MITM -- Interceptacao e Injecao de Dados",
        "conference_title": "O que seu monitor cardÃ­aco nao sabe que vocÃª sabe",
        "difficulty": "avancado",
        "equipment": ["Kali Linux", "2x adaptadores BT (HCI)", "Python + bleak + hciconfig"],
        "reference": "BreakMi paper, Attack 3: OTA MiTM. BlueDoor (MobiSys 2020)",
        "time_to_execute": "2â5 minutos para posicionamento",
        "detection_risk": "Baixo -- latÃªncia levemente aumentada, as vezes reconexao",

        "description": (
            "MITM posiciona-se entre Samsung A10 (Zepp Life) e Mi Band real. "
            "Como Xiaomi desabilita link-layer encryption, todo trÃ¡fego e em plaintext. "
            "O atacante:\n"
            "  1. Conecta silenciosamente a Mi Band real (relay)\n"
            "  2. Serve GATT server falso ao Samsung A10 (impersonation)\n"
            "  3. Intercepta TODOS os dados bidirecionais\n"
            "  4. MODIFICA dados antes de repassar (injecao)\n\n"
            "Dados comprometidos: BPM, SpO2, steps, sleep patterns, notificacÃµes SMS/WhatsApp"
        ),
        "attack_chain": [
            "Pre-ataque:",
            "  1. Scan â identifica MAC da Mi Band alvo",
            "  2. Captura advertising e connection parameters",
            "",
            "Fase 1 -- Relay com Mi Band real (HCI adapter 1):",
            "  3. Conecta a Mi Band como GATT client legÃ­timo",
            "  4. Autentica usando protocolo Xiaomi (bypassÃ¡vel -- ver AT-MIB-001)",
            "  5. Assina CCCDs para receber notificacÃµes (HR, steps, alerts)",
            "",
            "Fase 2 -- Impersonation do Zepp Life (HCI adapter 2):",
            "  6. Clona MAC da Mi Band, sobe GATT server espelho",
            "  7. Zepp Life conecta ao servidor falso",
            "  8. Bypass de autenticacao (unilateral â 0x10 Auth OK)",
            "",
            "Fase 3 -- Intercept + Modify:",
            "  9. HR real: 72 BPM â injetar: 45 BPM (bradycardia falsa!) ou 200 BPM",
            " 10. NotificacÃµes SMS: capturar conteÃ->do antes de exibir no band",
            " 11. Steps: falsificar contagem diÃ¡ria",
        ],
        "data_intercepted": {
            "heart_rate": "BPM em tempo real -- dado medico sensÃ­vel",
            "spo2": "SpO2 (Mi Band 4) -- saturacao de oxigÃªnio",
            "sleep": "PadrÃµes de sono (horÃ¡rio deitar/acordar)",
            "steps": "Contagem de passos e calorias",
            "notifications": "Primeiros 15-20 chars de SMS/WhatsApp/notificacÃµes",
            "user_info": "Peso, altura, idade, gÃªnero configurados no app",
        },
        "data_injectable": {
            "heart_rate": "Qualquer valor 0â255 BPM (ex: 200 = alarme falso, 40 = emergÃªncia)",
            "notifications": "Texto arbitrÃ¡rio exibido na tela do band",
            "vibration": "Padrao de vibracao arbitrÃ¡rio",
            "steps": "Contagem de passos falsificada",
        },
        "impact_demo": [
            "ð« Zepp Life mostra BPM de 45 â usuÃ¡rio preocupado â busca medico desnecessariamente",
            "ð¨ Notificacao: 'URGENTE: Seu banco bloqueou seu cartao. Ligue 0800...'",
            "ð´ HistÃ³rico de sono falsificado â seguro de saÃ->de baseado em dados manipulados",
            "ð Dados subidos ao servidor Huami com informacÃµes adulteradas",
        ],
    },

    # ââ CENÃRIO 3: Injecao Direta de Alertas (sem MITM completo) âââââââââââââ
    "AT-MIB-003": {
        "name": "Notification Injection -- Alertas Falsos na Mi Band",
        "conference_title": "Engenharia social via relÃ³gio inteligente",
        "difficulty": "fÃ¡cil",
        "equipment": ["Kali Linux", "1x adaptador BT", "Python + bleak"],
        "reference": "Yogesh Ojha, Medium 2019. Protocolo 0xFF03 documentado publicamente.",
        "time_to_execute": "< 60 segundos apÃ³s auth bypass",
        "detection_risk": "Zero -- notificacÃµes parecem normais no band",

        "description": (
            "ApÃ³s conexao e bypass de autenticacao, o atacante pode enviar notificacÃµes "
            "arbitrÃ¡rias a Mi Band via characteristic 0xFF03 (Alert). "
            "O dispositivo exibe o texto na tela e vibra -- indistinguÃ­vel de notificacao real. "
            "CenÃ¡rio de engenharia social com alta eficÃ¡cia em ambiente de conferÃªncia."
        ),
        "notification_payloads": {
            # Payload format: [type_byte, ...text_bytes]
            "phone_call": "0x02 â exibe 'Ligacao' + nÃ->mero ou nome",
            "sms_alert":  "0x01 + UTF-8 text â exibe mensagem",
            "vibrate_3x": "0x01 + 3 bytes â vibracao tripla (urgÃªncia)",
            "silent":     "0x00 â para qualquer alerta ativo",
        },
        "social_engineering_examples": [
            "'Banco ItaÃ->: Transacao R$1.450 aprovada. Nao fui eu? Ligue *****'",
            "'Alerta: Temperatura corporal 38.9Â°C detectada. Procure atendimento.'",
            "'CEO Joao Silva: Reuniao urgente sala 3 AGORA'",
            "'Zepp Life: Atualizacao de seguranca necessÃ¡ria. Conecte no Wi-Fi.'",
        ],
    },

    # ââ CENÃRIO 4: OTA Firmware Attack (avancado, requer hardware) ââââââââââââ
    "AT-MIB-004": {
        "name": "OTA Firmware Injection -- Mi Band 3",
        "conference_title": "Seu relÃ³gio agora e meu",
        "difficulty": "muito avancado",
        "equipment": ["Kali Linux", "BT adapter", "Python + bleak", "Firmware bin modificado"],
        "reference": "Yogesh Ojha, Part II -- OTA Firmware Hack. FEE7 service sem assinatura.",
        "time_to_execute": "5-15 minutos (upload + flash)",
        "detection_risk": "Medio -- band reinicia durante update",

        "description": (
            "A Mi Band 3 aceita firmware via OBD service 0xFEE7 SEM verificacao de assinatura. "
            "Qualquer firmware compilado para a plataforma (Dialog DA14681/DA14697) pode ser "
            "instalado. O atacante pode modificar o firmware oficial e re-flashar remotamente.\n\n"
            "NOTA: Este ataque e destrutivo e irreversÃ­vel sem acesso fÃ­sico/JTAG. "
            "Para demonstracao em conferÃªncia, use hardware dedicado (Mi Band extra)."
        ),
        "demonstration_note": (
            "Para Mindthesec/BSides/Ekoparty: usar Mi Band de sacrifÃ­cio. "
            "Modificacao mÃ­nima recomendada: trocar tela de boot (imagem) para demonstrar "
            "compromisso sem destruir funcionalidade. Firmware binÃ¡rio disponÃ­vel para RE."
        ),
    },
}


# =============================================================================
# MAPEAMENTO COMPLETO DE UUIDs -- Mi Band 3 / Mi Band 4
# Fontes: changy- (2015), Yogesh Ojha (2019), BreakMi (2022), satcar77/miband4
# =============================================================================

MIBAND_UUID_MAP = {
    # ââ Servicos âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
    "0000180a-0000-1000-8000-00805f9b34fb": ("Service",    "Device Information",       "medium"),
    "0000180d-0000-1000-8000-00805f9b34fb": ("Service",    "Heart Rate Service",        "critical"),
    "00001800-0000-1000-8000-00805f9b34fb": ("Service",    "Generic Access",            "low"),
    "00001801-0000-1000-8000-00805f9b34fb": ("Service",    "Generic Attribute",         "low"),
    "0000fee0-0000-1000-8000-00805f9b34fb": ("Service",    "Mi Band Main (Xiaomi prop)","critical"),
    "0000fee1-0000-1000-8000-00805f9b34fb": ("Service",    "Mi Band Auth (Xiaomi prop)","critical"),
    "0000fee7-0000-1000-8000-00805f9b34fb": ("Service",    "Mi Band DFU/OTA",           "critical"),
    "0000fd00-0000-1000-8000-00805f9b34fb": ("Service",    "Mi Band Extended (Band 4)", "critical"),
    # ââ CaracterÃ­sticas SIG padrao ââââââââââââââââââââââââââââââââââââââââââââ
    "00002a00-0000-1000-8000-00805f9b34fb": ("Char",       "Device Name",               "low"),
    "00002a01-0000-1000-8000-00805f9b34fb": ("Char",       "Appearance",                "low"),
    "00002a24-0000-1000-8000-00805f9b34fb": ("Char",       "Model Number",              "medium"),
    "00002a25-0000-1000-8000-00805f9b34fb": ("Char",       "Serial Number",             "high"),
    "00002a26-0000-1000-8000-00805f9b34fb": ("Char",       "Firmware Revision",         "high"),
    "00002a27-0000-1000-8000-00805f9b34fb": ("Char",       "Hardware Revision",         "medium"),
    "00002a28-0000-1000-8000-00805f9b34fb": ("Char",       "Software Revision",         "medium"),
    "00002a29-0000-1000-8000-00805f9b34fb": ("Char",       "Manufacturer Name",         "low"),
    "00002a37-0000-1000-8000-00805f9b34fb": ("Char",       "Heart Rate Measurement",    "critical"),
    "00002a39-0000-1000-8000-00805f9b34fb": ("Char",       "Heart Rate Control Point",  "critical"),
    # ââ CaracterÃ­sticas ProprietÃ¡rias 0xFEE0 (Mi Band Main) ââââââââââââââââââ
    "0000ff01-0000-1000-8000-00805f9b34fb": ("Char Priv",  "Device Info (16 bytes)",    "high"),
    "0000ff02-0000-1000-8000-00805f9b34fb": ("Char Priv",  "Device Name (writeable)",   "medium"),
    "0000ff03-0000-1000-8000-00805f9b34fb": ("Char Priv",  "Notification/Alert (inject)","critical"),
    "0000ff04-0000-1000-8000-00805f9b34fb": ("Char Priv",  "User Info (weight/height)", "critical"),
    "0000ff05-0000-1000-8000-00805f9b34fb": ("Char Priv",  "Control Point (reboot!)",   "critical"),
    "0000ff06-0000-1000-8000-00805f9b34fb": ("Char Priv",  "Realtime Steps",            "medium"),
    "0000ff07-0000-1000-8000-00805f9b34fb": ("Char Priv",  "Activity Data (historical)","high"),
    "0000ff08-0000-1000-8000-00805f9b34fb": ("Char Priv",  "Firmware Upload (OTA!)",    "critical"),
    "0000ff0c-0000-1000-8000-00805f9b34fb": ("Char Priv",  "Battery Status",            "medium"),
    "0000ff0f-0000-1000-8000-00805f9b34fb": ("Char Priv",  "Test Mode Trigger",         "high"),
    "0000ff17-0000-1000-8000-00805f9b34fb": ("Char Priv",  "Display Settings",          "medium"),
    "0000ff20-0000-1000-8000-00805f9b34fb": ("Char Priv",  "Device Configuration",      "critical"),
    # ââ CaracterÃ­sticas Auth 0xFEE1 âââââââââââââââââââââââââââââââââââââââââââ
    "00000009-0000-3512-2118-0009af100700": ("Char Auth",  "Auth Key Exchange (AES-128)","critical"),
    # ââ Descritores ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
    "00002902-0000-1000-8000-00805f9b34fb": ("Descriptor", "CCCD (enable notifications)","medium"),
    "00002901-0000-1000-8000-00805f9b34fb": ("Descriptor", "User Description",           "low"),
}


# =============================================================================
# PERFIS DE OUTROS SMARTWATCHES -- para expandir a demonstracao na conferÃªncia
# =============================================================================

SMARTWATCH_PROFILES = {

    "miband3": {
        "name": "Xiaomi Mi Band 3",
        "model": "Mi Smart Band 3 (XMSH05HM)",
        "year": 2018,
        "ble_version": "4.2",
        "soc": "Dialog DA14681",
        "mac_prefix": "C8:0F:10",  # OUI Huami Technology
        "services": list(MIBAND_SERVICES.keys()),
        "key_uuids": ["0000fee0", "0000fee1", "0000180d", "0000fee7"],
        "auth_bypass": True,
        "link_layer_encryption": False,  # Xiaomi desabilita!
        "ota_signed": False,
        "attacks": ["AT-MIB-001", "AT-MIB-002", "AT-MIB-003", "AT-MIB-004"],
        "companion_app": "Zepp Life (ex-Mi Fit)",
        "companion_package": "com.xiaomi.hm.health",
        "vulnerabilities": [
            "BreakMi: Unilateral authentication (app doesn't verify band)",
            "BreakMi: Replayable authentication",
            "BlueDoor: MITM via MAC spoofing + auth bypass",
            "No BLE link-layer encryption (ignores BLE SC)",
            "OTA without firmware signing",
        ],
        "cves": [],  # Xiaomi nao emitiu CVEs -- corrigido silenciosamente em versÃµes posteriores
        "references": [
            "BreakMi (CHES 2022) -- https://hexhive.epfl.ch/publications/files/22CHES.pdf",
            "BlueDoor (MobiSys 2020) -- https://tns.thss.tsinghua.edu.cn/~jiliang/publications/MOBISYS2020_BlueDoor.pdf",
            "Yogesh Ojha (2019) -- https://medium.com/@yogeshojha/i-hacked-xiaomi-miband-3-and-here-is-how-i-did-it",
        ],
    },

    "miband4": {
        "name": "Xiaomi Mi Band 4",
        "model": "Mi Smart Band 4 (XMSH07HM)",
        "year": 2019,
        "ble_version": "5.0",
        "soc": "Dialog DA14697",
        "mac_prefix": "C8:0F:10",  # Mesmo OUI Huami
        "services": list(MIBAND_SERVICES.keys()),
        "key_uuids": ["0000fee0", "0000fee1", "0000180d", "0000fee7", "0000fd00"],
        "auth_bypass": True,
        "link_layer_encryption": False,  # Ainda desabilitado no Band 4!
        "ota_signed": False,
        "attacks": ["AT-MIB-001", "AT-MIB-002", "AT-MIB-003", "AT-MIB-004"],
        "additional_data": ["SpO2 (saturacao O2)", "Stress level", "Menstrual cycle data"],
        "companion_app": "Zepp Life (ex-Mi Fit)",
        "companion_package": "com.xiaomi.hm.health",
        "vulnerabilities": [
            "Mesmas do Mi Band 3 + dados adicionais (SpO2, ciclo menstrual)",
            "Wi-Fi credential storage em 0xFF20 -- credenciais expostas via auth bypass",
        ],
        "references": [
            "BreakMi (CHES 2022) -- estudo inclui Mi Band 4",
            "satcar77/miband4 -- https://github.com/satcar77/miband4",
        ],
    },

    "fitbit_inspire": {
        "name": "Fitbit Inspire / Inspire HR",
        "year": "2019-2022",
        "ble_version": "4.1",
        "mac_prefix": "C0:15:1B",  # Fitbit OUI
        "key_uuids": ["adabfb00", "adabfb01", "adabfb02"],  # Fitbit proprietary
        "auth_bypass": False,  # Fitbit tem autenticacao mais robusta
        "link_layer_encryption": True,
        "ota_signed": True,
        "attacks": ["AT-MIB-003"],  # Apenas notification se AUTH bypassada
        "companion_app": "Fitbit App",
        "vulnerabilities": [
            "BreakMi: Auth bypass adaptado de Xiaomi para Fitbit (vulnerabilidade similar)",
            "breakmi tool porting -- https://hexhive.epfl.ch",
        ],
    },

    "generic_ble_watch": {
        "name": "Smartwatch BLE Generico (mercado livre/AliExpress)",
        "description": "Dispositivos com protocolos nao documentados, sem autenticacao",
        "mac_prefix": "varies",
        "key_uuids": ["0000180d", "0000fee0", "0000fee1"],
        "auth_bypass": True,   # Geralmente sem auth alguma
        "link_layer_encryption": False,
        "ota_signed": False,
        "attacks": ["AT-MIB-001", "AT-MIB-003"],
        "vulnerabilities": [
            "Sem autenticacao alguma -- dados completamente abertos",
            "OTA sem assinatura",
            "NotificacÃµes injetÃ¡veis sem restricao",
        ],
    },
}


# =============================================================================
# GUIA DE DEMONSTRAÃÃO PARA CONFERÃNCIA
# =============================================================================

CONFERENCE_DEMO_GUIDE = {
    "setup_hardware": {
        "items": [
            "1x Mi Band 3 (alvo -- usada pelo 'usuÃ¡rio vÃ­tima' na demo)",
            "1x Mi Band 4 (alvo alternativo)",
            "1x Samsung A10 com Zepp Life instalado e banda pareada",
            "1x Laptop Kali Linux com Python 3.10+",
            "1x USB Bluetooth LE adapter (ASUS USB-BT400 ou similar -- chipset BCM20702)",
            "Opcional: 2x adapters BT para cenÃ¡rio MITM real",
        ],
        "software_requirements": [
            "pip install bleak",
            "sudo apt install bluetooth bluez bluez-tools",
            "hciconfig hci0 up",
            "sudo python3 (necessÃ¡rio para raw BT socket)",
        ],
        "environment_check": [
            "hciconfig -a  # Verificar adapter",
            "bluetoothctl scan on  # Verificar deteccao da Mi Band",
            "python3 -c 'import bleak; print(bleak.__version__)'",
        ],
    },

    "demo_flow_15min": {
        "title": "Fluxo de Demo -- 15 minutos (Mindthesec/BSides)",
        "steps": [
            ("0:00", "Contexto", "Mostrar diagrama: Mi Band â Samsung A10 â Zepp Life â Servidor Huami"),
            ("0:02", "Discovery", "Rodar BLE scan â mostrar Mi Band no radar com MAC e UUIDs"),
            ("0:04", "UUID Resolution", "Resolver 0xFEE0/0xFEE1 com Nordic DB â mostrar que sao servicos Xiaomi proprietÃ¡rios"),
            ("0:06", "Auth Analysis", "Explicar o protocolo de auth Xiaomi (unilateral) com BreakMi slide"),
            ("0:08", "DEMO AO VIVO", "Conectar a Mi Band + bypass de auth â mostrar GATT server completo"),
            ("0:10", "Notification Injection", "Injetar alerta de ligacao falsa â Mi Band vibra e exibe na tela"),
            ("0:12", "Heart Rate Spoof", "Ativar HR monitoring â capturar BPM real â mostrar como MITM modificaria"),
            ("0:14", "Impacto + Remediacao", "O que Xiaomi deveria fazer: BLE SC + autenticacao mutuatua + firmware signing"),
        ],
    },

    "demo_flow_30min": {
        "title": "Fluxo de Demo -- 30 minutos (Ekoparty workshop)",
        "steps": [
            ("0:00", "Intro", "Ecossistema Xiaomi: 1 bilhao de dispositivos, mesmos protocolos"),
            ("0:03", "BLE Fundamentals", "GAP/GATT/Services/Characteristics -- o que o Nordic DB nos diz"),
            ("0:08", "Discovery + Fingerprint", "Scan â UUID resolution â identificar Mi Band 3 vs Band 4"),
            ("0:13", "Protocol RE", "Mostrar Wireshark + HCI snoop do auth protocol Xiaomi"),
            ("0:18", "DEMO 1: Auth Bypass", "Conectar, bypass, enumerar todas as caracterÃ­sticas"),
            ("0:22", "DEMO 2: Notification Inject", "Injetar mensagem de engenharia social"),
            ("0:25", "DEMO 3: MITM Setup", "Mostrar setup MITM (2 adapters), interceptar HR real"),
            ("0:28", "Remediacao + Disclosure", "BreakMi responsible disclosure, o que foi/nao foi corrigido"),
        ],
    },

    "ethical_notes": {
        "authorization": "Demonstracao com hardware prÃ³prio -- Mi Band e do pesquisador",
        "audience_device_protection": "Nao escanear nem conectar a dispositivos da audiÃªncia sem consentimento explÃ­cito",
        "responsible_disclosure": "Vulnerabilidades do BreakMi foram reportadas a Xiaomi/Huami em 2021. Paper publicado CHES 2022.",
        "legal_note": "Demonstracao educacional com dispositivo prÃ³prio -- legal no Brasil (Lei 12.737/2012 art. 2Â° Â§1Â° exige 'dispositivo alheio')",
    },
}


# =============================================================================
# FUNÃÃES UTILITÃRIAS
# =============================================================================

def get_profile(model: str) -> Dict[str, Any]:
    """Retorna perfil do smartwatch."""
    return SMARTWATCH_PROFILES.get(model, SMARTWATCH_PROFILES["generic_ble_watch"])


def get_attack_scenario(attack_id: str) -> Dict[str, Any]:
    """Retorna cenÃ¡rio de ataque completo."""
    return DEMO_ATTACK_SCENARIOS.get(attack_id, {})


def resolve_miband_uuid(uuid: str) -> Optional[Tuple[str, str, str]]:
    """
    Resolve UUID da Mi Band para (tipo, nome, risco).
    Retorna None se nao reconhecido.
    """
    u = uuid.lower()
    if u in MIBAND_UUID_MAP:
        return MIBAND_UUID_MAP[u]
    return None


def list_injectable_chars(model: str = "miband3") -> List[Dict[str, Any]]:
    """Lista caracterÃ­sticas injetÃ¡veis sem autenticacao completa."""
    injectable = []
    for uuid, char in MIBAND_CHARACTERISTICS.items():
        if char.get("injectable"):
            injectable.append({
                "uuid": uuid,
                "name": char["name"],
                "handle": char.get("handle","?"),
                "requires_auth": char.get("auth_required", True),
                "bypass_possible": True,  # Autenticacao Xiaomi e bypassÃ¡vel
                "payloads": list(char.get("payloads", {}).keys()),
                "risk": char["risk"],
                "demo_payload": list(char.get("payloads", {}).values())[0].hex() if char.get("payloads") else "",
            })
    return injectable


def profile_to_dict(model: str) -> Dict[str, Any]:
    """Serializa perfil para API JSON."""
    profile = get_profile(model)
    injectable = list_injectable_chars(model)
    return {
        **profile,
        "injectable_characteristics": injectable,
        "attack_scenarios": {
            aid: {
                "name": DEMO_ATTACK_SCENARIOS[aid]["name"],
                "difficulty": DEMO_ATTACK_SCENARIOS[aid]["difficulty"],
                "conference_title": DEMO_ATTACK_SCENARIOS[aid]["conference_title"],
                "time_to_execute": DEMO_ATTACK_SCENARIOS[aid]["time_to_execute"],
            }
            for aid in profile.get("attacks", [])
            if aid in DEMO_ATTACK_SCENARIOS
        },
        "demo_guide_15min": CONFERENCE_DEMO_GUIDE["demo_flow_15min"],
        "ethical_notes": CONFERENCE_DEMO_GUIDE["ethical_notes"],
        "uuid_map": {
            k: {"type": v[0], "name": v[1], "risk": v[2]}
            for k, v in MIBAND_UUID_MAP.items()
        },
    }
