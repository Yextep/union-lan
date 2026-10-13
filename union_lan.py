#!/usr/bin/env python3
# Copyright 2026 Yextep. See LICENSE and NOTICE for the applicable terms.
"""Incorporacion por invitacion y acceso SSH por identidad en una LAN IPv4."""

import argparse
import base64
import concurrent.futures
import contextlib
import fcntl
import hashlib
import hmac
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import select
import shlex
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

PROJECT = Path(__file__).resolve().parent
ALIAS = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
USER = re.compile(r"[a-z_][a-zA-Z0-9_-]{0,63}\Z")
LAN_RANGES = tuple(ipaddress.ip_network(value) for value in
                   ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8"))


def local_ipv4(value):
    address = ipaddress.IPv4Address(value)
    if not any(address in network for network in LAN_RANGES):
        raise ValueError("Union LAN solo admite direcciones IPv4 de red local.")
    return str(address)


def public_key(value):
    parts = value.split()
    if len(parts) not in (2, 3) or parts[0] != "ssh-ed25519":
        raise ValueError("Se requiere una clave publica SSH Ed25519 valida.")
    try:
        raw = base64.b64decode(parts[1], validate=True)
    except ValueError as exc:
        raise ValueError("Clave publica mal codificada.") from exc
    if len(raw) != 51 or raw[:19] != b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20":
        raise ValueError("Clave publica Ed25519 invalida.")
    return " ".join(parts[:2])


def fingerprint(key):
    raw = base64.b64decode(public_key(key).split()[1])
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def validate_node(alias, ip, user, key, port=8022):
    if not ALIAS.fullmatch(alias) or not USER.fullmatch(user):
        raise ValueError("Nombre o usuario invalido; usa letras, numeros, guion o guion bajo.")
    if not 1024 <= int(port) <= 65535:
        raise ValueError("Puerto fuera del intervalo 1024-65535.")
    return {"ip": local_ipv4(ip), "usuario": user,
            "clave": public_key(key), "puerto": int(port)}


def probe(ip, port, patient=False):
    """Consultar una clave no autoriza conexiones: luego se compara con la registrada."""
    try:
        # La IP conocida puede responder mas despacio bajo carga de Wi-Fi/CPU.
        # El barrido mantiene su limite corto para no alargar toda la subred.
        with socket.create_connection((ip, port), timeout=3 if patient else 0.35):
            pass
        result = subprocess.run(
            ["ssh-keyscan", "-T", "5" if patient else "2", "-p", str(port), "-t", "ed25519", ip],
            capture_output=True, text=True, timeout=6 if patient else 3)
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[1] == "ssh-ed25519":
                return public_key(" ".join(parts[1:]))
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    return None


def route_ip(target="192.0.2.1"):
    # UDP connect consulta la ruta sin transmitir paquetes.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((target, 9))
        return sock.getsockname()[0]


def atomic_write(path, contents):
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".union-lan-")
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(contents)
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class Manager:
    def __init__(self, home=None):
        self.home = Path(home) if home else Path.home()
        self.state_dir = self.home / ".config/union-lan"
        self.ssh_dir = self.home / ".ssh"
        self.state = self.state_dir / "nodos.json"
        self.identity = self.ssh_dir / "union-lan_ed25519"
        self.known_hosts = self.state_dir / "known_hosts"
        self.config = self.ssh_dir / "config.d/union-lan.conf"
        for directory in (self.state_dir, self.ssh_dir, self.config.parent):
            directory.mkdir(parents=True, mode=0o700, exist_ok=True)

    @contextlib.contextmanager
    def locked(self):
        with (self.state_dir / "lock").open("a") as stream:
            os.chmod(stream.name, 0o600)
            fcntl.flock(stream, fcntl.LOCK_EX)
            yield

    def load(self):
        if not self.state.exists():
            return {"nodos": {}, "redes": []}
        data = json.loads(self.state.read_text())
        for alias, node in data["nodos"].items():
            validate_node(alias, node["ip"], node["usuario"], node["clave"], node["puerto"])
        return data

    def prepare_identity(self):
        if not self.identity.exists():
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                            "-C", "union-lan", "-f", str(self.identity)], check=True)
        pub = Path(str(self.identity) + ".pub")
        if not pub.exists():
            result = subprocess.run(["ssh-keygen", "-y", "-f", str(self.identity)],
                                    capture_output=True, text=True, check=True)
            atomic_write(pub, result.stdout)
        return public_key(pub.read_text())

    @staticmethod
    def host_line(alias, node):
        # HostKeyAlias se guarda literalmente, incluso con un puerto distinto de 22.
        return f"union-lan-{alias} {node['clave']}\n"

    def write_config(self, data):
        lines = ["# Generado por union-lan. Los nombres siguen a la clave SSH.\n"]
        known = []
        for alias, node in sorted(data["nodos"].items()):
            proxy = shlex.join([sys.executable, str(PROJECT / "union_lan.py"), "proxy", alias])
            lines.append(f"\nHost {alias}\n"
                         f"    HostName {alias}\n"
                         f"    User {node['usuario']}\n"
                         f"    Port {node['puerto']}\n"
                         f'    IdentityFile "{self.identity}"\n'
                         f"    IdentitiesOnly yes\n"
                         f'    UserKnownHostsFile "{self.known_hosts}"\n'
                         f"    HostKeyAlias union-lan-{alias}\n"
                         f"    StrictHostKeyChecking yes\n"
                         f"    ServerAliveInterval 30\n"
                         f"    ServerAliveCountMax 3\n"
                         f"    ProxyCommand {proxy}\n")
            known.append(self.host_line(alias, node))
        atomic_write(self.config, "".join(lines))
        atomic_write(self.known_hosts, "".join(known))
        global_config = self.ssh_dir / "config"
        existing = global_config.read_text() if global_config.exists() else ""
        include = f"Include {self.config}"
        if include not in existing.splitlines():
            atomic_write(global_config, include + "\n\n" + existing)

    def save(self, data):
        atomic_write(self.state, json.dumps(data, indent=2, ensure_ascii=False) + "\n")

    def check_access(self, alias, node):
        if probe(node["ip"], node["puerto"]) != node["clave"]:
            raise ValueError("La clave presentada por esa IP no coincide con la enviada.")
        with tempfile.NamedTemporaryFile(mode="w", dir=self.state_dir) as stream:
            stream.write(self.host_line(alias, node))
            stream.flush()
            command = ["ssh", "-F", "/dev/null", "-i", str(self.identity),
                       "-p", str(node["puerto"]), "-o", "BatchMode=yes",
                       "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=5",
                       "-o", "StrictHostKeyChecking=yes",
                       "-o", f"UserKnownHostsFile={stream.name}",
                       "-o", f"HostKeyAlias=union-lan-{alias}",
                       f"{node['usuario']}@{node['ip']}", "whoami"]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            if result.returncode or result.stdout.strip() != node["usuario"]:
                raise ValueError("SSH no autentico con la clave central: " + result.stderr.strip())

    def register(self, alias, node):
        node = validate_node(alias, node["ip"], node["usuario"], node["clave"], node["puerto"])
        self.check_access(alias, node)
        with self.locked():
            data = self.load()
            old = data["nodos"].get(alias)
            if old and (old["clave"] != node["clave"] or old["usuario"] != node["usuario"]):
                raise ValueError("Ese nombre ya pertenece a otro dispositivo; elige otro nombre.")
            data["nodos"][alias] = node
            self.write_config(data)
            self.save(data)

    def networks(self, data, node):
        if data["redes"]:
            values = data["redes"]
        else:
            local = route_ip(node["ip"])
            values = [str(ipaddress.ip_network(local + "/24", strict=False))]
        networks = [ipaddress.ip_network(value, strict=False) for value in values]
        if any(net.version != 4 or net.num_addresses > 1024 for net in networks):
            raise ValueError("Usa redes IPv4 de hasta 1024 direcciones (/22 o menor).")
        if sum(net.num_addresses for net in networks) > 1024:
            raise ValueError("La busqueda admite como maximo 1024 direcciones en total.")
        if any(not any(network.subnet_of(allowed) for allowed in LAN_RANGES) for network in networks):
            raise ValueError("La busqueda solo admite redes IPv4 locales.")
        return networks

    def resolve(self, alias, force=False):
        data = self.load()
        if alias not in data["nodos"]:
            raise ValueError(f"Dispositivo desconocido: {alias}")
        node = data["nodos"][alias]
        if not force and probe(node["ip"], node["puerto"], patient=True) == node["clave"]:
            return node["ip"], node["puerto"]
        networks = self.networks(data, node)
        print(f"Buscando {alias} por su clave SSH en {', '.join(map(str, networks))}...", file=sys.stderr)
        candidates = sorted({str(ip) for network in networks for ip in network.hosts()})
        found = None
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=32)
        jobs = {executor.submit(probe, ip, node["puerto"]): ip for ip in candidates}
        try:
            for job in concurrent.futures.as_completed(jobs):
                if job.result() == node["clave"]:
                    found = jobs[job]
                    break
        finally:
            for job in jobs:
                job.cancel()
            executor.shutdown(wait=True, cancel_futures=True)
        if not found:
            raise ValueError(f"No se encontro {alias}. Comprueba Wi-Fi y que Termux/SSH siga activo.")
        with self.locked():
            latest = self.load()
            if latest["nodos"].get(alias, {}).get("clave") != node["clave"]:
                raise ValueError("La identidad cambio durante la busqueda; vuelve a intentar.")
            latest["nodos"][alias]["ip"] = found
            self.save(latest)
        print(f"{alias} encontrado en {found}.", file=sys.stderr)
        return found, node["puerto"]


class Invitation:
    def __init__(self, manager, alias, url, seconds=1800):
        if not ALIAS.fullmatch(alias):
            raise ValueError("Nombre invalido para el dispositivo.")
        self.manager, self.alias, self.url = manager, alias, url
        self.token = secrets.token_urlsafe(24)
        self.expires = time.monotonic() + seconds
        self.used = False
        self.lock = threading.Lock()
        values = {"CENTRAL_KEY": manager.prepare_identity(), "CENTRAL_URL": url,
                  "TOKEN": self.token, "ALIAS": alias}
        template = (PROJECT / "incorporar-termux.sh.template").read_text()
        # Cada instalador distribuido lleva los terminos completos y los creditos.
        legal = "\n".join("# " + line for line in (PROJECT / "LICENSE").read_text().splitlines())
        shebang, body = template.split("\n", 1)
        template = shebang + "\n" + legal + "\n" + body
        for name, value in values.items():
            template = template.replace("@" + name + "@", shlex.quote(value))
        self.script = template.encode()

    def valid(self, token):
        return (not self.used and time.monotonic() < self.expires
                and hmac.compare_digest(token.encode(), self.token.encode()))

    def command(self):
        url = self.url + "/instalar/" + self.token
        digest = hashlib.sha256(self.script).hexdigest()
        return (f"curl -fsS {shlex.quote(url)} -o ~/union-lan-incorporar.sh && "
                f"printf '%s  %s\\n' {digest} ~/union-lan-incorporar.sh | sha256sum -c - && "
                "bash ~/union-lan-incorporar.sh")


def handler_for(invitation):
    class Handler(http.server.BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, *args):
            # Evita registrar el token de invitacion en el log de URLs.
            pass

        def reply(self, code, value, content_type="text/plain; charset=utf-8"):
            body = value if isinstance(value, bytes) else value.encode()
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            prefix = "/instalar/"
            if not self.path.startswith(prefix) or not invitation.valid(self.path[len(prefix):]):
                self.reply(403, "Invitacion invalida, usada o vencida.\n")
                return
            self.reply(200, invitation.script)

        def do_POST(self):
            if self.path != "/incorporar":
                self.reply(404, "Ruta desconocida.\n")
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 4096:
                    raise ValueError("Solicitud demasiado grande o vacia.")
                fields = urllib.parse.parse_qs(self.rfile.read(size).decode(), strict_parsing=True)
                with invitation.lock:
                    if not invitation.valid(fields.get("token", [""])[0]):
                        self.reply(403, "Invitacion invalida, usada o vencida.\n")
                        return
                    node = validate_node(invitation.alias, self.client_address[0],
                                         fields["usuario"][0], fields["clave"][0])
                    invitation.manager.register(invitation.alias, node)
                    invitation.used = True
                self.reply(200, f"Incorporado: {invitation.alias} ({node['ip']}).\n")
                print(f"Incorporado y acceso SSH verificado: {invitation.alias} ({node['ip']}).", flush=True)
            except (ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
                self.reply(400, f"No se pudo incorporar: {exc}\n")
    return Handler


def serve(manager, args):
    nodes = manager.load()["nodos"]
    target = next(iter(nodes.values()))["ip"] if nodes else "192.0.2.1"
    ip = local_ipv4(args.ip_central if args.ip_central else route_ip(target))
    invitation = Invitation(manager, args.nombre, f"http://{ip}:{args.puerto}", args.segundos)
    with http.server.ThreadingHTTPServer((ip, args.puerto), handler_for(invitation)) as server:
        server.timeout = 1
        print(f"En el nuevo dispositivo, abre Termux fuera de Debian y pega este comando:\n\n"
              f"{invitation.command()}\n\n"
              f"Invitacion para {args.nombre}: valida {args.segundos // 60} minutos, un solo uso.\n"
              "Mantén este comando abierto hasta que se incorpore el dispositivo.", flush=True)
        while not invitation.used and time.monotonic() < invitation.expires:
            server.handle_request()
    if not invitation.used:
        raise ValueError("La invitacion vencio; genera otra con invitar.")


def proxy(manager, alias):
    ip, port = manager.resolve(alias)
    with socket.create_connection((ip, port), timeout=5) as remote:
        # Igual que el transporte TCP de SSH: no retrasar paquetes pequenos.
        remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        remote.settimeout(None)
        inputs = [0, remote]
        while remote in inputs:
            ready, _, _ = select.select(inputs, [], [])
            if 0 in ready:
                chunk = os.read(0, 65536)
                if chunk:
                    remote.sendall(chunk)
                else:
                    inputs.remove(0)
                    remote.shutdown(socket.SHUT_WR)
            if remote in ready:
                chunk = remote.recv(65536)
                if not chunk:
                    return
                view = memoryview(chunk)
                while view:
                    view = view[os.write(1, view):]


def main(argv=None):
    parser = argparse.ArgumentParser(description="Incorporar dispositivos Termux y acceder por nombre.")
    commands = parser.add_subparsers(dest="accion", required=True)
    invite = commands.add_parser("invitar", help="Generar un comando de incorporacion de un solo uso")
    invite.add_argument("nombre")
    invite.add_argument("--ip-central")
    invite.add_argument("--puerto", type=int, default=8765)
    invite.add_argument("--segundos", type=int, default=1800)
    commands.add_parser("listar", help="Mostrar nombres e IPs guardadas")
    for action in ("buscar", "proxy"):
        commands.add_parser(action, help="Encontrar por su clave SSH").add_argument("nombre")
    register = commands.add_parser("registrar", help="Incorporar un dispositivo ya preparado")
    register.add_argument("nombre")
    register.add_argument("ip")
    register.add_argument("usuario")
    register.add_argument("clave")
    network = commands.add_parser("red", help="Definir redes de busqueda; sin argumentos, usar /24 local")
    network.add_argument("cidr", nargs="*")
    args = parser.parse_args(argv)
    manager = Manager()
    if args.accion == "invitar":
        if not 1 <= args.segundos <= 86400 or not 1024 <= args.puerto <= 65535:
            raise ValueError("Duracion o puerto fuera del intervalo permitido.")
        serve(manager, args)
    elif args.accion == "listar":
        for alias, node in sorted(manager.load()["nodos"].items()):
            print(f"{alias:20} {node['ip']:15} {node['usuario']}  {fingerprint(node['clave'])}")
    elif args.accion == "registrar":
        manager.prepare_identity()
        manager.register(args.nombre, validate_node(args.nombre, args.ip, args.usuario, args.clave))
        print(f"Registrado y verificado: {args.nombre}")
    elif args.accion == "buscar":
        print(manager.resolve(args.nombre, force=True)[0])
    elif args.accion == "proxy":
        proxy(manager, args.nombre)
    elif args.accion == "red":
        networks = [str(ipaddress.ip_network(value, strict=False)) for value in args.cidr]
        manager.networks({"redes": networks}, {"ip": "192.0.2.1"})
        with manager.locked():
            data = manager.load()
            data["redes"] = networks
            manager.save(data)
        print("Redes de busqueda: " + (", ".join(networks) or "/24 de la IP local actual"))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print(f"union-lan: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInvitacion cancelada.", file=sys.stderr)
        sys.exit(130)
