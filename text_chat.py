#!/usr/bin/env python3
"""
chat_mesh_hub.py

- Default mode: P2P mesh (B). Each instance listens for incoming peer connections
  and can auto-discover peers via UDP broadcast, then connects to them.
  Messages/files are broadcast to all connected peers. Message IDs prevent loops.

- Hub mode (A): when "Start Hub" is pressed, this instance becomes a central server
  that accepts many clients and forwards every client's messages to all other clients.

GUI allows configuring TCP port and Discovery (UDP) port, password, sounds, and
has buttons for "Start Listen (Peer)", "Connect Auto (Peer)", "Start Hub", "Stop Hub".
"""

import sys, socket, threading, struct, json, os, time, uuid
from pathlib import Path
from PyQt5 import QtWidgets, QtCore, QtMultimedia
from PyQt5.QtWidgets import QFileDialog, QMessageBox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64

# ----------------- Helpers: encryption & framing -----------------

def derive_key_from_password(password: str, salt: bytes = b"fixed_salt_for_demo_change") -> bytes:
    if not password:
        return None
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def pack_payload(header: dict, body: bytes, fernet: Fernet = None) -> bytes:
    header_json = json.dumps(header).encode("utf-8")
    plain = header_json + b"|" + body
    if fernet:
        payload = fernet.encrypt(plain)
    else:
        payload = plain
    return struct.pack(">I", len(payload)) + payload

def unpack_payload(payload: bytes, fernet: Fernet = None):
    if fernet:
        plain = fernet.decrypt(payload)
    else:
        plain = payload
    header_json, body = plain.split(b"|", 1)
    header = json.loads(header_json.decode("utf-8"))
    return header, body

def recvall(sock, n):
    data = b""
    while len(data) < n:
        try:
            packet = sock.recv(n - len(data))
        except:
            return None
        if not packet:
            return None
        data += packet
    return data

# ----------------- Message / Node identity -----------------

NODE_ID = str(uuid.uuid4())  # unique id for this node
# keep record of seen message ids to prevent rebroadcast loops
SEEN_MSGS = set()
SEEN_MSGS_LOCK = threading.Lock()

def mark_seen(msgid: str):
    with SEEN_MSGS_LOCK:
        SEEN_MSGS.add(msgid)
def seen_before(msgid: str) -> bool:
    with SEEN_MSGS_LOCK:
        return msgid in SEEN_MSGS

# ----------------- Main GUI / Networking -----------------

class ChatWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MeshChat — P2P Mesh + Hub (A)")
        self.setMinimumSize(900, 560)

        # GUI state / network state
        self.tcp_port = 5050
        self.discovery_port = 5051
        self.listen_socket = None         # listening socket for P2P incoming connections
        self.listen_thread = None
        self.hub_mode = False
        self.hub_socket = None            # hub server socket (accepts many clients)
        self.hub_clients = []             # list of client sockets in hub mode
        self.hub_lock = threading.Lock()

        self.peers = {}                   # mapping ip:socket for outgoing/incoming peer connections
        self.peers_lock = threading.Lock()

        self.client_receive_threads = []  # helper list for cleaning
        self.fernet = None

        # sounds (try to load wavs, fallback to Qt beep)
        self.sound_received = QtMultimedia.QSoundEffect()
        self.sound_sent = QtMultimedia.QSoundEffect()
        # try load local WAVs; if not found, will use fallback beep method
        recv_wav = Path("receive.wav")
        send_wav = Path("send.wav")
        if recv_wav.exists():
            self.sound_received.setSource(QtCore.QUrl.fromLocalFile(str(recv_wav)))
        if send_wav.exists():
            self.sound_sent.setSource(QtCore.QUrl.fromLocalFile(str(send_wav)))

        self.build_ui()

        # Start discovery listener thread only when needed (started with Listen or Hub)
        self.discovery_thread = None
        self.discovery_socket = None

    # ---------- UI ----------
    def build_ui(self):
        layout = QtWidgets.QVBoxLayout(self)

        # Top controls: ports, password, listen, connect auto, hub
        top = QtWidgets.QHBoxLayout()
        self.tcp_port_input = QtWidgets.QLineEdit("5050")
        self.discovery_port_input = QtWidgets.QLineEdit("5051")
        self.password_input = QtWidgets.QLineEdit()
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password_input.setPlaceholderText("Password (optional)")

        listen_btn = QtWidgets.QPushButton("Start Listen (Peer)")
        listen_btn.clicked.connect(self.start_listen_peer)
        stop_listen_btn = QtWidgets.QPushButton("Stop Listen")
        stop_listen_btn.clicked.connect(self.stop_listen_peer)

        connect_auto_btn = QtWidgets.QPushButton("Connect (Auto)")
        connect_auto_btn.clicked.connect(self.auto_connect)

        start_hub_btn = QtWidgets.QPushButton("Start Hub (A)")
        start_hub_btn.clicked.connect(self.start_hub)
        stop_hub_btn = QtWidgets.QPushButton("Stop Hub")
        stop_hub_btn.clicked.connect(self.stop_hub)

        top.addWidget(QtWidgets.QLabel("TCP Port:")); top.addWidget(self.tcp_port_input)
        top.addWidget(QtWidgets.QLabel("Discovery Port:")); top.addWidget(self.discovery_port_input)
        top.addWidget(QtWidgets.QLabel("Password:")); top.addWidget(self.password_input)
        top.addWidget(listen_btn); top.addWidget(stop_listen_btn)
        top.addWidget(connect_auto_btn)
        top.addWidget(start_hub_btn); top.addWidget(stop_hub_btn)
        layout.addLayout(top)

        # Middle: chat display and peers list
        mid = QtWidgets.QHBoxLayout()
        self.chat_display = QtWidgets.QTextEdit()
        self.chat_display.setReadOnly(True)
        mid.addWidget(self.chat_display, 3)

        right = QtWidgets.QVBoxLayout()
        self.peers_list = QtWidgets.QListWidget()
        right.addWidget(QtWidgets.QLabel("Peers / Hub Clients:"))
        right.addWidget(self.peers_list)
        self.remove_peer_btn = QtWidgets.QPushButton("Disconnect Selected")
        self.remove_peer_btn.clicked.connect(self.disconnect_selected_peer)
        right.addWidget(self.remove_peer_btn)
        mid.addLayout(right, 1)
        layout.addLayout(mid)

        # Bottom: message entry, send, file
        bottom = QtWidgets.QHBoxLayout()
        self.msg_input = QtWidgets.QLineEdit()
        self.msg_input.returnPressed.connect(self.send_message)
        send_btn = QtWidgets.QPushButton("Send")
        send_btn.clicked.connect(self.send_message)
        file_btn = QtWidgets.QPushButton("Send File")
        file_btn.clicked.connect(self.send_file)
        bottom.addWidget(self.msg_input)
        bottom.addWidget(send_btn)
        bottom.addWidget(file_btn)
        layout.addLayout(bottom)

        # status/progress
        self.progress = QtWidgets.QProgressBar()
        layout.addWidget(self.progress)
        self.status_label = QtWidgets.QLabel("Status: idle")
        layout.addWidget(self.status_label)

    # ---------- Logging ----------
    def log(self, *parts):
        text = " ".join(str(p) for p in parts)
        self.chat_display.append(text)

    # ---------- Encryption ----------
    def apply_password(self):
        pwd = self.password_input.text().strip()
        if pwd == "":
            self.fernet = None
            self.log("[System] Encryption disabled.")
            return
        key = derive_key_from_password(pwd)
        self.fernet = Fernet(key)
        self.log("[System] Encryption enabled.")

    # ---------- Peer listening (P2P incoming) ----------
    def start_listen_peer(self):
        try:
            self.tcp_port = int(self.tcp_port_input.text())
            self.discovery_port = int(self.discovery_port_input.text())
        except:
            QMessageBox.warning(self, "Invalid port", "Ports must be integers.")
            return
        if self.listen_socket:
            self.log("[System] Already listening for peer connections.")
            return
        self.apply_password()
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.listen_socket.bind(("", self.tcp_port))
            self.listen_socket.listen(5)
        except Exception as e:
            QMessageBox.critical(self, "Listen error", f"Could not listen on {self.tcp_port}: {e}")
            self.listen_socket = None
            return
        self.listen_thread = threading.Thread(target=self._accept_peers_loop, daemon=True)
        self.listen_thread.start()
        # start discovery responder
        self._start_discovery_listener()
        self.status_label.setText(f"Status: Listening for peers on TCP {self.tcp_port}, discovery {self.discovery_port}")
        self.log(f"[System] Listening for peer connections (P2P) on TCP {self.tcp_port}")

    def _accept_peers_loop(self):
        while self.listen_socket:
            try:
                conn, addr = self.listen_socket.accept()
            except:
                break
            self.log(f"[System] Incoming peer connection from {addr}")
            # add to peers and start receive thread
            with self.peers_lock:
                key = f"{addr[0]}:{addr[1]}"
                self.peers[key] = conn
            self._refresh_peers_list()
            t = threading.Thread(target=self._peer_receive_loop, args=(conn, addr), daemon=True)
            t.start()
            self.client_receive_threads.append(t)

    def stop_listen_peer(self):
        # close listen socket (stop accepting new peers)
        if self.listen_socket:
            try:
                self.listen_socket.close()
            except: pass
            self.listen_socket = None
            self.log("[System] Stopped listening for peer connections.")
        # stop discovery listener
        self._stop_discovery_listener()
        self.status_label.setText("Status: idle")

    # ---------- Discovery (UDP) ----------
    def _start_discovery_listener(self):
        if self.discovery_thread and self.discovery_socket:
            return
        try:
            self.discovery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.discovery_socket.bind(("", self.discovery_port))
        except Exception as e:
            self.log("[System] Discovery listener failed:", e)
            self.discovery_socket = None
            self.discovery_thread = None
            return
        self.discovery_thread = threading.Thread(target=self._discovery_loop, daemon=True)
        self.discovery_thread.start()

    def _discovery_loop(self):
        sock = self.discovery_socket
        while sock:
            try:
                data, addr = sock.recvfrom(2048)
                if data == b"DISCOVER_MESHCHAT":
                    # reply with simple payload; client will attempt TCP connect to addr[0]
                    sock.sendto(b"MESHCHAT_HERE", addr)
            except:
                break

    def _stop_discovery_listener(self):
        if self.discovery_socket:
            try: self.discovery_socket.close()
            except: pass
            self.discovery_socket = None
            self.discovery_thread = None

    # ---------- Auto-connect (broadcast discovery + connect) ----------
    def auto_connect(self):
        try:
            self.tcp_port = int(self.tcp_port_input.text())
            self.discovery_port = int(self.discovery_port_input.text())
        except:
            QMessageBox.warning(self, "Invalid port", "Ports must be integers.")
            return
        self.apply_password()
        self.log("[System] Broadcasting discovery to LAN...")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.settimeout(3.0)
        try:
            s.sendto(b"DISCOVER_MESHCHAT", ('<broadcast>', self.discovery_port))
            data, addr = s.recvfrom(2048)
            if data == b"MESHCHAT_HERE":
                server_ip = addr[0]
                self.log(f"[System] Found peer at {server_ip} — attempting connect")
                self._connect_with_retry(server_ip)
            else:
                self.log("[System] Received unexpected discovery reply:", data)
        except Exception as e:
            self.log("[System] No peer found via discovery:", e)
        finally:
            try: s.close()
            except: pass

    def _connect_with_retry(self, ip, attempts=6, delay=0.5):
        for i in range(attempts):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3.0)
                s.connect((ip, self.tcp_port))
                s.settimeout(None)
                # store peer
                with self.peers_lock:
                    key = f"{ip}:{s.getpeername()[1]}"
                    self.peers[key] = s
                self._refresh_peers_list()
                self.log(f"[System] Connected to peer {ip}")
                t = threading.Thread(target=self._peer_receive_loop, args=(s, (ip, s.getpeername()[1])), daemon=True)
                t.start()
                self.client_receive_threads.append(t)
                return True
            except Exception as e:
                self.log(f"[System] Connect attempt {i+1} to {ip} failed: {e}")
                time.sleep(delay)
        self.log("[System] Could not connect to", ip)
        return False

    # ---------- Peer receive loop (handles incoming messages from a peer socket) ----------
    def _peer_receive_loop(self, sock, addr):
        try:
            while True:
                raw_len = recvall(sock, 4)
                if not raw_len:
                    break
                n = struct.unpack(">I", raw_len)[0]
                payload = recvall(sock, n)
                if payload is None:
                    break
                try:
                    header, body = unpack_payload(payload, self.fernet)
                except Exception as e:
                    self.log("[System] Failed to parse/decrypt payload:", e)
                    continue
                # expected header fields: type, msgid, origin
                mtype = header.get("type")
                msgid = header.get("msgid")
                origin = header.get("origin")
                # if message id seen before, skip (prevents loops)
                if msgid:
                    if seen_before(msgid):
                        continue
                    mark_seen(msgid)
                # handle types
                if mtype == "msg":
                    text = body.decode("utf-8", errors="replace")
                    self._on_incoming_message(origin or str(addr), text, msgid)
                    # rebroadcast to other peers (mesh behavior)
                    self._mesh_forward(payload, exclude_sock=sock)
                elif mtype == "file":
                    fname = header.get("name", "file")
                    saved = self._save_incoming_file(fname, body)
                    self._play_recv_sound()
                    self.log(f"[File] Received from {origin or addr[0]}: {fname} -> {saved}")
                    # forward to other peers
                    self._mesh_forward(payload, exclude_sock=sock)
                elif mtype == "shutdown":
                    self.log(f"[System] Peer {origin or addr} requested shutdown")
                    try: sock.close()
                    except: pass
                    break
        except Exception as e:
            self.log("[System] Peer receive ended:", e)
        finally:
            # cleanup peer socket from mapping
            self._remove_sock(sock)
            self._refresh_peers_list()

    # ---------- Mesh forwarding: forward a payload to all peers except the origin socket ----------
    def _mesh_forward(self, payload_bytes: bytes, exclude_sock=None):
        with self.peers_lock:
            socks = list(self.peers.items())
        for key, psock in socks:
            if psock is exclude_sock:
                continue
            try:
                psock.sendall(payload_bytes)
            except:
                # remove broken socket
                self._remove_sock(psock)
        self._refresh_peers_list()

    # ---------- Hub mode (A): Start a central hub server that accepts many clients ----------
    def start_hub(self):
        try:
            self.tcp_port = int(self.tcp_port_input.text())
            self.discovery_port = int(self.discovery_port_input.text())
        except:
            QMessageBox.warning(self, "Invalid port", "Ports must be integers.")
            return
        if self.hub_mode:
            self.log("[System] Hub already running.")
            return
        self.apply_password()
        # start hub TCP server
        self.hub_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.hub_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.hub_socket.bind(("", self.tcp_port))
            self.hub_socket.listen(50)
        except Exception as e:
            QMessageBox.critical(self, "Hub error", f"Could not start hub on {self.tcp_port}: {e}")
            self.hub_socket = None
            return
        self.hub_mode = True
        self.hub_accept_thread = threading.Thread(target=self._hub_accept_loop, daemon=True)
        self.hub_accept_thread.start()
        # discovery responder for hub
        self._start_discovery_listener()
        self.status_label.setText(f"Status: Hub running on {self.tcp_port}, discovery {self.discovery_port}")
        self.log(f"[System] Hub started on TCP {self.tcp_port}")

    def _hub_accept_loop(self):
        while self.hub_mode and self.hub_socket:
            try:
                client, addr = self.hub_socket.accept()
            except:
                break
            with self.hub_lock:
                self.hub_clients.append((client, addr))
            self.log(f"[Hub] Client connected: {addr}")
            threading.Thread(target=self._hub_client_receive_loop, args=(client, addr), daemon=True).start()
            self._refresh_peers_list()

    def _hub_client_receive_loop(self, client_sock, addr):
        try:
            while True:
                raw_len = recvall(client_sock, 4)
                if not raw_len:
                    break
                n = struct.unpack(">I", raw_len)[0]
                payload = recvall(client_sock, n)
                if payload is None:
                    break
                # server hub will decrypt/encrypt with same fernet
                try:
                    header, body = unpack_payload(payload, self.fernet)
                except Exception as e:
                    self.log("[Hub] Failed to parse payload from", addr, e)
                    continue
                # when hub receives a payload, it should forward it to all other hub clients
                self._hub_broadcast(payload, exclude_sock=client_sock)
                # also show in local chat window
                mtype = header.get("type")
                if mtype == "msg":
                    origin = header.get("origin") or f"{addr[0]}:{addr[1]}"
                    text = body.decode("utf-8", errors="replace")
                    self.log(f"[Hub][{origin}] {text}")
                elif mtype == "file":
                    self.log(f"[Hub] Received file transfer from {addr} (forwarded).")
        except Exception as e:
            self.log("[Hub] Client loop ended:", e)
        finally:
            # remove client
            with self.hub_lock:
                self.hub_clients = [(s,a) for (s,a) in self.hub_clients if s is not client_sock]
            try: client_sock.close()
            except: pass
            self._refresh_peers_list()

    def _hub_broadcast(self, payload_bytes: bytes, exclude_sock=None):
        with self.hub_lock:
            clients = list(self.hub_clients)
        for (csock, addr) in clients:
            if csock is exclude_sock:
                continue
            try:
                csock.sendall(payload_bytes)
            except:
                with self.hub_lock:
                    self.hub_clients = [(s,a) for (s,a) in self.hub_clients if s is not csock]
        self._refresh_peers_list()

    def stop_hub(self):
        if not self.hub_mode:
            self.log("[System] Hub not running.")
            return
        # notify clients
        with self.hub_lock:
            for (csock, addr) in list(self.hub_clients):
                try:
                    header = {"type":"shutdown", "origin":NODE_ID}
                    payload = pack_payload(header, b"hub_shutdown", self.fernet)
                    csock.sendall(payload)
                except: pass
                try: csock.close()
                except: pass
            self.hub_clients = []
        try:
            self.hub_socket.close()
        except: pass
        self.hub_socket = None
        self.hub_mode = False
        self._stop_discovery_listener()
        self.log("[System] Hub stopped.")
        self._refresh_peers_list()
        self.status_label.setText("Status: idle")

    # ---------- Peer list UI ----------
    def _refresh_peers_list(self):
        # show both hub clients (if hub) and peers
        self.peers_list.clear()
        with self.peers_lock:
            for key in list(self.peers.keys()):
                self.peers_list.addItem(f"Peer: {key}")
        with self.hub_lock:
            for (s,addr) in self.hub_clients:
                self.peers_list.addItem(f"HubClient: {addr[0]}:{addr[1]}")

    def disconnect_selected_peer(self):
        items = self.peers_list.selectedItems()
        if not items:
            return
        for it in items:
            text = it.text()
            if text.startswith("Peer: "):
                key = text.split("Peer: ",1)[1]
                with self.peers_lock:
                    sock = self.peers.get(key)
                if sock:
                    try:
                        header = {"type":"shutdown", "origin":NODE_ID}
                        sock.sendall(pack_payload(header, b"bye", self.fernet))
                    except: pass
                    try: sock.close()
                    except: pass
                    self._remove_sock(sock)
            elif text.startswith("HubClient: "):
                addrstr = text.split("HubClient: ",1)[1]
                # disconnect hub client only if we're hub
                with self.hub_lock:
                    for (s,a) in list(self.hub_clients):
                        if f"{a[0]}:{a[1]}" == addrstr:
                            try: s.close()
                            except: pass
                            self.hub_clients.remove((s,a))
        self._refresh_peers_list()

    def _remove_sock(self, sock):
        with self.peers_lock:
            for k,v in list(self.peers.items()):
                if v is sock:
                    try: v.close()
                    except: pass
                    del self.peers[k]

    # ---------- Sending messages & files ----------
    def send_message(self):
        text = self.msg_input.text().strip()
        if not text:
            return
        msgid = str(uuid.uuid4())
        mark_seen(msgid)
        header = {"type":"msg", "msgid": msgid, "origin": NODE_ID}
        payload = pack_payload(header, text.encode("utf-8"), self.fernet)
        # If hub_mode: send to hub (if connected)
        if self.hub_mode:
            # hub local sending: hub broadcasts to clients; also display locally
            self.log(f"[You->Hub] {text}")
            self._play_sent_sound()
            # Hub won't be a peer in peers map; hub clients send via client socket; not implemented here
            # If running as hub and you want to send as hub -> broadcast to clients
            self._hub_broadcast(payload, exclude_sock=None)
            return
        # otherwise mesh: send to all connected peers
        with self.peers_lock:
            socks = list(self.peers.values())
        if not socks:
            self.log("[System] No peers connected to send message.")
            return
        for psock in socks:
            try:
                psock.sendall(payload)
            except:
                self._remove_sock(psock)
        self.log(f"You: {text}")
        self._play_sent_sound()
        self.msg_input.clear()
        self._refresh_peers_list()

    def send_file(self):
        fname, _ = QFileDialog.getOpenFileName(self, "Select File to Send")
        if not fname:
            return
        try:
            with open(fname, "rb") as f:
                data = f.read()
        except Exception as e:
            QMessageBox.critical(self, "File error", f"Could not read file: {e}")
            return
        msgid = str(uuid.uuid4()); mark_seen(msgid)
        header = {"type":"file", "msgid": msgid, "origin": NODE_ID, "name": os.path.basename(fname), "size": len(data)}
        payload = pack_payload(header, data, self.fernet)
        if self.hub_mode:
            # broadcast to hub clients
            self._hub_broadcast(payload)
            self.log(f"[Hub] Sent file {fname} to clients.")
            self._play_sent_sound()
            return
        # mesh: send to all peers
        with self.peers_lock:
            socks = list(self.peers.values())
        if not socks:
            self.log("[System] No peers connected to send file.")
            return
        for psock in socks:
            try:
                psock.sendall(payload)
            except:
                self._remove_sock(psock)
        self.log(f"[File] Sent {fname} to peers.")
        self._play_sent_sound()
        self.progress.setValue(100)
        self._refresh_peers_list()

    def _on_incoming_message(self, origin, text, msgid):
        self._play_recv_sound()
        self.log(f"{origin}: {text}")

    def _save_incoming_file(self, name, data: bytes):
        downloads = Path("downloads")
        downloads.mkdir(exist_ok=True)
        target = downloads / name
        base, ext = os.path.splitext(name)
        i = 1
        while target.exists():
            target = downloads / f"{base}({i}){ext}"
            i += 1
        try:
            with open(target, "wb") as f:
                f.write(data)
            return str(target)
        except Exception as e:
            return f"Error saving file: {e}"

    # ---------- Play sounds with fallback ----------
    def _play_recv_sound(self):
        try:
            if str(self.sound_received.source()) != "":
                self.sound_received.play()
            else:
                QtWidgets.QApplication.beep()
        except:
            try: QtWidgets.QApplication.beep()
            except: pass

    def _play_sent_sound(self):
        try:
            if str(self.sound_sent.source()) != "":
                self.sound_sent.play()
            else:
                QtWidgets.QApplication.beep()
        except:
            try: QtWidgets.QApplication.beep()
            except: pass

    # ---------- Cleanup and close ----------
    def closeEvent(self, event):
        # notify peers/hub clients
        header = {"type":"shutdown", "origin":NODE_ID}
        payload = pack_payload(header, b"bye", self.fernet)
        # send to peers
        with self.peers_lock:
            for psock in list(self.peers.values()):
                try: psock.sendall(payload)
                except: pass
                try: psock.close()
                except: pass
        # send to hub clients if hub
        with self.hub_lock:
            for (csock, addr) in list(self.hub_clients):
                try: csock.sendall(payload)
                except: pass
                try: csock.close()
                except: pass
        # close listening sockets
        try:
            if self.listen_socket: self.listen_socket.close()
        except: pass
        try:
            if self.hub_socket: self.hub_socket.close()
        except: pass
        try:
            if self.discovery_socket: self.discovery_socket.close()
        except: pass
        event.accept()

# --------------- Run app ---------------
def main():
    app = QtWidgets.QApplication(sys.argv)
    w = ChatWindow()
    w.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
