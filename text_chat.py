import sys
import socket
import threading
import struct
import json
import os
from pathlib import Path
from PyQt5 import QtWidgets, QtCore, QtMultimedia
from PyQt5.QtWidgets import QFileDialog, QMessageBox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64
import time

# ==================== Encryption Helpers ====================
def derive_key_from_password(password: str, salt: bytes = b"fixed_salt_for_demo") -> bytes:
    if not password:
        return None
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

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
    header_json, body = plain.split(b"|",1)
    header = json.loads(header_json.decode())
    return header, body

def recvall(sock, n):
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

# ==================== Chat Window ====================
class ChatWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure PyText — Auto LAN Discovery + Configurable Ports")
        self.setMinimumSize(800, 500)

        # Networking
        self.server_socket = None
        self.conn = None
        self.conn_addr = None
        self.client_socket = None
        self.fernet = None
        self.discovery_thread = None
        self.receive_thread = None
        self.TCP_PORT = 5050
        self.DISCOVERY_PORT = 5051

        # Sounds
        self.sound_received = QtMultimedia.QSoundEffect()
        self.sound_received.setSource(QtCore.QUrl.fromLocalFile("receive.wav"))
        self.sound_sent = QtMultimedia.QSoundEffect()
        self.sound_sent.setSource(QtCore.QUrl.fromLocalFile("send.wav"))

        self.build_ui()

    # ==================== UI ====================
    def build_ui(self):
        layout = QtWidgets.QVBoxLayout(self)

        top_row = QtWidgets.QHBoxLayout()
        self.tcp_port_input = QtWidgets.QLineEdit("5050")
        self.udp_port_input = QtWidgets.QLineEdit("5051")
        self.password_input = QtWidgets.QLineEdit()
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password_input.setPlaceholderText("Password (optional)")

        start_btn = QtWidgets.QPushButton("Start Server")
        start_btn.clicked.connect(self.start_server)

        stop_btn = QtWidgets.QPushButton("Stop Server")
        stop_btn.clicked.connect(self.stop_server)

        connect_btn = QtWidgets.QPushButton("Connect (Auto)")
        connect_btn.clicked.connect(self.auto_connect)

        top_row.addWidget(QtWidgets.QLabel("TCP Port:"))
        top_row.addWidget(self.tcp_port_input)
        top_row.addWidget(QtWidgets.QLabel("Discovery Port:"))
        top_row.addWidget(self.udp_port_input)
        top_row.addWidget(QtWidgets.QLabel("Password:"))
        top_row.addWidget(self.password_input)
        top_row.addWidget(start_btn)
        top_row.addWidget(stop_btn)
        top_row.addWidget(connect_btn)
        layout.addLayout(top_row)

        self.chat_display = QtWidgets.QTextEdit()
        self.chat_display.setReadOnly(True)
        layout.addWidget(self.chat_display)

        bottom_row = QtWidgets.QHBoxLayout()
        self.msg_input = QtWidgets.QLineEdit()
        self.msg_input.returnPressed.connect(self.send_text)
        send_btn = QtWidgets.QPushButton("Send")
        send_btn.clicked.connect(self.send_text)
        file_btn = QtWidgets.QPushButton("Send File")
        file_btn.clicked.connect(self.send_file)
        bottom_row.addWidget(self.msg_input)
        bottom_row.addWidget(send_btn)
        bottom_row.addWidget(file_btn)
        layout.addLayout(bottom_row)

        self.progress = QtWidgets.QProgressBar()
        layout.addWidget(self.progress)

        self.status = QtWidgets.QLabel("Status: idle")
        layout.addWidget(self.status)

    def log(self, *parts):
        self.chat_display.append(" ".join(str(p) for p in parts))

    # ==================== Password / Encryption ====================
    def apply_password(self):
        pwd = self.password_input.text().strip()
        if pwd == "":
            self.fernet = None
            self.log("[System] Encryption disabled.")
            return
        key = derive_key_from_password(pwd)
        self.fernet = Fernet(key)
        self.log("[System] Encryption enabled.")

    # ==================== Server ====================
    def start_server(self):
        try:
            self.TCP_PORT = int(self.tcp_port_input.text())
            self.DISCOVERY_PORT = int(self.udp_port_input.text())
        except:
            QMessageBox.warning(self, "Invalid port", "Ports must be integers.")
            return

        self.apply_password()
        if self.server_socket:
            self.log("[System] Server already running.")
            return
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(("", self.TCP_PORT))
        self.server_socket.listen(1)
        self.log(f"[System] Server started on TCP port {self.TCP_PORT}")
        self.status.setText(f"Status: Listening on {self.TCP_PORT}")

        threading.Thread(target=self._accept_loop, daemon=True).start()
        self.discovery_thread = threading.Thread(target=self._discovery_listener, daemon=True)
        self.discovery_thread.start()

    def _accept_loop(self):
        try:
            conn, addr = self.server_socket.accept()
            self.conn = conn
            self.conn_addr = addr
            self.status.setText(f"Connected: {addr}")
            self.log(f"[System] Peer connected: {addr}")
            self.receive_thread = threading.Thread(target=self._receive_loop, args=(conn,), daemon=True)
            self.receive_thread.start()
        except:
            self.log("[System] Server accept stopped.")

    # ==================== Stop Server ====================
    def stop_server(self):
        if not self.server_socket:
            self.log("[System] Server not running.")
            return
        try:
            if self.conn:
                payload = pack_payload({"type":"shutdown"}, b"server_stopped", self.fernet)
                self.conn.sendall(payload)
        except:
            pass
        try:
            self.server_socket.close()
        except:
            pass
        self.server_socket = None
        try:
            if self.conn:
                self.conn.close()
        except:
            pass
        self.conn = None
        self.status.setText("Status: Server stopped")
        self.log("[System] Server manually stopped.")

    # ==================== Auto Connect via Broadcast ====================
    def auto_connect(self):
        try:
            self.TCP_PORT = int(self.tcp_port_input.text())
            self.DISCOVERY_PORT = int(self.udp_port_input.text())
        except:
            QMessageBox.warning(self, "Invalid port", "Ports must be integers.")
            return

        self.apply_password()
        self.log("[System] Searching for server on LAN...")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.settimeout(3)
        try:
            message = b"DISCOVER_CHAT_SERVER"
            s.sendto(message, ('<broadcast>', self.DISCOVERY_PORT))
            data, addr = s.recvfrom(1024)
            if data == b"CHAT_SERVER_HERE":
                self.log(f"[System] Server found at {addr[0]}")
                self.connect_to_peer(addr[0])
        except Exception as e:
            self.log("[System] No server found:", e)
        finally:
            s.close()

    # ==================== Discovery Listener ====================
    def _discovery_listener(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("", self.DISCOVERY_PORT))
        except:
            self.log("[System] Discovery port already in use.")
            return
        while self.server_socket:
            try:
                data, addr = s.recvfrom(1024)
                if data == b"DISCOVER_CHAT_SERVER":
                    s.sendto(b"CHAT_SERVER_HERE", addr)
            except:
                break

    # ==================== TCP Connect ====================
    def connect_to_peer(self, ip):
        for attempt in range(5):
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                self.client_socket.connect((ip, self.TCP_PORT))
                self.status.setText(f"Connected to {ip}")
                self.log(f"[System] Connected to {ip}")
                threading.Thread(target=self._receive_loop, args=(self.client_socket,), daemon=True).start()
                return
            except Exception as e:
                self.log(f"[System] Connection attempt {attempt+1} failed: {e}")
                time.sleep(0.5)
        self.log("[System] Could not connect after multiple attempts.")
        self.client_socket = None

    # ==================== Receive Loop ====================
    def _receive_loop(self, sock):
        try:
            while True:
                raw_len = recvall(sock, 4)
                if not raw_len:
                    self.log("[System] Peer disconnected")
                    self.status.setText("Status: Disconnected")
                    break
                n = struct.unpack(">I", raw_len)[0]
                payload = recvall(sock, n)
                if payload is None:
                    break
                header, body = unpack_payload(payload, self.fernet)
                t = header.get("type")
                if t=="msg":
                    self.sound_received.play()
                    self.log(f"Friend: {body.decode()}")
                elif t=="file":
                    saved = self.save_incoming_file(header.get("name","file"), body)
                    self.log(f"[File] Received {header.get('name')} -> {saved}")
                    self.sound_received.play()
                elif t=="shutdown":
                    self.log("[System] Peer has stopped their server")
                    self.status.setText("Status: Peer shutdown")
                    try: sock.close() 
                    except: pass
                    break
        except:
            pass

    # ==================== Send Functions ====================
    def send_text(self):
        text = self.msg_input.text().strip()
        if not text or not (self.client_socket or self.conn):
            return
        payload = pack_payload({"type":"msg"}, text.encode(), self.fernet)
        if self._send_raw(payload):
            self.sound_sent.play()
            self.log("You:", text)
            self.msg_input.clear()

    def send_file(self):
        fname,_ = QFileDialog.getOpenFileName(self, "Select File")
        if not fname: return
        with open(fname,"rb") as f:
            data=f.read()
        header={"type":"file","name":os.path.basename(fname),"size":len(data)}
        payload = pack_payload(header, data, self.fernet)
        if self._send_raw(payload):
            self.sound_sent.play()
            self.log(f"[File] Sent {os.path.basename(fname)}")
            self.progress.setValue(100)

    def _send_raw(self, payload):
        sock = self.client_socket or self.conn
        if not sock: return False
        try:
            sock.sendall(payload)
            return True
        except: return False

    # ==================== File Save ====================
    def save_incoming_file(self, name, data):
        downloads = Path("downloads")
        downloads.mkdir(exist_ok=True)
        target = downloads / name
        base,ext=os.path.splitext(name);i=1
        while target.exists(): target=downloads/f"{base}({i}){ext}"; i+=1
        with open(target,"wb") as f:f.write(data)
        return str(target)

    # ==================== Close ====================
    def closeEvent(self,event):
        try:
            sock = self.client_socket or self.conn
            if sock:
                payload = pack_payload({"type":"shutdown"}, b"window_closed", self.fernet)
                sock.sendall(payload)
        except: pass
        for s in [self.server_socket,self.conn,self.client_socket]:
            try: s.close()
            except: pass
        event.accept()


# ==================== Run App ====================
def main():
    app = QtWidgets.QApplication(sys.argv)
    w = ChatWindow()
    w.show()
    sys.exit(app.exec_())

if __name__=="__main__":
    main()
