import sys
import threading
import time
from collections import deque, Counter
from scapy.all import sniff, IP, TCP, UDP, conf
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QLabel, QPlainTextEdit)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QPoint, QObject
from PyQt5.QtGui import QPainter, QColor, QPen, QFont

MY_IP = "<ip>"  
MONITOR_PORT = 5000       
ATTACK_THRESHOLD = 50 

class PacketData:
    def __init__(self, src_ip, proto, size):
        self.src_ip = src_ip
        self.proto = proto
        self.size = size
        self.timestamp = time.time()
        self.pos = 0.0 

class SnifferSignals(QObject):
    new_packet = pyqtSignal(object)

class MonitorThread(threading.Thread):
    def __init__(self, signals):
        super().__init__()
        self.signals = signals
        self.daemon = True
        self.running = False

    def run(self):
        self.running = True
        try:
            sniff(filter=f"port {MONITOR_PORT}", prn=self.packet_callback, store=0, stop_filter=self.stop_check)
        except Exception as e:
            print(f"Sniffer Error: {e}")

    def packet_callback(self, pkt):
        if IP in pkt:
            self.signals.new_packet.emit(pkt)

    def stop_check(self, x):
        return not self.running

class NetworkVisualizer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("netattack dashboard")
        self.setGeometry(50, 50, 1200, 700)
        self.setStyleSheet("background-color: #0F111A; color: #E0E0E0;")
        
        self.packets = deque()
        self.stats = Counter()
        self.total_count = 0
        
        self.signals = SnifferSignals()
        self.signals.new_packet.connect(self.process_packet_ui)

        self.init_ui()
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_frame)
        self.timer.start(16)

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)

        self.canvas = VisualCanvas(self)
        main_layout.addWidget(self.canvas, 6)

        right_panel = QVBoxLayout()
        self.log_console = QPlainTextEdit()
        self.log_console.setReadOnly(True)
        self.log_console.setFont(QFont("Consolas", 10))
        self.log_console.setStyleSheet("background-color: #1A1C25; color: #00FF00; border: 1px solid #333;")
        
        self.stats_label = QLabel("Packets: 0")
        self.stats_label.setFont(QFont("Arial", 12, QFont.Bold))
        
        btn_start = QPushButton("ACTIVATE SCAN")
        btn_start.setStyleSheet("background-color: #1B5E20; color: white; padding: 15px; font-weight: bold;")
        btn_start.clicked.connect(self.start_monitoring)

        right_panel.addWidget(QLabel("LIVE ACCESS LOGS"))
        right_panel.addWidget(self.log_console)
        right_panel.addWidget(self.stats_label)
        right_panel.addWidget(btn_start)
        main_layout.addLayout(right_panel, 4)

    def process_packet_ui(self, pkt):
        src = pkt[IP].src
        proto = "TCP" if TCP in pkt else "UDP"
        size = len(pkt)
        
        self.packets.append(PacketData(src, proto, size))
        
        timestamp = time.strftime('%H:%M:%S')
        log_entry = f"[{timestamp}] {src} -> :{MONITOR_PORT} | {proto} | {size}B"
        
        if self.stats[src] > ATTACK_THRESHOLD:
            log_entry = "!!! ALERT !!! " + log_entry
            
        self.log_console.appendPlainText(log_entry)
        self.total_count += 1
        self.stats[src] += 1

    def update_frame(self):
        now = time.time()
        while self.packets and (self.packets[0].pos > 1.0 or (now - self.packets[0].timestamp) > 2):
            self.packets.popleft()
        for p in self.packets:
            p.pos += 0.03
        self.stats_label.setText(f"TOTAL PACKETS RECEIVED: {self.total_count}")
        self.canvas.update()

    def start_monitoring(self):
        self.log_console.appendPlainText("--- SYSTEM ACTIVE: LISTENING ON PORT 5000 ---")
        self.sniffer = MonitorThread(self.signals)
        self.sniffer.start()

class VisualCanvas(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillRect(self.rect(), QColor(15, 17, 26))
        center = self.rect().center()
        
        painter.setPen(QPen(QColor(0, 255, 255), 2))
        painter.setBrush(QColor(0, 255, 255, 30))
        painter.drawEllipse(center, 30, 30)
        painter.setPen(QColor(255, 255, 255))
        painter.drawText(center.x() - 30, center.y() + 50, "MY_SERVER")
        
        for p in self.parent.packets:
            angle = (hash(p.src_ip) % 360)
            dist = 380 * (1.0 - p.pos)
            import math
            x = center.x() + dist * math.cos(math.radians(angle))
            y = center.y() + dist * math.sin(math.radians(angle))
            
            color = QColor(255, 0, 0) if self.parent.stats[p.src_ip] > ATTACK_THRESHOLD else QColor(0, 255, 120)
            painter.setBrush(color)
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(QPoint(int(x), int(y)), 6, 6)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkVisualizer()
    window.show()
    sys.exit(app.exec_())
