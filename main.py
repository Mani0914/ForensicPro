import sys
import os
import sqlite3
import hashlib
import psutil
import datetime
import glob
import logging
import configparser
import subprocess
import platform
import time
import requests
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QTextEdit, QPushButton, QDialog,
    QTabWidget, QTableView, QMessageBox, QStatusBar, QAction,
    QMenu, QGraphicsDropShadowEffect, QFileDialog
)
from PyQt5.QtCore import Qt, QAbstractTableModel, QTimer
from PyQt5.QtGui import QFont, QColor
import matplotlib
matplotlib.use('QtAgg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
import bcrypt
import csv
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet

LOG_FILE = "forensictool.log"
DB_NAME = "forensic.db"
VIRUSTOTAL_API_KEY = "your virus total api key"  # Replace with your actual API key

logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

class DatabaseManager:
    def __init__(self, db_name=DB_NAME):
        self.db_name = db_name
        self.conn = None
        self.cursor = None

    def connect(self):
        try:
            db_dir = os.path.dirname(os.path.abspath(self.db_name)) or "."
            logging.debug(f"Attempting to connect to database at {self.db_name}")
            if not os.access(db_dir, os.W_OK):
                logging.error(f"No write permission for directory: {db_dir}")
                return False
            self.conn = sqlite3.connect(self.db_name)
            self.cursor = self.conn.cursor()
            logging.info(f"Successfully connected to database at {self.db_name}")
            return True
        except sqlite3.Error as e:
            logging.error(f"Database connection error: {e}")
            return False

    def disconnect(self):
        if self.conn:
            logging.debug(f"Disconnecting from database at {self.db_name}")
            self.conn.close()
            self.conn = None
            self.cursor = None

    def create_tables(self):
        if not self.conn:
            if not self.connect():
                return False
        logging.debug("Creating database tables")
        try:
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS Users (
                    UserID INTEGER PRIMARY KEY AUTOINCREMENT,
                    Username TEXT NOT NULL UNIQUE,
                    PasswordHash TEXT NOT NULL
                )
            """)
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS BrowserArtifacts (
                    ArtifactID INTEGER PRIMARY KEY AUTOINCREMENT,
                    BrowserType TEXT NOT NULL,
                    URL TEXT NOT NULL,
                    Title TEXT,
                    VisitTime TEXT,
                    Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS USBDevices (
                    USBID INTEGER PRIMARY KEY AUTOINCREMENT,
                    DeviceName TEXT NOT NULL,
                    DeviceID TEXT,
                    LastConnected TEXT,
                    Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS USBActivity (
                    ActivityID INTEGER PRIMARY KEY AUTOINCREMENT,
                    DeviceID TEXT NOT NULL,
                    EventType TEXT NOT NULL,
                    EventTime TEXT,
                    Details TEXT,
                    Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS LiveAnalysis (
                    AnalysisID INTEGER PRIMARY KEY AUTOINCREMENT,
                    Type TEXT NOT NULL,
                    Details TEXT NOT NULL,
                    Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS FileComparisons (
                    ComparisonID INTEGER PRIMARY KEY AUTOINCREMENT,
                    File1Path TEXT NOT NULL,
                    File2Path TEXT NOT NULL,
                    HashMatch BOOLEAN,
                    ByteMatch BOOLEAN,
                    Details TEXT,
                    Metadata1 TEXT,
                    Metadata2 TEXT,
                    Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS AutopsyAnalysis (
                    AutopsyID INTEGER PRIMARY KEY AUTOINCREMENT,
                    Type TEXT NOT NULL,
                    Category TEXT,
                    Details TEXT NOT NULL,
                    Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS MalwareAnalysis (
                    AnalysisID INTEGER PRIMARY KEY AUTOINCREMENT,
                    FilePath TEXT NOT NULL,
                    MD5Hash TEXT,
                    Result TEXT,
                    Entropy REAL,
                    Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS MalwareVendorResults (
                    ResultID INTEGER PRIMARY KEY AUTOINCREMENT,
                    AnalysisID INTEGER,
                    VendorName TEXT NOT NULL,
                    DetectionStatus TEXT NOT NULL,
                    FOREIGN KEY (AnalysisID) REFERENCES MalwareAnalysis(AnalysisID)
                )
            """)
            self.conn.commit()
            self.create_default_user()
            logging.info("Database tables created successfully")
            return True
        except sqlite3.Error as e:
            logging.error(f"Error creating tables: {e}")
            return False

    def create_default_user(self):
        default_username = "admin"
        default_password = "password123"
        hashed_password = bcrypt.hashpw(default_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        try:
            query = "SELECT Username FROM Users WHERE Username = ?"
            self.cursor.execute(query, (default_username,))
            if not self.cursor.fetchone():
                query = "INSERT INTO Users (Username, PasswordHash) VALUES (?, ?)"
                self.cursor.execute(query, (default_username, hashed_password))
                self.conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Error creating default user: {e}")

    def verify_user(self, username, password):
        if not self.conn:
            if not self.connect():
                return False
        try:
            query = "SELECT PasswordHash FROM Users WHERE Username = ?"
            self.cursor.execute(query, (username,))
            result = self.cursor.fetchone()
            if result:
                stored_hash = result[0].encode('utf-8')
                return bcrypt.checkpw(password.encode('utf-8'), stored_hash)
            return False
        except sqlite3.Error as e:
            logging.error(f"Error verifying user: {e}")
            return False

    def execute_query(self, query, params=None, fetch=False):
        if not self.conn:
            if not self.connect():
                return False
        try:
            logging.debug(f"Executing query: {query} with params: {params}")
            if params:
                self.cursor.execute(query, params)
            else:
                self.cursor.execute(query)
            if fetch:
                result = self.cursor.fetchall()
                logging.debug(f"Query result: {result}")
                return result
            else:
                self.conn.commit()
                logging.info("Query executed successfully")
                return True
        except sqlite3.Error as e:
            logging.error(f"Error executing query '{query}': {e}")
            return False

    def clear_artifacts(self):
        if not self.conn:
            if not self.connect():
                return False
        try:
            tables = ['BrowserArtifacts', 'USBDevices', 'USBActivity', 'LiveAnalysis', 'FileComparisons', 'AutopsyAnalysis', 'MalwareAnalysis', 'MalwareVendorResults']
            for table in tables:
                self.cursor.execute(f"DELETE FROM {table}")
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            logging.error(f"Error clearing database: {e}")
            return False

class CustomTableModel(QAbstractTableModel):
    def __init__(self, data, headers):
        super().__init__()
        self._data = data
        self._headers = headers

    def rowCount(self, parent=None):
        return len(self._data) if self._data else 0

    def columnCount(self, parent=None):
        return len(self._headers)

    def data(self, index, role=Qt.DisplayRole):
        if role == Qt.DisplayRole:
            return str(self._data[index.row()][index.column()])
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self._headers[section]
        return None

class LoginDialog(QDialog):
    def __init__(self, db_manager):
        super().__init__()
        self.db_manager = db_manager
        self.setWindowTitle("🕵‍♂️ Forensic Tool Login")
        self.setGeometry(500, 200, 520, 440)

        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(0, 0, 0, 160))
        shadow.setOffset(0, 8)
        self.setGraphicsEffect(shadow)

        self.setStyleSheet("""
            QDialog {
                background-color: #0F0F0F;
                border-radius: 20px;
            }
            QLabel {
                color: #D6D6D6;
                font-family: 'Playfair Display';
                font-size: 16px;
            }
            QLineEdit {
                padding: 10px;
                font-size: 14px;
                font-family: 'Segoe UI';
                border: 1.5px solid #2f2f2f;
                border-radius: 8px;
                background-color: rgba(33, 33, 33, 0.9);
                color: #ffffff;
            }
            QLineEdit:focus {
                border: 2px solid #3a7bd5;
                background-color: rgba(50, 50, 60, 0.95);
            }
            QPushButton {
                padding: 10px;
                font-size: 15px;
                font-weight: 600;
                border-radius: 8px;
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                                  stop:0 #1f2c4d, stop:1 #3a7bd5);
                color: white;
                font-family: 'Segoe UI';
            }
            QPushButton:hover {
                background-color: #2e5d9f;
            }
            QPushButton:pressed {
                background-color: #1b2e5f;
            }
        """)

        self.title_label = QLabel("Student Forensic Analysis Tool")
        self.title_label.setAlignment(Qt.AlignCenter)
        self.title_label.setFont(QFont("Playfair Display", 22, QFont.Bold))

        self.username_label = QLabel("Username:")
        self.username_input = QLineEdit()

        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.check_credentials)

        layout = QVBoxLayout()
        layout.setSpacing(12)
        layout.setContentsMargins(40, 30, 40, 30)
        layout.addWidget(self.title_label)
        layout.addSpacing(15)
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addSpacing(20)
        layout.addWidget(self.login_button)

        self.setLayout(layout)

    def check_credentials(self):
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        if not username or not password:
            QMessageBox.warning(self, "Input Error", "Please enter both username and password.")
            return
        if self.db_manager.verify_user(username, password):
            self.accept()
        else:
            QMessageBox.warning(self, "Access Denied", "Invalid username or password.")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Forensic Tool")
        self.setGeometry(100, 100, 1200, 800)
        self.db_manager = DatabaseManager()
        if not self.db_manager.connect():
            QMessageBox.critical(self, "Database Error",
                                 "Failed to connect to the database. Check logs for details.", QMessageBox.Ok)
            sys.exit(1)
        if not self.db_manager.create_tables():
            QMessageBox.critical(self, "Database Error",
                                 "Failed to create database tables. Check logs for details.", QMessageBox.Ok)
            self.db_manager.disconnect()
            sys.exit(1)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #0F0F0F;
            }
            QTabWidget::pane {
                border: 1px solid #2f2f2f;
                background-color: #1a1a1a;
            }
            QTabBar::tab {
                background-color: #2f2f2f;
                color: #D6D6D6;
                padding: 10px;
                font-family: 'Segoe UI';
                font-size: 14px;
            }
            QTabBar::tab:selected {
                background-color: #3a7bd5;
                color: white;
            }
            QTableView {
                background-color: #1a1a1a;
                color: #D6D6D6;
                gridline-color: #2f2f2f;
                font-family: 'Segoe UI';
                font-size: 12px;
            }
            QTextEdit {
                background-color: #1a1a1a;
                color: #D6D6D6;
                border: 1px solid #2f2f2f;
                font-family: 'Courier New';
                font-size: 12px;
            }
            QPushButton {
                padding: 8px;
                font-size: 14px;
                font-weight: 600;
                border-radius: 6px;
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                                  stop:0 #1f2c4d, stop:1 #3a7bd5);
                color: white;
                font-family: 'Segoe UI';
            }
            QPushButton:hover {
                background-color: #2e5d9f;
            }
            QPushButton:pressed {
                background-color: #1b2e5f;
            }
            QLineEdit {
                padding: 8px;
                font-size: 12px;
                font-family: 'Segoe UI';
                border: 1px solid #2f2f2f;
                border-radius: 6px;
                background-color: #1a1a1a;
                color: #ffffff;
            }
            QLineEdit:focus {
                border: 2px solid #3a7bd5;
            }
        """)

        self.is_fullscreen = False
        self.init_ui()
        self.load_data()

    def init_ui(self):
        self.tabs = QTabWidget()

        self.tabs.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tabs.customContextMenuRequested.connect(self.show_context_menu)

        self.browser_tab = QWidget()
        self.browser_layout = QVBoxLayout(self.browser_tab)
        
        search_layout = QHBoxLayout()
        self.search_label = QLabel("Search URL:")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter URL to search (e.g., evil.com)")
        self.filter_timer = QTimer(self)
        self.filter_timer.setSingleShot(True)
        self.filter_timer.timeout.connect(self.filter_browser_artifacts)
        self.search_input.textChanged.connect(lambda: self.filter_timer.start(300))
        search_layout.addWidget(self.search_label)
        search_layout.addWidget(self.search_input)
        self.browser_layout.addLayout(search_layout)

        self.browser_table = QTableView()
        self.browser_log = QTextEdit()
        self.browser_log.setReadOnly(True)
        self.browser_layout.addWidget(self.browser_table)
        self.browser_layout.addWidget(QLabel("Log:"))
        self.browser_layout.addWidget(self.browser_log)
        browser_button_layout = QHBoxLayout()
        self.extract_browser_button = QPushButton("Extract Browser Artifacts")
        self.extract_browser_button.clicked.connect(self.extract_browser_artifacts)
        self.clear_db_button = QPushButton("Clear Database")
        self.clear_db_button.clicked.connect(self.clear_database)
        browser_button_layout.addWidget(self.extract_browser_button)
        browser_button_layout.addWidget(self.clear_db_button)
        self.browser_layout.addLayout(browser_button_layout)
        self.tabs.addTab(self.browser_tab, "Browser Artifacts")

        self.usb_tab = QWidget()
        self.usb_layout = QVBoxLayout(self.usb_tab)
        self.usb_table = QTableView()
        self.usb_log = QTextEdit()
        self.usb_log.setReadOnly(True)
        self.usb_activity_table = QTableView()
        self.usb_layout.addWidget(self.usb_table)
        self.usb_layout.addWidget(QLabel("Log:"))
        self.usb_layout.addWidget(self.usb_log)
        usb_button_layout = QHBoxLayout()
        self.detect_usb_button = QPushButton("Detect USB Devices")
        self.detect_usb_button.clicked.connect(self.find_last_usb)
        self.refresh_activity_button = QPushButton("Refresh USB Activity")
        self.refresh_activity_button.clicked.connect(self.load_usb_activity)
        usb_button_layout.addWidget(self.detect_usb_button)
        usb_button_layout.addWidget(self.refresh_activity_button)
        self.usb_layout.addLayout(usb_button_layout)
        self.usb_layout.addWidget(QLabel("USB Activity Log:"))
        self.usb_layout.addWidget(self.usb_activity_table)
        self.tabs.addTab(self.usb_tab, "USB Devices")

        self.live_tab = QWidget()
        self.live_layout = QVBoxLayout(self.live_tab)
        self.live_table = QTableView()
        self.live_log = QTextEdit()
        self.live_log.setReadOnly(True)
        self.live_layout.addWidget(self.live_table)
        self.live_layout.addWidget(QLabel("Log:"))
        self.live_layout.addWidget(self.live_log)
        live_button_layout = QHBoxLayout()
        self.analyze_live_button = QPushButton("Perform Live Analysis")
        self.analyze_live_button.clicked.connect(self.live_forensic_analysis)
        live_button_layout.addWidget(self.analyze_live_button)
        self.live_layout.addLayout(live_button_layout)
        self.tabs.addTab(self.live_tab, "Live Analysis")

        self.compare_tab = QWidget()
        self.compare_layout = QVBoxLayout(self.compare_tab)
        self.compare_table = QTableView()
        self.compare_log = QTextEdit()
        self.compare_log.setReadOnly(True)
        self.compare_layout.addWidget(self.compare_table)
        self.compare_layout.addWidget(QLabel("Log:"))
        self.compare_layout.addWidget(self.compare_log)
        compare_button_layout = QHBoxLayout()
        self.compare_files_button = QPushButton("Compare Files")
        self.compare_files_button.clicked.connect(self.show_compare_files_dialog)
        self.export_results_button = QPushButton("Export Results")
        self.export_results_button.clicked.connect(self.export_comparison_results)
        compare_button_layout.addWidget(self.compare_files_button)
        compare_button_layout.addWidget(self.export_results_button)
        self.compare_layout.addLayout(compare_button_layout)
        self.tabs.addTab(self.compare_tab, "File Comparison")

        self.autopsy_tab = QWidget()
        self.autopsy_layout = QVBoxLayout(self.autopsy_tab)
        self.autopsy_table = QTableView()
        self.autopsy_log = QTextEdit()
        self.autopsy_log.setReadOnly(True)
        self.autopsy_layout.addWidget(self.autopsy_table)
        self.autopsy_layout.addWidget(QLabel("Log:"))
        self.autopsy_layout.addWidget(self.autopsy_log)
        autopsy_button_layout = QHBoxLayout()
        self.analyze_system_button = QPushButton("Analyze this System")
        self.analyze_system_button.clicked.connect(self.perform_autopsy_analysis)
        autopsy_button_layout.addWidget(self.analyze_system_button)
        self.autopsy_layout.addLayout(autopsy_button_layout)
        search_layout = QHBoxLayout()
        self.autopsy_search_label = QLabel("Search Details:")
        self.autopsy_search_input = QLineEdit()
        self.autopsy_search_input.setPlaceholderText("Enter keyword (e.g., 'IP', 'file')")
        self.autopsy_search_input.textChanged.connect(self.filter_autopsy_analysis)
        self.autopsy_search_button = QPushButton("Search")
        self.autopsy_search_button.clicked.connect(self.filter_autopsy_analysis)
        search_layout.addWidget(self.autopsy_search_label)
        search_layout.addWidget(self.autopsy_search_input)
        search_layout.addWidget(self.autopsy_search_button)
        self.autopsy_layout.addLayout(search_layout)
        self.tabs.addTab(self.autopsy_tab, "Autopsy Analysis")

        self.malware_tab = QWidget()
        self.malware_layout = QVBoxLayout(self.malware_tab)
        self.malware_table = QTableView()
        self.malware_log = QTextEdit()
        self.malware_log.setReadOnly(True)
        self.malware_layout.addWidget(self.malware_table)
        self.malware_layout.addWidget(QLabel("Log:"))
        self.malware_layout.addWidget(self.malware_log)
        malware_button_layout = QHBoxLayout()
        self.analyze_malware_button = QPushButton("Analyze File for Malware")
        self.analyze_malware_button.clicked.connect(self.show_malware_analysis_dialog)
        self.show_chart_button = QPushButton("Show Chart")
        self.show_chart_button.clicked.connect(self.show_malware_chart)
        self.clear_analysis_button = QPushButton("Clear Analysis")
        self.clear_analysis_button.clicked.connect(self.clear_malware_analysis)
        malware_button_layout.addWidget(self.analyze_malware_button)
        malware_button_layout.addWidget(self.show_chart_button)
        malware_button_layout.addWidget(self.clear_analysis_button)
        self.malware_layout.addLayout(malware_button_layout)
        self.tabs.addTab(self.malware_tab, "File Malware Analysis")

        self.layout.addWidget(self.tabs)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

    def show_context_menu(self, pos):
        menu = QMenu(self)
        toggle_action = QAction("Toggle Fullscreen", self)
        toggle_action.triggered.connect(self.toggle_fullscreen)
        menu.addAction(toggle_action)
        menu.exec_(self.tabs.mapToGlobal(pos))

    def toggle_fullscreen(self):
        self.is_fullscreen = not self.is_fullscreen
        if self.is_fullscreen:
            self.showFullScreen()
            self.log(self.browser_log, "Entered fullscreen mode")
        else:
            self.showNormal()
            self.log(self.browser_log, "Exited fullscreen mode")

    def log(self, tab_log, message):
        tab_log.append(f"[*] {message}\n")
        self.status_bar.showMessage(message, 3000)
        logging.info(message)

    def load_data(self):
        self.load_browser_artifacts()
        self.load_usb_devices()
        self.load_usb_activity()
        self.load_live_analysis()
        self.load_file_comparisons()
        self.load_autopsy_analysis()
        self.load_malware_analysis()

    def load_browser_artifacts(self):
        query = "SELECT ArtifactID, BrowserType, URL, Title, VisitTime FROM BrowserArtifacts"
        artifacts = self.db_manager.execute_query(query, fetch=True)
        if artifacts is False or artifacts is None:
            self.log(self.browser_log, "Error loading browser artifacts. Check database connection and logs.")
            self.browser_data = []
            self.all_browser_data = []
        else:
            self.browser_data = artifacts
            self.all_browser_data = artifacts
        self.browser_headers = ["ID", "Browser", "URL", "Title", "Visit Time"]
        self.browser_model = CustomTableModel(self.browser_data, self.browser_headers)
        self.browser_table.setModel(self.browser_model)

    def filter_browser_artifacts(self):
        search_text = self.search_input.text().strip().lower()
        self.log(self.browser_log, f"Filtering with search text: '{search_text}'")
        if not search_text:
            self.browser_data = self.all_browser_data
            self.log(self.browser_log, f"No search text, showing all {len(self.all_browser_data)} records")
        else:
            self.browser_data = [
                row for row in self.all_browser_data
                if search_text in str(row[2]).lower()  # row[2] is URL
            ]
            self.log(self.browser_log, f"Filtered to {len(self.browser_data)} records matching '{search_text}'")
        self.browser_model._data = self.browser_data
        self.browser_model.layoutChanged.emit()

    def clear_database(self):
        reply = QMessageBox.question(
            self, "Confirm Clear Database",
            "Are you sure you want to clear all forensic data? This will delete all records from Browser Artifacts, USB Devices, Live Analysis, File Comparisons, Autopsy Analysis, and Malware Analysis (user credentials will be preserved).",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            if self.db_manager.clear_artifacts():
                self.log(self.browser_log, "Database cleared successfully.")
                self.load_data()
            else:
                self.log(self.browser_log, "Error clearing database. Check logs for details.")

    def load_usb_devices(self):
        query = "SELECT USBID, DeviceName, DeviceID, LastConnected FROM USBDevices"
        devices = self.db_manager.execute_query(query, fetch=True)
        if devices is False or devices is None:
            self.log(self.usb_log, "Error loading USB devices. Check database connection.")
            self.usb_data = []
        else:
            self.usb_data = devices
        self.usb_headers = ["ID", "Device Name", "Device ID", "Last Connected"]
        self.usb_model = CustomTableModel(self.usb_data, self.usb_headers)
        self.usb_table.setModel(self.usb_model)

    def load_usb_activity(self):
        query = "SELECT ActivityID, DeviceID, EventType, EventTime, Details FROM USBActivity"
        activity = self.db_manager.execute_query(query, fetch=True)
        if activity is False or activity is None:
            self.log(self.usb_log, "Error loading USB activity. Check database connection.")
            self.usb_activity_data = []
        else:
            self.usb_activity_data = activity
        self.usb_activity_headers = ["ID", "Device ID", "Event Type", "Event Time", "Details"]
        self.usb_activity_model = CustomTableModel(self.usb_activity_data, self.usb_activity_headers)
        self.usb_activity_table.setModel(self.usb_activity_model)

    def load_live_analysis(self):
        query = "SELECT AnalysisID, Type, Details FROM LiveAnalysis"
        analysis = self.db_manager.execute_query(query, fetch=True)
        if analysis is False or analysis is None:
            self.log(self.live_log, "Error loading live analysis data. Check database connection.")
            self.live_data = []
        else:
            self.live_data = analysis
        self.live_headers = ["Type", "Details", "Timestamp"]
        self.live_model = CustomTableModel(self.live_data, self.live_headers)
        self.live_table.setModel(self.live_model)

    def load_autopsy_analysis(self):
        query = "SELECT AutopsyID, Type, Category, Details FROM AutopsyAnalysis"
        analysis = self.db_manager.execute_query(query, fetch=True)
        if analysis is False or analysis is None:
            self.log(self.autopsy_log, "Error loading autopsy analysis data. Check database connection.")
            self.autopsy_data = []
            self.all_autopsy_data = []
        else:
            self.autopsy_data = analysis
            self.all_autopsy_data = analysis
        self.autopsy_headers = ["ID", "Type", "Category", "Details"]
        self.autopsy_model = CustomTableModel(self.autopsy_data, self.autopsy_headers)
        self.autopsy_table.setModel(self.autopsy_model)

    def filter_autopsy_analysis(self):
        search_text = self.autopsy_search_input.text().strip().lower()
        if not search_text:
            self.autopsy_data = self.all_autopsy_data
        else:
            self.autopsy_data = [
                row for row in self.all_autopsy_data
                if search_text in row[3].lower()
            ]
        self.autopsy_model = CustomTableModel(self.autopsy_data, self.autopsy_headers)
        self.autopsy_table.setModel(self.autopsy_model)
        self.log(self.autopsy_log, f"Filtered {len(self.autopsy_data)} records matching '{search_text}'")

    def perform_autopsy_analysis(self):
        self.autopsy_log.clear()
        self.log(self.autopsy_log, "Performing system autopsy analysis...")
        try:
            query = "INSERT INTO AutopsyAnalysis (Type, Category, Details) VALUES (?, ?, ?)"

            system_info = f"OS: {platform.system()} {platform.release()}, Version: {platform.version()}, Architecture: {platform.machine()}"
            self.log(self.autopsy_log, system_info)
            self.db_manager.execute_query(query, ("System", "OS", system_info))

            boot_time = datetime.datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S')
            boot_info = f"System Boot Time: {boot_time}"
            self.log(self.autopsy_log, boot_info)
            self.db_manager.execute_query(query, ("Boot", "System", boot_info))

            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_info = f"CPU Count: {cpu_count}, Current Freq: {cpu_freq.current:.2f} MHz, Max Freq: {cpu_freq.max:.2f} MHz, Usage: {cpu_percent}%"
            self.log(self.autopsy_log, cpu_info)
            self.db_manager.execute_query(query, ("CPU", "Hardware", cpu_info))

            mem = psutil.virtual_memory()
            swap = psutil.swap_memory()
            mem_info = f"RAM: Total: {mem.total / (1024 ** 3):.2f} GB, Used: {mem.used / (1024 ** 3):.2f} GB, Free: {mem.free / (1024 ** 3):.2f} GB, Percent: {mem.percent}%; Swap: Total: {swap.total / (1024 ** 3):.2f} GB, Used: {swap.used / (1024 ** 3):.2f} GB"
            self.log(self.autopsy_log, mem_info)
            self.db_manager.execute_query(query, ("Memory", "Hardware", mem_info))

            partitions = psutil.disk_partitions()
            for part in partitions:
                disk_info = f"Partition: Device: {part.device}, Mount: {part.mountpoint}, Type: {part.fstype}, Options: {part.opts}"
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    disk_info += f", Total: {usage.total / (1024 ** 3):.2f} GB, Used: {usage.used / (1024 ** 3):.2f} GB, Free: {usage.free / (1024 ** 3):.2f} GB"
                except:
                    disk_info += ", Usage: Not available"
                self.log(self.autopsy_log, disk_info)
                self.db_manager.execute_query(query, ("Disk", "Storage", disk_info))

            try:
                result = subprocess.run(['lsblk', '-o', 'NAME,MOUNTPOINT,FSTYPE,SIZE,MODEL'], capture_output=True, text=True)
                mounted = result.stdout.strip().splitlines()[1:5]
                for device in mounted:
                    if device.strip():
                        self.log(self.autopsy_log, f"Mounted Device: {device}")
                        self.db_manager.execute_query(query, ("MountedDevice", "Storage", device))
            except:
                self.log(self.autopsy_log, "Could not retrieve mounted devices")

            net_if = psutil.net_if_addrs()
            for iface, addrs in net_if.items():
                for addr in addrs:
                    if addr.family == 2:
                        net_info = f"Interface: {iface}, IP: {addr.address}, Netmask: {addr.netmask}"
                        self.log(self.autopsy_log, net_info)
                        self.db_manager.execute_query(query, ("NetworkInterface", "Network", net_info))

            connections = psutil.net_connections(kind='inet')
            for conn in connections[:5]:
                if conn.status == 'LISTEN':
                    proc = psutil.Process(conn.pid) if conn.pid else None
                    port_info = f"Port: {conn.laddr.port}, Protocol: {conn.type}, Process: {proc.name() if proc else 'Unknown'}, PID: {conn.pid}"
                    self.log(self.autopsy_log, port_info)
                    self.db_manager.execute_query(query, ("OpenPort", "Network", port_info))

            try:
                result = subprocess.run(['systemd-resolve', '--statistics'], capture_output=True, text=True)
                dns_info = result.stdout.strip().splitlines()[:5]
                dns_details = "DNS Cache: " + "; ".join(dns_info)
                self.log(self.autopsy_log, dns_details)
                self.db_manager.execute_query(query, ("DNSCache", "Network", dns_details))
            except:
                self.log(self.autopsy_log, "Could not retrieve DNS cache")

            try:
                result = subprocess.run(['getent', 'passwd'], capture_output=True, text=True)
                users = result.stdout.splitlines()[:5]
                for user in users:
                    user_info = user.split(':')
                    user_details = f"User: {user_info[0]}, UID: {user_info[2]}, Home: {user_info[5]}, Shell: {user_info[6]}"
                    self.log(self.autopsy_log, user_details)
                    self.db_manager.execute_query(query, ("UserAccount", "System", user_details))
            except:
                self.log(self.autopsy_log, "Could not retrieve user accounts")

            processes = sorted(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']),
                              key=lambda p: p.info['cpu_percent'], reverse=True)[:5]
            for proc in processes:
                proc_info = f"PID: {proc.info['pid']}, Name: {proc.info['name']}, CPU: {proc.info['cpu_percent']:.2f}%, Memory: {proc.info['memory_percent']:.2f}%"
                self.log(self.autopsy_log, proc_info)
                self.db_manager.execute_query(query, ("Process", "System", proc_info))

            try:
                result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
                cron_jobs = result.stdout.splitlines()[:5]
                for job in cron_jobs:
                    if job.strip() and not job.startswith('#'):
                        self.log(self.autopsy_log, f"Cron Job: {job}")
                        self.db_manager.execute_query(query, ("CronJob", "System", job))
            except:
                self.log(self.autopsy_log, "Could not retrieve cron jobs")

            try:
                result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=active'], capture_output=True, text=True)
                services = result.stdout.splitlines()[1:6]
                for service in services:
                    if service.strip():
                        self.log(self.autopsy_log, f"Service: {service}")
                        self.db_manager.execute_query(query, ("Service", "System", service))
            except:
                self.log(self.autopsy_log, "Could not retrieve system services")

            try:
                result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
                firewall_rules = result.stdout.strip().splitlines()[:5]
                firewall_details = "Firewall Status: " + "; ".join(firewall_rules)
                self.log(self.autopsy_log, firewall_details)
                self.db_manager.execute_query(query, ("Firewall", "Network", firewall_details))
            except:
                self.log(self.autopsy_log, "Could not retrieve firewall rules")

            try:
                log_file = "/var/log/syslog" if os.path.exists("/var/log/syslog") else "/var/log/auth.log"
                if os.path.exists(log_file):
                    with open(log_file, 'r') as f:
                        logs = f.readlines()[-5:]
                        for log in logs:
                            self.log(self.autopsy_log, f"System Log: {log.strip()}")
                            self.db_manager.execute_query(query, ("SystemLog", "System", log.strip()))
            except:
                self.log(self.autopsy_log, "Could not retrieve system logs")

            try:
                result = subprocess.run(['dpkg', '--list'], capture_output=True, text=True)
                packages = result.stdout.splitlines()[:5]
                for pkg in packages:
                    if pkg.startswith('ii'):
                        self.log(self.autopsy_log, f"Package: {pkg}")
                        self.db_manager.execute_query(query, ("Software", "System", pkg))
            except:
                self.log(self.autopsy_log, "Could not retrieve installed software")

            env_vars = ['PATH', 'HOME', 'USER', 'SHELL']
            for var in env_vars:
                value = os.environ.get(var, 'Not set')
                env_info = f"Env Var: {var}={value}"
                self.log(self.autopsy_log, env_info)
                self.db_manager.execute_query(query, ("Environment", "System", env_info))

            user_dir = os.path.expanduser("~")
            recent_files = []
            for root, _, files in os.walk(user_dir):
                for file in files[:5]:
                    file_path = os.path.join(root, file)
                    try:
                        mtime = datetime.datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
                        details = f"File: {file_path}, Modified: {mtime}"
                        recent_files.append(details)
                    except:
                        continue
                if len(recent_files) >= 5:
                    break
            for details in recent_files:
                self.log(self.autopsy_log, details)
                self.db_manager.execute_query(query, ("RecentFile", "Storage", details))

            uptime_seconds = time.time() - psutil.boot_time()
            uptime_info = f"Uptime: {uptime_seconds / 3600:.2f} hours"
            self.log(self.autopsy_log, uptime_info)
            self.db_manager.execute_query(query, ("Uptime", "System", uptime_info))

            try:
                result = subprocess.run(['lsmod'], capture_output=True, text=True)
                modules = result.stdout.splitlines()[1:6]
                for module in modules:
                    if module.strip():
                        self.log(self.autopsy_log, f"Kernel Module: {module}")
                        self.db_manager.execute_query(query, ("KernelModule", "System", module))
            except:
                self.log(self.autopsy_log, "Could not retrieve kernel modules")

            self.load_autopsy_analysis()
        except Exception as e:
            self.log(self.autopsy_log, f"Error during autopsy analysis: {str(e)}")

    def load_malware_analysis(self):
        query = "SELECT AnalysisID, FilePath, MD5Hash, Result, Entropy FROM MalwareAnalysis ORDER BY AnalysisID DESC LIMIT 1"
        artifacts = self.db_manager.execute_query(query, fetch=True)
        if artifacts is False or artifacts is None:
            self.log(self.malware_log, "Error loading malware analysis data. Check database connection and logs.")
            self.malware_data = []
        elif not artifacts:
            self.log(self.malware_log, "No malware analysis data available. Perform an analysis first.")
            self.malware_data = []
        else:
            analysis_id = artifacts[0][0]
            query = "SELECT VendorName, DetectionStatus FROM MalwareVendorResults WHERE AnalysisID = ?"
            vendor_results = self.db_manager.execute_query(query, (analysis_id,), fetch=True)
            if vendor_results:
                table_data = [[vendor, status] for vendor, status in vendor_results]
                self.malware_data = [["Vendor", "Detection Status"]] + table_data
            else:
                self.malware_data = [["Vendor", "Detection Status"], ["No detailed vendor data", "N/A"]]
        self.malware_headers = ["Vendor", "Detection Status"]
        self.malware_model = CustomTableModel(self.malware_data, self.malware_headers)
        self.malware_table.setModel(self.malware_model)

    def analyze_malware(self, file_path):
        self.malware_log.clear()
        self.log(self.malware_log, f"Analyzing file: {file_path}...")
        if not file_path or not os.path.exists(file_path):
            self.log(self.malware_log, "Invalid or non-existent file path.")
            return
        try:
            self.log(self.malware_log, f"Received file path: {file_path}")

            # Calculate MD5 hash
            md5_hash = hashlib.md5()
            with open(file_path, 'rb') as f:
                while chunk := f.read(4096):
                    md5_hash.update(chunk)
            md5_hash = md5_hash.hexdigest()
            self.log(self.malware_log, f"Calculated MD5 Hash: {md5_hash}")

            # VirusTotal API request
            url = f"https://www.virustotal.com/api/v3/files/{md5_hash}"
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            self.log(self.malware_log, f"Sending request to {url}")
            response = requests.get(url, headers=headers, timeout=10)
            self.log(self.malware_log, f"API Response Status: {response.status_code}")
            if response.status_code == 200:
                result_data = response.json().get("data", {})
                if result_data and "attributes" in result_data:
                    analysis_results = result_data["attributes"].get("last_analysis_results", {})
                    detailed_results = {}
                    for vendor, result in analysis_results.items():
                        category = result.get("category", "undetected")
                        detection_status = "detected" if category == "malicious" else "not detected"
                        detailed_results[vendor] = detection_status
                    query = "INSERT INTO MalwareAnalysis (FilePath, MD5Hash, Result, Entropy) VALUES (?, ?, ?, ?)"
                    if not self.db_manager.execute_query(query, (file_path, md5_hash, "; ".join([f"{v}: {s}" for v, s in detailed_results.items()]), None)):
                        self.log(self.malware_log, "Failed to insert malware analysis data into database.")
                        return
                    query = "SELECT last_insert_rowid()"
                    analysis_id = self.db_manager.execute_query(query, fetch=True)[0][0]
                    self.log(self.malware_log, f"Inserted analysis with ID: {analysis_id}")
                    for vendor, status in detailed_results.items():
                        query = "INSERT INTO MalwareVendorResults (AnalysisID, VendorName, DetectionStatus) VALUES (?, ?, ?)"
                        if not self.db_manager.execute_query(query, (analysis_id, vendor, status)):
                            self.log(self.malware_log, f"Failed to insert vendor result for {vendor}.")
                            continue
                    self.log(self.malware_log, f"Analysis Result: {'; '.join([f'{v}: {s}' for v, s in detailed_results.items()])}")
                else:
                    self.log(self.malware_log, "No detailed analysis results available.")
                    query = "INSERT INTO MalwareAnalysis (FilePath, MD5Hash, Result, Entropy) VALUES (?, ?, ?, ?)"
                    if not self.db_manager.execute_query(query, (file_path, md5_hash, "No detailed results", None)):
                        self.log(self.malware_log, "Failed to insert minimal malware analysis data.")
            elif response.status_code == 403:
                self.log(self.malware_log, "API Error 403: Invalid or unauthorized API key. Please update VIRUSTOTAL_API_KEY.")
                query = "INSERT INTO MalwareAnalysis (FilePath, MD5Hash, Result, Entropy) VALUES (?, ?, ?, ?)"
                if not self.db_manager.execute_query(query, (file_path, md5_hash, "API Error: Unauthorized", None)):
                    self.log(self.malware_log, "Failed to insert API error data.")
            elif response.status_code == 429:
                self.log(self.malware_log, "API Error 429: Rate limit exceeded. Try again later.")
                query = "INSERT INTO MalwareAnalysis (FilePath, MD5Hash, Result, Entropy) VALUES (?, ?, ?, ?)"
                if not self.db_manager.execute_query(query, (file_path, md5_hash, "API Error: Rate Limited", None)):
                    self.log(self.malware_log, "Failed to insert API error data.")
            else:
                self.log(self.malware_log, f"API Error: {response.status_code} - {response.text}")
                query = "INSERT INTO MalwareAnalysis (FilePath, MD5Hash, Result, Entropy) VALUES (?, ?, ?, ?)"
                if not self.db_manager.execute_query(query, (file_path, md5_hash, f"API Error: {response.status_code}", None)):
                    self.log(self.malware_log, "Failed to insert API error data.")
            self.load_malware_analysis()
        except Exception as e:
            self.log(self.malware_log, f"Error during malware analysis: {str(e)}")

    def show_malware_chart(self):
        query = "SELECT AnalysisID, FilePath, MD5Hash, Result, Entropy FROM MalwareAnalysis ORDER BY AnalysisID DESC LIMIT 1"
        analysis = self.db_manager.execute_query(query, fetch=True)
        if analysis is False or analysis is None or not analysis:
            self.log(self.malware_log, "No malware analysis data available to chart.")
            return

        analysis_id = analysis[0][0]
        query = "SELECT DetectionStatus, COUNT(*) as count FROM MalwareVendorResults WHERE AnalysisID = ? GROUP BY DetectionStatus"
        vendor_stats = self.db_manager.execute_query(query, (analysis_id,), fetch=True)
        if not vendor_stats:
            self.log(self.malware_log, "No vendor data available to chart.")
            return

        stats = {row[0]: row[1] for row in vendor_stats}
        detected = stats.get("detected", 0)
        not_detected = stats.get("not detected", 0)
        total = detected + not_detected

        fig, ax = plt.subplots(figsize=(8, 6))
        labels = ['Detected', 'Not Detected']
        values = [detected, not_detected]
        ax.bar(labels, values, color=['#ff9999', '#66b3ff'])
        ax.set_title(f'VirusTotal Detection Summary (Total Vendors: {total})')
        ax.set_ylabel('Number of Vendors')
        for i, v in enumerate(values):
            ax.text(i, v + 0.5, str(v), ha='center')

        plt.savefig('malware_chart.png')
        plt.close()

        self.canvas = FigureCanvas(plt.figure(figsize=(8, 6)))
        self.canvas.figure = fig
        self.chart_dialog = QDialog(self)
        self.chart_dialog.setWindowTitle("Malware Detection Chart")
        self.chart_dialog.setGeometry(400, 300, 600, 400)
        layout = QVBoxLayout(self.chart_dialog)
        layout.addWidget(self.canvas)
        self.chart_dialog.setStyleSheet("""
            QDialog {
                background-color: #0F0F0F;
                border-radius: 15px;
            }
        """)
        self.chart_dialog.exec_()

    def show_malware_analysis_dialog(self):
        dialog = MalwareAnalysisDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            file_path = dialog.get_file()
            if file_path:
                self.analyze_malware(file_path)

    def live_forensic_analysis(self):
        self.live_log.clear()
        self.log(self.live_log, "Performing live forensic analysis...")
        try:
            for proc in list(psutil.process_iter(['pid', 'name', 'create_time']))[:5]:
                create_time = datetime.datetime.fromtimestamp(proc.info['create_time']).strftime('%Y-%m-%d %H:%M:%S')
                details = f"PID: {proc.info['pid']}, Name: {proc.info['name']}, Started: {create_time}"
                self.log(self.live_log, details)
                query = "INSERT INTO LiveAnalysis (Type, Details) VALUES (?, ?)"
                self.db_manager.execute_query(query, ("Process", details))

            user_dir = os.path.expanduser("~")
            recent_files = []
            for root, _, files in os.walk(user_dir):
                for file in files[:5]:
                    file_path = os.path.join(root, file)
                    try:
                        mtime = datetime.datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
                        details = f"File: {file_path}, Modified: {mtime}"
                        recent_files.append(details)
                    except:
                        continue
                if len(recent_files) >= 5:
                    break
            for details in recent_files:
                self.log(self.live_log, details)
                query = "INSERT INTO LiveAnalysis (Type, Details) VALUES (?, ?)"
                self.db_manager.execute_query(query, ("File", details))

            mem = psutil.virtual_memory()
            details = f"Total: {mem.total / (1024 ** 3):.2f} GB, Used: {mem.used / (1024 ** 3):.2f} GB, Free: {mem.free / (1024 ** 3):.2f} GB"
            self.log(self.live_log, f"Memory Usage: {details}")
            query = "INSERT INTO LiveAnalysis (Type, Details) VALUES (?, ?)"
            self.db_manager.execute_query(query, ("Memory", details))

            disk = psutil.disk_usage('/')
            details = f"Total: {disk.total / (1024 ** 3):.2f} GB, Used: {disk.used / (1024 ** 3):.2f} GB, Free: {disk.free / (1024 ** 3):.2f} GB"
            self.log(self.live_log, f"Disk Space: {details}")
            query = "INSERT INTO LiveAnalysis (Type, Details) VALUES (?, ?)"
            self.db_manager.execute_query(query, ("Disk", details))

            connections = psutil.net_connections(kind='inet')
            for conn in connections[:5]:
                details = f"Local: {conn.laddr}, Remote: {conn.raddr}, Status: {conn.status}"
                self.log(self.live_log, f"Network Connection: {details}")
                query = "INSERT INTO LiveAnalysis (Type, Details) VALUES (?, ?)"
                self.db_manager.execute_query(query, ("Network", details))

            result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=active'], capture_output=True, text=True)
            services = result.stdout.splitlines()
            for service in services[1:6]:
                if service.strip():
                    details = service.strip()
                    self.log(self.live_log, f"Service: {details}")
                    query = "INSERT INTO LiveAnalysis (Type, Details) VALUES (?, ?)"
                    self.db_manager.execute_query(query, ("Service", details))

            self.load_live_analysis()
        except Exception as e:
            self.log(self.live_log, f"Error during live analysis: {str(e)}")

    def load_file_comparisons(self):
        query = "SELECT ComparisonID, File1Path, File2Path, HashMatch, ByteMatch, Details, Metadata1, Metadata2 FROM FileComparisons"
        comparisons = self.db_manager.execute_query(query, fetch=True)
        if comparisons is False or comparisons is None:
            self.log(self.compare_log, "Error loading file comparisons. Check database connection.")
            self.compare_data = []
        else:
            self.compare_data = comparisons
        self.compare_headers = ["ID", "File 1", "File 2", "Hash Match", "Byte Match", "Details", "Metadata 1", "Metadata 2"]
        self.compare_model = CustomTableModel(self.compare_data, self.compare_headers)
        self.compare_table.setModel(self.compare_model)

    def get_file_metadata(self, file_path):
        try:
            stat_info = os.stat(file_path)
            metadata = {
                "Size": f"{stat_info.st_size} bytes",
                "Created": datetime.datetime.fromtimestamp(stat_info.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
                "Modified": datetime.datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                "Accessed": datetime.datetime.fromtimestamp(stat_info.st_atime).strftime('%Y-%m-%d %H:%M:%S'),
                "Owner": os.getlogin()  # Simplified owner; could be expanded with pwd module
            }
            return str(metadata)
        except Exception as e:
            self.log(self.compare_log, f"Error getting metadata for {file_path}: {str(e)}")
            return "N/A"

    def compare_files(self, file1_path, file2_path):
        self.compare_log.clear()
        self.log(self.compare_log, f"Comparing files: {file1_path} and {file2_path}...")
        try:
            # Get metadata
            metadata1 = self.get_file_metadata(file1_path)
            metadata2 = self.get_file_metadata(file2_path)

            hash1_md5 = hashlib.md5()
            hash2_md5 = hashlib.md5()
            hash1_sha = hashlib.sha256()
            hash2_sha = hashlib.sha256()

            with open(file1_path, 'rb') as f1, open(file2_path, 'rb') as f2:
                while True:
                    chunk1 = f1.read(4096)
                    chunk2 = f2.read(4096)
                    if not chunk1 and not chunk2:
                        break
                    hash1_md5.update(chunk1)
                    hash2_md5.update(chunk2)
                    hash1_sha.update(chunk1)
                    hash2_sha.update(chunk2)

            md5_match = hash1_md5.hexdigest() == hash2_md5.hexdigest()
            sha_match = hash1_sha.hexdigest() == hash2_sha.hexdigest()
            hash_match = md5_match and sha_match

            byte_match = True
            with open(file1_path, 'rb') as f1, open(file2_path, 'rb') as f2:
                while True:
                    byte1 = f1.read(1)
                    byte2 = f2.read(1)
                    if byte1 != byte2:
                        byte_match = False
                        break
                    if not byte1 and not byte2:
                        break

            details = (f"MD5 Match: {md5_match}, SHA256 Match: {sha_match}, "
                      f"Byte Match: {byte_match}")
            self.log(self.compare_log, details)
            query = "INSERT INTO FileComparisons (File1Path, File2Path, HashMatch, ByteMatch, Details, Metadata1, Metadata2) VALUES (?, ?, ?, ?, ?, ?, ?)"
            self.db_manager.execute_query(query, (file1_path, file2_path, hash_match, byte_match, details, metadata1, metadata2))
            self.load_file_comparisons()
        except Exception as e:
            self.log(self.compare_log, f"Error comparing files: {str(e)}")

    def export_comparison_results(self):
        self.compare_log.clear()
        self.log(self.compare_log, "Exporting comparison results...")
        try:
            query = "SELECT * FROM FileComparisons"
            results = self.db_manager.execute_query(query, fetch=True)
            if not results:
                self.log(self.compare_log, "No comparison results to export.")
                return

            # Export to CSV with improved formatting
            csv_file = QFileDialog.getSaveFileName(self, "Save CSV File", "", "CSV Files (*.csv)")[0]
            if csv_file:
                with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                    writer.writerow(["ID", "File 1", "File 2", "Hash Match", "Byte Match", "Details", "Metadata 1", "Metadata 2", "Timestamp"])
                    for row in results:
                        writer.writerow(row)
                self.log(self.compare_log, f"Exported to {csv_file}")

            # Export to PDF with improved alignment and styling
            pdf_file = QFileDialog.getSaveFileName(self, "Save PDF File", "", "PDF Files (*.pdf)")[0]
            if pdf_file:
                pdf = SimpleDocTemplate(pdf_file, pagesize=letter)
                styles = getSampleStyleSheet()
                table_data = [self.compare_headers] + [list(map(str, row)) for row in results]
                table = Table(table_data)
                table_width = 500  # Fixed width for now, adjust based on content if needed
                col_widths = [table_width / len(self.compare_headers)] * len(self.compare_headers)
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                    ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 1), (-1, -1), 10),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 5),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 5),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ]))
                table._argW = col_widths
                elements = [table]
                pdf.build(elements)
                self.log(self.compare_log, f"Exported to {pdf_file}")
        except Exception as e:
            self.log(self.compare_log, f"Error exporting results: {str(e)}")

    def get_firefox_profile(self):
        profiles_ini = os.path.expanduser("~/.mozilla/firefox/profiles.ini")
        if not os.path.exists(profiles_ini):
            return None
        config = configparser.ConfigParser()
        config.read(profiles_ini)
        for section in config.sections():
            if section.startswith("Profile") and config[section].get("Default") == "1":
                profile_path = config[section].get("Path")
                full_path = os.path.expanduser(f"~/.mozilla/firefox/{profile_path}")
                if os.path.exists(os.path.join(full_path, "places.sqlite")):
                    return full_path
        for section in config.sections():
            if section.startswith("Profile"):
                profile_path = config[section].get("Path")
                full_path = os.path.expanduser(f"~/.mozilla/firefox/{profile_path}")
                if os.path.exists(os.path.join(full_path, "places.sqlite")):
                    return full_path
        return None

    def extract_browser_artifacts(self):
        self.browser_log.clear()
        self.log(self.browser_log, "Extracting browser artifacts...")
        try:
            chrome_paths = [
                os.path.expanduser("~/.config/google-chrome/Default/History"),
                os.path.expanduser("~/.config/chromium/Default/History")
            ]
            chrome_found = False
            for chrome_path in chrome_paths:
                if os.path.exists(chrome_path):
                    chrome_found = True
                    browser_type = "Chrome" if "google-chrome" in chrome_path else "Chromium"
                    temp_path = "/tmp/chrome_history_temp"
                    with open(chrome_path, 'rb') as src, open(temp_path, 'wb') as dst:
                        dst.write(src.read())
                    conn = sqlite3.connect(temp_path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC")
                    results = cursor.fetchall()
                    self.log(self.browser_log, f"Extracted {len(results)} URLs from {browser_type}")
                    for row in results:
                        url, title, timestamp = row
                        epoch = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=timestamp)
                        self.log(self.browser_log, f"{browser_type} - URL: {url}, Title: {title}, Visited: {epoch}")
                        query = "INSERT INTO BrowserArtifacts (BrowserType, URL, Title, VisitTime) VALUES (?, ?, ?, ?)"
                        self.db_manager.execute_query(query, (browser_type, url, title, str(epoch)))
                    conn.close()
                    os.remove(temp_path)
                    break
            if not chrome_found:
                self.log(self.browser_log, "Chrome/Chromium History file not found. Ensure a browser is installed.")

            firefox_profile = self.get_firefox_profile()
            if firefox_profile:
                firefox_path = os.path.join(firefox_profile, "places.sqlite")
                if os.path.exists(firefox_path):
                    temp_path = "/tmp/firefox_history_temp"
                    with open(firefox_path, 'rb') as src, open(temp_path, 'wb') as dst:
                        dst.write(src.read())
                    conn = sqlite3.connect(temp_path)
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT moz_places.url, moz_places.title, moz_places.last_visit_date
                        FROM moz_places
                        WHERE last_visit_date IS NOT NULL
                        ORDER BY last_visit_date DESC
                    """)
                    results = cursor.fetchall()
                    self.log(self.browser_log, f"Extracted {len(results)} URLs from Firefox")
                    for row in results:
                        url, title, timestamp = row
                        epoch = datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=timestamp)
                        self.log(self.browser_log, f"Firefox - URL: {url}, Title: {title}, Visited: {epoch}")
                        query = "INSERT INTO BrowserArtifacts (BrowserType, URL, Title, VisitTime) VALUES (?, ?, ?, ?)"
                        self.db_manager.execute_query(query, ("Firefox", url, title, str(epoch)))
                    conn.close()
                    os.remove(temp_path)
                else:
                    self.log(self.browser_log, "Firefox History file not found.")
            else:
                self.log(self.browser_log, "Firefox profile not found. Ensure Firefox is installed.")
        except Exception as e:
            self.log(self.browser_log, f"Error extracting browser artifacts: {str(e)}")
        self.load_browser_artifacts()

    def find_last_usb(self):
        self.usb_log.clear()
        self.log(self.usb_log, "Finding last connected USB device...")
        try:
            usb_path = "/sys/bus/usb/devices"
            devices = []
            for device in glob.glob(f"{usb_path}/usb*"):
                try:
                    with open(f"{device}/product", 'r') as f:
                        device_name = f.read().strip()
                    with open(f"{device}/serial", 'r') as f:
                        device_id = f.read().strip()
                    log_file = "/var/log/syslog"
                    last_connected = "Unknown"
                    if os.path.exists(log_file):
                        with open(log_file, 'r') as f:
                            for line in f:
                                if device_id in line:
                                    last_connected = " ".join(line.split()[0:3])
                                    break
                    devices.append((device_name, device_id, last_connected))
                except:
                    continue

            if devices:
                device = devices[0]
                self.log(self.usb_log, f"Device: {device[0]}, ID: {device[1]}, Last Connected: {device[2]}")
                query = "INSERT INTO USBDevices (DeviceName, DeviceID, LastConnected) VALUES (?, ?, ?)"
                self.db_manager.execute_query(query, (device[0], device[1], device[2]))
                self.load_usb_devices()
            else:
                self.log(self.usb_log, "No USB devices found.")
        except Exception as e:
            self.log(self.usb_log, f"Error finding USB devices: {str(e)}")

    def show_compare_files_dialog(self):
        dialog = CompareFilesDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            file1_path, file2_path = dialog.get_files()
            if file1_path and file2_path:
                self.compare_files(file1_path, file2_path)

    def clear_malware_analysis(self):
        self.malware_log.clear()
        self.malware_data = []
        self.malware_model = CustomTableModel(self.malware_data, self.malware_headers)
        self.malware_table.setModel(self.malware_model)
        self.log(self.malware_log, "Cleared current malware analysis data.")

    def closeEvent(self, event):
        self.db_manager.disconnect()
        event.accept()

class CompareFilesDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Compare Files")
        self.setGeometry(400, 300, 500, 300)
        self.setStyleSheet("""
            QDialog {
                background-color: #0F0F0F;
                border-radius: 15px;
            }
            QLabel {
                color: #D6D6D6;
                font-family: 'Segoe UI';
                font-size: 14px;
            }
            QLineEdit {
                padding: 8px;
                font-size: 12px;
                font-family: 'Segoe UI';
                border: 1px solid #2f2f2f;
                border-radius: 6px;
                background-color: #1a1a1a;
                color: #ffffff;
            }
            QPushButton {
                padding: 8px;
                font-size: 14px;
                font-weight: 600;
                border-radius: 6px;
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                                  stop:0 #1f2c4d, stop:1 #3a7bd5);
                color: white;
                font-family: 'Segoe UI';
            }
            QPushButton:hover {
                background-color: #2e5d9f;
            }
            QPushButton:pressed {
                background-color: #1b2e5f;
            }
        """)

        self.layout = QVBoxLayout(self)

        self.file1_label = QLabel("Select First File:")
        self.file1_input = QLineEdit()
        self.file1_input.setReadOnly(True)
        self.file1_button = QPushButton("Browse")
        self.file1_button.clicked.connect(self.browse_file1)
        file1_layout = QHBoxLayout()
        file1_layout.addWidget(self.file1_input)
        file1_layout.addWidget(self.file1_button)

        self.file2_label = QLabel("Select Second File:")
        self.file2_input = QLineEdit()
        self.file2_input.setReadOnly(True)
        self.file2_button = QPushButton("Browse")
        self.file2_button.clicked.connect(self.browse_file2)
        file2_layout = QHBoxLayout()
        file2_layout.addWidget(self.file2_input)
        file2_layout.addWidget(self.file2_button)

        self.button_box = QHBoxLayout()
        self.compare_button = QPushButton("Compare")
        self.compare_button.clicked.connect(self.accept)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        self.button_box.addWidget(self.compare_button)
        self.button_box.addWidget(self.cancel_button)

        self.layout.addWidget(self.file1_label)
        self.layout.addLayout(file1_layout)
        self.layout.addWidget(self.file2_label)
        self.layout.addLayout(file2_layout)
        self.layout.addStretch()
        self.layout.addLayout(self.button_box)

    def browse_file1(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select First File")
        if file_path:
            self.file1_input.setText(file_path)

    def browse_file2(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Second File")
        if file_path:
            self.file2_input.setText(file_path)

    def get_files(self):
        return self.file1_input.text(), self.file2_input.text()

    def accept(self):
        if not self.file1_input.text() or not self.file2_input.text():
            QMessageBox.warning(self, "Error", "Please select both files to compare.", QMessageBox.Ok)
            return
        super().accept()

class MalwareAnalysisDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Analyze File for Malware")
        self.setGeometry(400, 300, 500, 300)
        self.setStyleSheet("""
            QDialog {
                background-color: #0F0F0F;
                border-radius: 15px;
            }
            QLabel {
                color: #D6D6D6;
                font-family: 'Segoe UI';
                font-size: 14px;
            }
            QLineEdit {
                padding: 8px;
                font-size: 12px;
                font-family: 'Segoe UI';
                border: 1px solid #2f2f2f;
                border-radius: 6px;
                background-color: #1a1a1a;
                color: #ffffff;
            }
            QPushButton {
                padding: 8px;
                font-size: 14px;
                font-weight: 600;
                border-radius: 6px;
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                                  stop:0 #1f2c4d, stop:1 #3a7bd5);
                color: white;
                font-family: 'Segoe UI';
            }
            QPushButton:hover {
                background-color: #2e5d9f;
            }
            QPushButton:pressed {
                background-color: #1b2e5f;
            }
        """)

        self.layout = QVBoxLayout(self)

        self.file_label = QLabel("Select File to Analyze:")
        self.file_input = QLineEdit()
        self.file_input.setReadOnly(True)
        self.file_button = QPushButton("Browse")
        self.file_button.clicked.connect(self.browse_file)
        file_layout = QHBoxLayout()
        file_layout.addWidget(self.file_input)
        file_layout.addWidget(self.file_button)

        self.button_box = QHBoxLayout()
        self.analyze_button = QPushButton("Analyze")
        self.analyze_button.clicked.connect(self.accept)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        self.button_box.addWidget(self.analyze_button)
        self.button_box.addWidget(self.cancel_button)

        self.layout.addWidget(self.file_label)
        self.layout.addLayout(file_layout)
        self.layout.addStretch()
        self.layout.addLayout(self.button_box)

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Analyze")
        if file_path:
            self.file_input.setText(file_path)

    def get_file(self):
        return self.file_input.text()

    def accept(self):
        if not self.file_input.text():
            QMessageBox.warning(self, "Error", "Please select a file to analyze.", QMessageBox.Ok)
            return
        super().accept()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    db_manager = DatabaseManager()
    if not db_manager.connect():
        QMessageBox.critical(None, "Database Error",
                             "Failed to connect to the database. Check logs for details.", QMessageBox.Ok)
        sys.exit(1)
    if not db_manager.create_tables():
        QMessageBox.critical(None, "Database Error",
                             "Failed to create database tables. Check logs for details.", QMessageBox.Ok)
        db_manager.disconnect()
        sys.exit(1)
    login = LoginDialog(db_manager)
    if login.exec_() == QDialog.Accepted:
        main_window = MainWindow()
        main_window.show()
        sys.exit(app.exec_())
    db_manager.disconnect()

