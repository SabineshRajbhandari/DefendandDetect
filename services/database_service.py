import sqlite3
import json
from datetime import datetime
import streamlit as st

DB_FILE = "history.db"

class DatabaseService:
    @staticmethod
    def init_db():
        """Initialize the SQLite database and create the table if it doesn't exist."""
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                type TEXT,
                input TEXT,
                result TEXT
            )
        ''')
        conn.commit()
        conn.close()

    @staticmethod
    def save_scan(scan_type: str, input_data: str, result_data: dict):
        """Save a new scan result to the database."""
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute('INSERT INTO scans (timestamp, type, input, result) VALUES (?, ?, ?, ?)',
                  (timestamp, scan_type, input_data, json.dumps(result_data)))
        conn.commit()
        conn.close()

    @staticmethod
    def get_recent_scans(limit=10):
        """Retrieve the most recent scans."""
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT * FROM scans ORDER BY id DESC LIMIT ?', (limit,))
        rows = c.fetchall()
        conn.close()
        scans = []
        for row in rows:
            data = dict(row)
            try:
                data['result'] = json.loads(data['result'])
            except:
                data['result'] = {}
            scans.append(data)
        return scans

    @staticmethod
    def get_all_history():
        """Retrieve all scans from the database."""
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT * FROM scans ORDER BY id DESC')
        rows = c.fetchall()
        conn.close()
        scans = []
        for row in rows:
            data = dict(row)
            try:
                data['result'] = json.loads(data['result'])
            except:
                data['result'] = {}
            scans.append(data)
        return scans

    @staticmethod
    def get_scan_by_id(scan_id):
        """Retrieve a specific scan by ID."""
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
        row = c.fetchone()
        conn.close()
        if row:
            data = dict(row)
            # Parse the JSON result back into a dict
            try:
                data['result'] = json.loads(data['result'])
            except:
                data['result'] = {}
            return data
        return None
    
    @staticmethod
    def delete_scans(scan_ids: list):
        """Delete specific records from the database."""
        if not scan_ids:
            return
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        # Use comma separated string for IN clause
        placeholders = ', '.join(['?'] * len(scan_ids))
        query = f'DELETE FROM scans WHERE id IN ({placeholders})'
        c.execute(query, tuple(scan_ids))
        conn.commit()
        conn.close()

    @staticmethod
    def get_history(sector: str = None, limit: int = 100):
        """Retrieve scans with optional sector filtering and proper parameterization."""
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        if sector:
            c.execute('SELECT * FROM scans WHERE type = ? ORDER BY id DESC LIMIT ?', (sector, limit))
        else:
            c.execute('SELECT * FROM scans ORDER BY id DESC LIMIT ?', (limit,))
            
        rows = c.fetchall()
        conn.close()
        
        scans = []
        for row in rows:
            data = dict(row)
            try:
                data['result'] = json.loads(data['result'])
            except:
                data['result'] = {}
            scans.append(data)
        return scans

    @staticmethod
    def clear_history():
        """Delete all records from the database."""
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('DELETE FROM scans')
        conn.commit()
        conn.close()
