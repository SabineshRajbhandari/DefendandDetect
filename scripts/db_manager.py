import sqlite3
import os
import sys
import shutil
from datetime import datetime

# Add the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DB_PATH = "history.db"
BACKUP_DIR = "backups"

def backup_db():
    if not os.path.exists(DB_PATH):
        print(f"❌ Error: {DB_PATH} not found.")
        return
    
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
        
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(BACKUP_DIR, f"history_backup_{timestamp}.db")
    
    try:
        shutil.copy2(DB_PATH, backup_file)
        print(f"✅ Database backed up to: {backup_file}")
    except Exception as e:
        print(f"❌ Backup failed: {str(e)}")

def clear_history():
    if not os.path.exists(DB_PATH):
        print("❌ Database does not exist.")
        return
        
    confirm = input("⚠️ Are you sure you want to CLEAR ALL SCAN HISTORY? (y/n): ")
    if confirm.lower() == 'y':
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scans")
            conn.commit()
            conn.close()
            print("✅ All scan history cleared.")
            # Run VACUUM to reduce file size
            conn = sqlite3.connect(DB_PATH)
            conn.execute("VACUUM")
            conn.close()
        except Exception as e:
            print(f"❌ Error clearing history: {str(e)}")
    else:
        print("Operation cancelled.")

def show_stats():
    if not os.path.exists(DB_PATH):
        print("❌ Database does not exist.")
        return
        
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT scan_type, COUNT(*) FROM scans GROUP BY scan_type")
        stats = cursor.fetchall()
        
        print("\n=== Forensic History Stats ===")
        total = 0
        for s_type, count in stats:
            print(f"• {s_type}: {count} scans")
            total += count
        print(f"-----------------------------")
        print(f"Total Forensic Scans: {total}")
        conn.close()
    except Exception as e:
        print(f"❌ Error fetching stats: {str(e)}")

if __name__ == "__main__":
    print("=== Defend & Detect DB Manager ===")
    print("1. Backup Database")
    print("2. Clear Scan History")
    print("3. Show Statistics")
    
    choice = input("\nSelect an option (1-3): ")
    if choice == '1':
        backup_db()
    elif choice == '2':
        clear_history()
    elif choice == '3':
        show_stats()
    else:
        print("Invalid choice.")
