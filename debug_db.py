import sqlite3
import sys
import os

sys.path.insert(0, os.getcwd())
from aix.db.database import AIXDatabase

db = AIXDatabase()
cursor = db.conn.cursor()

print("--- RESULTS TABLE DUMP ---")
cursor.execute("SELECT id, target, module, technique, payload FROM results")
rows = cursor.fetchall()
for row in rows:
    print(f"ID: {row[0]}, Target: '{row[1]}', Module: '{row[2]}', Tech: '{row[3]}', Payload: '{row[4][:20]}...'")

print(f"Total Rows: {len(rows)}")

# Check for duplicates on (Target, Module, Technique)
from collections import Counter
keys = [(r[1], r[2], r[3]) for r in rows]
counts = Counter(keys)
dupes = [k for k, v in counts.items() if v > 1]

if dupes:
    print(f"[!] FOUND DUPLICATES: {dupes}")
else:
    print("[+] NO DUPLICATES FOUND on (Target, Module, Technique)")
