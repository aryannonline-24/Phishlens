from database import init_db, log_scan

init_db()
log_scan("Test message", "http://example.com", 65, "high")
print("Database setup complete and test entry saved.")