"""Print saved scans locally. Prefer the browser history view for everyday use."""
import json
from database import init_db, list_scans
if __name__ == '__main__':
    init_db()
    print(json.dumps(list_scans(), indent=2, ensure_ascii=False))
