from threading import Lock

# In-memory dictionary to hold progress for each file_id
progress_store = {}
lock = Lock()

def update_progress(file_id, percent):
    """Update progress for a specific file ID (0–100)."""
    with lock:
        progress_store[file_id] = int(percent)

def get_progress(file_id):
    """Retrieve progress value (defaults to 0 if not found)."""
    with lock:
        return progress_store.get(file_id, 0)

def reset_progress(file_id):
    """Clear progress for a file ID (optional cleanup)."""
    with lock:
        if file_id in progress_store:
            del progress_store[file_id]
