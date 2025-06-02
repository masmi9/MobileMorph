import os
import platform

def get_output_folder():
    home_dir = os.path.expanduser("~")

    # Determine platform-specific Downloads path
    if platform.system() == "Windows":
        downloads_folder = os.path.join(home_dir, "Downloads", "MobileMorph")
    else:
        # Assume Linux/macOS
        downloads_folder = os.path.join(home_dir, "Downloads", "MobileMorph")

    os.makedirs(downloads_folder, exist_ok=True)
    return downloads_folder