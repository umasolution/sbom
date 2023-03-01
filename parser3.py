import os
import hashlib
import datetime
import json
import win32api

# Set the path to the Wireshark directory
dir_path = "C:/Program Files/Wireshark"

# Define a function to get the file properties
def get_file_properties(file_path):
    file_size = os.path.getsize(file_path)
    file_created = datetime.datetime.fromtimestamp(os.path.getctime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
    file_modified = datetime.datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
    file_accessed = datetime.datetime.fromtimestamp(os.path.getatime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
    file_hash = hashlib.md5(open(file_path, 'rb').read()).hexdigest()
    file_name = os.path.basename(file_path)
    if "libwiretap" in file_name:
        file_license = "GPLv2"
    elif "libwireshark" in file_name:
        file_license = "GPLv2"
    elif "libwsutil" in file_name:
        file_license = "GPLv2"
    else:
        file_license = "Unknown"
    # Get the file version information
    try:
        info = win32api.GetFileVersionInfo(file_path, "\\")
        version = info['FileVersionMS'], info['FileVersionLS']
        version = '.'.join(str(i) for i in version)
    except Exception:
        version = None
    file_properties = {
        "name": file_name,
        "path": file_path,
        "size": file_size,
        "created_date": file_created,
        "modified_date": file_modified,
        "accessed_date": file_accessed,
        "hash_value": file_hash,
        "license": file_license,
        "version": version
    }
    return file_properties

# Loop through all files in the Wireshark directory and its subdirectories
dll_files = []
for root, dirs, files in os.walk(dir_path):
    for file in files:
        if file.endswith(".dll"):
            file_path = os.path.join(root, file)
            file_properties = get_file_properties(file_path)
            dll_files.append(file_properties)

# Write the properties of all DLL files to a JSON file
with open("wireshark_dll_properties.json", "w") as f:
    json.dump(dll_files, f)
