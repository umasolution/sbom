import os
import hashlib
import xml.etree.ElementTree as ET
import win32api
import datetime

# Create the root element of the XML document
root = ET.Element('wireshark_dlls')

# Iterate over all files in the Wireshark plugins directory
plugins_dir = 'C:/Program Files/Wireshark'
for filename in os.listdir(plugins_dir):
    if filename.endswith('.dll'):
        # Create an element for the current DLL file
        dll_elem = ET.SubElement(root, 'dll', {'filename': filename})

        # Get the file properties and add them as child elements of the DLL element
        full_path = os.path.join(plugins_dir, filename)
        ET.SubElement(dll_elem, 'full_path').text = full_path
        ET.SubElement(dll_elem, 'size').text = str(os.path.getsize(full_path))
        ET.SubElement(dll_elem, 'created_time').text = str(datetime.datetime.fromtimestamp(os.path.getctime(full_path)).strftime('%Y-%m-%d %H:%M:%S'))
        ET.SubElement(dll_elem, 'accessed_time').text = str(datetime.datetime.fromtimestamp(os.path.getmtime(full_path)).strftime('%Y-%m-%d %H:%M:%S'))
        ET.SubElement(dll_elem, 'modified_time').text = str( datetime.datetime.fromtimestamp(os.path.getatime(full_path)).strftime('%Y-%m-%d %H:%M:%S'))

        # Calculate the MD5 hash of the file and add it as a child element of the DLL element
        with open(full_path, 'rb') as f:
            md5_hash = hashlib.md5(f.read()).hexdigest()
        ET.SubElement(dll_elem, 'md5_hash').text = md5_hash

        # Get the file version and add it as a child element of the DLL element (Windows only)
        try:
            info = win32api.GetFileVersionInfo(full_path, '\\')
            version = f"{info['FileVersionMS'] >> 16}.{info['FileVersionMS'] & 0xffff}.{info['FileVersionLS'] >> 16}.{info['FileVersionLS'] & 0xffff}"
            ET.SubElement(dll_elem, 'version').text = version
        except:
            pass

        # Get the file license details (if available) and add them as child elements of the DLL element
        license_path = os.path.join(plugins_dir, f"{filename}.license")
        if os.path.exists(license_path):
            with open(license_path, 'r') as f:
                license_details = f.read()
            ET.SubElement(dll_elem, 'license_details').text = license_details

# Create an ElementTree object and write it to an XML file
tree = ET.ElementTree(root)
tree.write('wireshark_dlls.xml', encoding='utf-8', xml_declaration=True)
