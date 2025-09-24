# ForensicPro
Browser artifacts extracter,Detection of USB devices &  its activity with Live system analysis,Comparing files,Malware Scanning

**Technologies Used**

This tool uses a QFileDialog to select a file for malware analysis, then passes the file path to `MainWindow.analyze_malware()`.

**Installation and Setup on Kali Linux**

These instructions detail how to install and run this forensic tool on a fresh Kali Linux installation (e.g., Kali 2024.x) with Python 3 and pip.

**Prerequisites**

*   Kali Linux with root/sudo privileges.
*   Internet connection for dependency installation and VirusTotal API access.
*   Valid VirusTotal API key.

**Installation Steps**

1.  **Update System:**
    ```bash
    sudo apt update && sudo apt upgrade -y
    ```
2.  **Install Python and pip:**
    ```bash
    sudo apt install python3 python3-pip -y
    ```
3.  **Install Python Packages:**
    ```bash
    pip3 install PyQt5 matplotlib psutil bcrypt requests reportlab
    ```
4.  **Install System Dependencies:**
    ```bash
    sudo apt install sqlite3 systemd -y
    ```
5.  **Save the Code:** Save the provided Python code as `forensic_tool.py`. Replace the `VIRUSTOTAL_API_KEY` placeholder with your actual VirusTotal API key.
6.  **Set Permissions:**
    ```bash
    chmod +x forensic_tool.py
    ```
7.  **Run the Tool:** Execute the script with root privileges:
    ```bash
    sudo python3 forensic_tool.py
    ```
8.  **Login:** Use the following credentials:
    *   Username: admin
    *   Password: password123

**Post-Installation Notes**

*   **Database:** The tool creates `forensic.db` in the script's directory.
*   **Log File:** Logs are written to `forensictool.log` in the same directory.
*   **Browser Support:** Install Firefox, Google Chrome, or Chromium for browser artifact extraction:
    ```bash
    sudo apt install firefox-esr chromium -y
    ```
*   **VirusTotal API:** Be aware of the VirusTotal API rate limits (e.g., 4 requests/minute) when using a free key. Consider a premium key or handle HTTP 429 errors for heavy usage.

**Troubleshooting**

*   **Permission Errors:** Run the tool with `sudo`.
*   **Missing Dependencies:** Retry installation with:
    ```bash
    pip3 install <package_name> --break-system-packages
    ```
*   **Database Errors:** Ensure write permissions in the script's directory:
    ```bash
    chmod -R 777 .
    ```
*   **API Errors:** Verify your VirusTotal API key and internet connectivity.
*   **GUI Issues:** Ensure X11 or Wayland is running (`startx` if needed).
