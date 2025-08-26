# Cyber Range Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/mdelarosa-cyber/Threat-Hunting-Scenario-Tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects some employees may be using the Tor Browser to bypass network security controls. Recent logs show atypical encrypted traffic and connections to known Tor entry (guard) nodes, and there are anonymous reports of attempts to access restricted sites during work hours. Objective: detect and analyze any Tor usage, assess related security incidents, and recommend mitigations. Action: if Tor usage is confirmed, isolate device and notify management immediately.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "labuser1" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-08-25T17:28:14.7213374Z`. These events began at `2025-08-25T17:11:19.8370144Z`.

**Query used to locate events:**

<img width="894" height="146" alt="DeviceFileEvents" src="https://github.com/user-attachments/assets/f110f044-78db-486c-a8d9-e7c64eadc15c" />

<img width="1127" height="390" alt="DeviceFileEventsResults" src="https://github.com/user-attachments/assets/0ffdafee-c92d-4fc6-a403-c176cae1b19d" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.5.6.exe". Based on the logs returned, at `2025-08-26T15:17:34.508852Z`, an employee on the "marcos-threat-h" device ran the file `tor-browser-windows-x86_64-portable-14.5.6.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

<img width="837" height="85" alt="DeviceProcessEvents_Table" src="https://github.com/user-attachments/assets/ffe245fa-41b7-4fb4-85be-8c22a6775a5a" />

<img width="1189" height="213" alt="DeviceProcessEvents_Table_Results" src="https://github.com/user-attachments/assets/a205ee67-8626-4856-9edc-ae12019abcc2" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "labuser1" actually opened the TOR browser. There was evidence that they did open it at `2025-08-25T17:18:39.2304004Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

<img width="837" height="114" alt="DeviceProcessEvents_TOR_Execution" src="https://github.com/user-attachments/assets/8332f2ff-d033-4afa-9a05-950bd3032762" />

<img width="1165" height="324" alt="DeviceProcessEvents_TOR_Execution_Results" src="https://github.com/user-attachments/assets/c167679a-4458-44dd-8fff-bd2b2abba695" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-08-25T17:18:57.3769454Z`, an employee on the "marcos-threat-h" device successfully established a connection to the remote IP address `80.239.189.76` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\labuser1\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port '443' & '9001'.

**Query used to locate events:**

<img width="1060" height="152" alt="DeviceNetworkEvents" src="https://github.com/user-attachments/assets/ea44c2ca-2030-4526-9707-4bc6f1fb8e63" />

<img width="1214" height="294" alt="DeviceNetworkEvents_Results" src="https://github.com/user-attachments/assets/ab3483e1-400f-4af8-940b-908a6e69bc44" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-08-25T17:11:19.8370144Z`
- **Event:** The user "labuser1" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.6.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\Labuser1\Downloads\tor-browser-windows-x86_64-portable-14.5.6.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-08-25T17:17:59.0691965Z`
- **Event:** The user "labuser1" executed the file `tor-browser-windows-x86_64-portable-14.5.6.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.6.exe /S`
- **File Path:** `C:\Users\Labuser1\Downloads\tor-browser-windows-x86_64-portable-14.5.6.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-08-25T17:18:39.2304004Z`
- **Event:** User 'labuser1' opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\Labuser1\Desktop\Tor Browser\Browser\firefox.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-08-25T17:18:57.3769454Z`
- **Event:** A network connection to IP `80.239.189.76` on port `9001` by user 'labuser1' was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\labuser1\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-08-25T17:18:57.8836595Z` - Connected to `2.56.164.157` on port `443`.
  - `2025-08-26T15:19:05.6171297Z` - Connected to `217.160.247.34` on port `9001`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user 'labuser1' through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-08-25T17:28:14.7213374Z`
- **Event:** The user 'labuser1' created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\Labuser1\Desktop\tor-shopping-list.txt`

---

## Summary

The user 'labuser1' on the "marcos-threat-h" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `marcos-threat-h` by the user `labuser1`. The device was isolated, and the user's direct manager was notified.

---
