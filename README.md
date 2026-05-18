### 

```markdown
# 🎯 Process Hunt: In-Memory Module & Export Enumerator

> Process Hunt is a C-based memory enumeration tool designed to analyze running Windows processes. It utilizes the Toolhelp32 API to find specific targets, maps their loaded DLLs, and uses `ReadProcessMemory` to extract their Export Directory Tables dynamically into a `.txt` report.

## 📖 About the Project

Process Hunt is a proof-of-concept security tool focused on dynamic memory analysis and module enumeration. Modeled after techniques utilized by malware analysts, game cheat developers, and EDR (Endpoint Detection and Response) systems, it actively interacts with the virtual memory space of live processes. 

By leveraging the Windows API, it parses PE structures directly from RAM, successfully extracting a complete list of exported functions from all loaded DLLs within the target process.

### ✨ Key Features
* **Dynamic Process Enumeration:** Targets and resolves PIDs dynamically based on the executable name.
* **In-Memory PE Parsing:** Reads PE structures (DOS Header, NT Headers, Data Directories) directly from the virtual memory of a live process.
* **Automated Reporting:** Automatically generates and saves a comprehensive `.txt` file (`process_hunt_report.txt`) containing all findings.

## 🚀 Usage

Compile the project and run it via the command line, providing the name of the target process you want to hunt:

```bash
# Example
./hunter.exe explorer.exe