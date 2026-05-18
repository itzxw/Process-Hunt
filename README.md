# 🎯 Process Hunt

A lightweight C tool designed for Windows memory analysis and module enumeration. It searches for an active process by its name, maps all of its loaded DLLs, and dynamically dumps their exported functions directly from RAM into a text file.

## ✨ Features

* **Process Targeting:** Finds the target process dynamically using its executable name.
* **In-Memory Parsing:** Reads PE structures (headers and data directories) straight from live memory using `ReadProcessMemory`.
* **Automated Logging:** Exports the entire list of discovered DLLs and functions into `process_hunt_report.txt`.

## 🚀 How to Run

Compile the project and run it via the command line, providing the name of the target process you want to hunt:

```bash
# Example
./hunter.exe explorer.exe
