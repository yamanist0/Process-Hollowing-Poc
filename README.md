<a id="readme-top"></a>

# Process Hollowing PoC

Windows education focused proof of concept that exhibits process hollowing. It creates a suspended process, unmaps its image, maps the PE file chosen in its address space, and resumes its execution. Process hollowing is exhibited in C, C++, and Python, thus this PoC should be relatively easy to explore.

> Suggested GitHub repository name: process-hollowing-poc

[![License: GPL-3.0](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)]()

## Table of Contents

1. [About The Project](#about-the-project)
2. [How Process Hollowing Works](#how-process-hollowing-works)
3. [Defensive Countermeasures](#defensive-countermeasures)
4. [Project Structure](#project-structure)
5. [Getting Started](#getting-started)
6. [Usage](#usage)
7. [Disclaimer](#disclaimer)
8. [License](#license)
9. [Contact](#contact)

## About The Project

Here you will find a proof-of-concept implementation of process hollowing in windows memory-injection technique that you are able to find often discussed in discussions around malwares, endpoint defenses and red teaming techniques. The aim of this work is not for malicious purposes but it aims at making an understandable explanation of how this method is working and how defenders can prevent the method.

The project is intentionally implemented in three languages:

- C: native Win32 API implementation
- C++: same flow using modern C++ and STL
- Python: equivalent behavior through `ctypes` and Windows API calls

All three variations follow the same high level logic: spawn an honest process, put it into suspended mode, overlay a new PE in the place of the old one, and then continue running from the injected entry point.

### Built With

- C and C++ with Windows API calls
- Python with `ctypes`
- PE image manipulation concepts for Windows executables

## How Process Hollowing Works

Process Hollowing This technique starts a valid Windows process in a suspended mode. It replaces the process code from memory, and writes into the process’s space a new executable image before resuming its thread.

The flow is typically:

1. A trusted process, for example, `svchost.exe`, is created as `CREATE_SUSPENDED`.
2. The PEB and image base are obtained from thread context.
3. The original image is unmapped with `NtUnmapViewOfSection`.
4. A desired PE image is read from the disk, parsed and processed.
5. The new image sections and headers are copied in the process at the original image base address.
6. The new PEB base address and the current instructionpointer is updated in the thread context to point on the new entrypoint.
7. The thread is resumed and the injected code is executed.
8. The PE host appears to be a standard process, however the code which is currently running inside is entirely different at runtime.

## Visual Flow Diagrams

### 1. Detailed flowchart


### 2. Long vertical flowchart



## Defensive Countermeasures

Defenders could do well to study process hollowing so that analysts and defenders know how attack malware can appear legitimate within an otherwise innocent process. But generally the most effective way to deal with process hollowing relies on multiple defenses.

### Detection Strategies
- observe for suspicious process parent-child process relationships from process create event types
- monitor for suspicious start processes that are later resumed, with a brief period of suspended process execution.
- examine for memory mapped image updates, which might indicate the creation of a maliciousPE Image.
- leverage endpoint telemetry to observe process module loading for indications of abnormal behavior or suspicious thread context manipulation.
- observe EDR logs for unusual module unmapping or memory writing behaviors which coincide with EDR process data.

### Prevention and Hardening

- Restrict execution rights and use application allowlisting where possible.
- Keep operating systems and security products updated to reduce exposure to known bypasses.
- Enforce code integrity and signed binary validation for critical workloads.
- Reduce the attack surface by limiting the use of high-privilege or broadly trusted processes.
- Apply least-privilege principles so a compromise has fewer opportunities to escalate.

### Behavioral Indicators

- A process that suddenly changes its executable image after startup.
- Unusual memory regions being allocated and written without a matching legitimate loader flow.
- Thread resumes that do not align with the expected application lifecycle.
- Suspicious transitions between benign and malicious code paths within the same process.

### Why This PoC Matters for Defense

This repository is great for learning as it clearly shows defenders precisely what mechanisms need to be understood: Process creation, memory unmapping, PE injection, and thread redirection. Once the steps are understood, it helps the creation of detection logic and incident response playbooks to become more refined.

## Project Structure

- [main.c](main.c) - C implementation of the PoC
- [main.cpp](main.cpp) - C++ implementation of the PoC
- [main.py](main.py) - Python implementation of the PoC
- [README.md](README.md) - project documentation

## Getting Started

### Prerequisites

This project targets Windows systems and uses the Win32 API. A typical setup includes:

- Windows 10 or Windows 11
- A C/C++ compiler such as MSVC or MinGW
- Python 3 for the Python variant

### Build and Run

#### C

```bat
cl /EHsc main.c /link user32.lib Comdlg32.lib
main.exe
```

#### C++

```bat
cl /EHsc main.cpp /link user32.lib Comdlg32.lib
main.exe
```

#### Python

```bat
py main.py
```

## Usage

1. Run the chosen implementation.
2. Confirm the consent prompt.
3. Select a PE executable to inject.
4. Observe the suspended process flow and the resulting execution path.

> Use this project only on systems you own or are explicitly authorized to test. The code is intentionally designed for education and defensive research.

## Disclaimer

The code in this project is intended solely for educational, research and defensive security purposes to help security professionals, malware researchers, and defenders learn how process hollowing works and how it can be detected. 

The author takes no responsibility for misuse, damage or any illegal activity associated with this code and using the provided code on systems or networks without permission is prohibited.

## License

This project is published under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for the full text.

## Contact

For questions, feedback, or collaboration ideas, open an issue or contact the repository maintainer.
