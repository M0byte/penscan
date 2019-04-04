# penscan
Python written Portscanner

A Portscanner written in Python for Linux CLI with some cool features.

## Features
- CLI Interface (Click)
- Database (SQLite3)
- PyDoc
- Config File Usage

## Usage 
```python --help```
- Displays the help for further usage

### TCP Example
```python -t -ip <ip> -r 80,443```
- Scans the Target

### SYN ACK Example
```sudo python -s -ip <ip> -r 40-500```
- Stealth-Scans the Target

### Logging Example
```python -l -t -ip <ip> -r <ports>```
- Logs the scan results

### Batch File Example
```python -f <path_to_logfile>```
- Reading the *.ini file

### Printing logged entries
```python -p <count>```
- Printing the last x logged entries
