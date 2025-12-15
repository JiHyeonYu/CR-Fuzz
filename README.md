# CR-Fuzz
CR-Fuzz is a feedback-driven fuzzing framework designed for robotic vehicles, drones, and IoT devices that communicate through structured binary protocols (e.g., MAVLink, DUML, BLE ATT). It automatically analyzes packet semantics (PSI), generates adaptive mutation strategies, and discovers new system behaviors or crashes in black-box environments.

This implementation includes:

✓ Packet Semantic Interpretation (PSI): Fixed / Specific / Mutable / Dependent field classification

✓ Adaptive byte-level mutation targeting (Feedback Engine)

✓ Dynamic operator scheduling (Mutation Scheduler)

✓ Dependent-field recomputation (length, CRC, checksums, etc.)

✓ Crash detection via windowed binary search (CrashFilter)

✓ UDP and Serial device interfaces

---

# 📦 Installation

```bash
git clone https://github.com/JiHyeonYu/CR-Fuzz.git
cd CR-Fuzz
pip install -r requirements.txt
```

For serial-device fuzzing:

```bash
pip install pyserial
```

---

# 📑 Normal Packet Log (Required)

CR-Fuzz requires a log file containing normal, valid packets.  
This baseline is used for PSI analysis and seed corpus initialization.

Example (`normal_packets.log`):

```bash
fd 01 0a 18 3f 00 12
fd 01 0a 18 40 00 10
```

Supported formats:

- Hex with spaces (`AA BB CC DD`)  
- Raw hex (`AABBCCDD`)  
- Wireshark-style logs (`0000 AA BB CC ...`)  
- Lines beginning with `#` or `//` are ignored  

---

# 🔧 CLI Parameters

Run:

```bash
python CR-Fuzz.py --help
```

## Basic Options

| Option | Description | Default |
|--------|-------------|---------|
| `--log PATH` | Path to normal packet log | `./normal_packets.log` |
| `--mode {udp,serial}` | Device mode | `udp` |
| `--iterations N` | Number of fuzzing inputs | `100000` |
| `--save-interval N` | Save corpus/statistics every N inputs | `1000` |
| `--corpus-dir DIR` | Directory for seed corpus | `./corpus` |
| `--stats-csv FILE` | CSV file for fuzzing statistics | `./fuzz_stats.csv` |
| `--dry-run` | Run logic only (no device I/O) | `False` |

---

## UDP Options

| Option | Description | Default |
|--------|-------------|---------|
| `--udp-ip IP` | Target device IP | `127.0.0.1` |
| `--udp-port PORT` | Target device port | `14550` |
| `--udp-local-ip IP` | Local bind IP | `0.0.0.0` |
| `--udp-local-port PORT` | Local bind port | `0` |

---

## Serial Options

| Option | Description | Default |
|--------|-------------|---------|
| `--serial-port PORT` | Serial port (e.g., COM3) | `COM3` |
| `--baudrate N` | UART baudrate | `115200` |
| `--serial-read-timeout` | Read timeout | `0.1` |
| `--serial-liveness-timeout` | Liveness check timeout | `5.0` |

*Useful for real hardware such as 3DR Solo, IoT devices using UART, etc.*

---

# ▶️ Usage Examples

## 1. Fuzzing via UDP

```bash
python CR_Fuzz.py \
  --mode udp \
  --udp-ip 127.0.0.1 \
  --udp-port 14550 \
  --log normal_packets.log \
  --iterations 200000 \
  --save-interval 1000
```

---

## 2. Fuzzing via Serial Port

```bash
python CR_Fuzz.py \
  --mode serial \
  --serial-port COM3 \
  --baudrate 1500000 \
  --log normal_packets.log \
  --iterations 300000
```

---

## 3. Using the Dummy Device Simulator

```python
from CR_fuzz.py import DummyDeviceInterface, DummyDeviceScenario
```

---

# 🧠 Architecture

CR-Fuzz internally performs the following steps:

1. Load normal packet seeds  
2. Initialize device interface (UDP, Serial, or Dummy)  
3. Run PSI (Packet Semantic Interpretation)  
   - Fixed fields  
   - Specific fields  
   - Mutable fields  
   - Dependent fields  
4. Compute dependent fields (e.g., length, checksum, CRC)   
5. Initialize mutation engines
6. Generate mutated testcases
7. Send to device & receive response  
8. Determine new response via Knowledge Base  
9. Crash detection using windowed binary search  
10. Seed corpus expansion  
11. Periodic stats CSV logging  

---

# 📊 Output Files

| Output | Description |
|--------|-------------|
| `./corpus/` | All seeds (normal, new-response, crash) |
| `index.csv` | Seed metadata |
| `fuzz_stats.csv` | Iteration-by-iteration stats |
| `resp_inputs.log` | Recorded input packets |
| `resp_responses.log` | Recorded output responses |
| `responses.csv` | Full response metadata |

---

# ⚠️ Requirements

- Python ≥ 3.8  
- For serial mode: `pyserial`  
- UDP mode uses standard socket API
- Real device is needed for wire/wireless communication and testing
- Depending on the target device, the dependent field calculation algorithm may need to be added manually
