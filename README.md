# CR-Fuzz
CR-Fuzz is a feedback-driven fuzzing framework designed for robotic vehicles, drones, and IoT devices that communicate through structured binary protocols (e.g., MAVLink, DUML, BLE ATT). It automatically analyzes packet semantics (PSI), generates adaptive mutation strategies, and discovers new system behaviors or crashes in black-box environments.

This implementation includes:

✓ Packet Semantic Interpretation (PSI): Fixed / Specific / Mutable / Dependent field classification
✓ Adaptive byte-level mutation targeting (Feedback Engine)
✓ Dynamic operator scheduling (Mutation Scheduler)
✓ Crash detection via windowed binary search (CrashFilter)
✓ UDP and Serial device interfaces
✓ Dummy device for simulation without real hardware

Installation
git clone https://github.com/your/repo.git
cd repo
pip install -r requirements.txt


For serial-device fuzzing:

pip install pyserial
