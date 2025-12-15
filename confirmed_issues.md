## Confirmed Issues Corresponding to Previously Reported issues

The following table summarizes devices for which CR-Fuzz discovered crashes
that correspond to previously reported vulnerabilities or public issues.
Since CR-Fuzz operates in a black-box setting, the correspondence is
established based on similarities in externally observable symptoms,
triggering input characteristics, and testing setup conditions such as
device model, firmware lineage, and communication protocol, etc.

| Crash ID | Target Device | Public Identifier / Reference |
|----------|---------------|-------------------------------|
| #3 | Segway Ninebot Mini Pro | [Report](https://www.ioactive.com/wp-content/uploads/pdfs/IOActive-Security-Advisory-Ninebot-Segway-miniPRO_Final.pdf) |
| #4 | DJI Mavic Air 2 | [Research Paper](https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_f217_paper.pdf) |
| #7 | DJI Mavic 3 | CVE-2023-6948 |
| #8 | DJI Mavic 3 | CVE-2023-51452 |
| #9 | 3DR Solo | CVE-2024-38951 |
| #10 | 3DR Solo | [Github Issue](https://github.com/PX4/PX4-Autopilot/issues/18385) |
| #11 | 3DR Solo | [Github Issue](https://github.com/PX4/PX4-Autopilot/issues/18651) |
| #12 | Parrot Mambo | [Github Issue](https://github.com/amymcgovern/pyparrot/issues/135) |
| #13 | Parrot Mambo | [Github Issue](https://github.com/amymcgovern/pyparrot/issues/207) |

The remaining crashes (#1, #2, #5, and #6) do not currently correspond to any
publicly documented vulnerabilities or issue reports. Analysis and vendor
communication for these cases are ongoing, and this table will be updated
accordingly as new information becomes available.
