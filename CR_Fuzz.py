#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import enum
import logging
import math
import os
import random
import socket
import sys
import time
import csv
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Sequence,
    Tuple,
    Union,
    Any,
)

try:
    import serial  # type: ignore
except ImportError:
    serial = None

@dataclass
class LogConfig:
    log_level: str = "INFO"
    log_file: Optional[str] = None
    log_to_stdout: bool = True

    def init_logging(self) -> None:
        level = getattr(logging, self.log_level.upper(), logging.INFO)
        handlers: List[logging.Handler] = []
        if self.log_to_stdout:
            handlers.append(logging.StreamHandler(sys.stdout))
        if self.log_file:
            handlers.append(logging.FileHandler(self.log_file, encoding="utf-8"))
        logging.basicConfig(
            level=level,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            handlers=handlers or None,
        )


@dataclass
class DeviceConfig:
    mode: str = "udp"  # "serial" or "udp"
    # serial
    serial_port: str = "COM3"
    serial_baudrate: int = 115200
    serial_read_timeout: float = 0.1
    serial_liveness_timeout: float = 5.0
    # udp
    udp_target_ip: str = "127.0.0.1"
    udp_target_port: int = 14550
    udp_local_ip: str = "0.0.0.0"
    udp_local_port: int = 0
    udp_recv_timeout: float = 0.1
    udp_liveness_timeout: float = 5.0


@dataclass
class PSIConfig:
    threshold_specific: int = 4
    test_mutable_samples: int = 3


@dataclass
class FeedbackConfig:
    learning_rate: float = 1.0
    epsilon: float = 0.01
    m_min: int = 1
    m_max_ratio: float = 0.5  # Used when determining m_max as a ratio of the number of mutable elements


@dataclass
class CrashConfig:
    window_size: int = 10_000
    liveness_check_interval: int = 2000
    liveness_timeout: float = 5.0


@dataclass
class FuzzConfig:
    iterations: int = 100_000
    log_path: str = "./normal_packets.log"
    corpus_dir: str = "./corpus"
    stats_csv: str = "./fuzz_stats.csv"
    dry_run: bool = False  # If True, local simulation instead of actual transmission (implementation if necessary)
    save_interval: int = 1000  # Save statistics/seed for each N input

logger = logging.getLogger("cr_fuzz")


class FieldType(enum.Enum):
    FIXED = "fixed"
    SPECIFIC = "specific"
    MUTABLE = "mutable"
    DEPENDENT = "dependent"


@dataclass
class FieldInfo:
    index: int
    field_type: FieldType
    values: List[int] = field(default_factory=list)

    def __repr__(self) -> str:
        if self.field_type in (FieldType.FIXED, FieldType.SPECIFIC):
            return f"<FieldInfo idx={self.index} type={self.field_type.value} values={self.values}>"
        return f"<FieldInfo idx={self.index} type={self.field_type.value}>"


class Packet:

    def __init__(self, data: Union[bytes, bytearray, List[int]]):
        if isinstance(data, (bytes, bytearray)):
            self.data = bytearray(data)
        else:
            self.data = bytearray(data)

    def __len__(self) -> int:
        return len(self.data)

    def copy(self) -> "Packet":
        return Packet(self.data[:])

    def to_bytes(self) -> bytes:
        return bytes(self.data)

    def __getitem__(self, idx: int) -> int:
        return self.data[idx]

    def __setitem__(self, idx: int, value: int) -> None:
        self.data[idx] = value & 0xFF

    def __repr__(self) -> str:
        return "Packet(" + self.data.hex(" ") + ")"


class DeviceInterface:

    def send_and_receive(self, data: bytes) -> Optional[bytes]:
        raise NotImplementedError

    def send_sequence_and_check_crash(self, seq: Iterable[bytes]) -> "CrashResult":
        raise NotImplementedError


class SerialDeviceInterface(DeviceInterface):
    def __init__(
        self,
        port: str,
        baudrate: int = 115200,
        read_timeout: float = 0.1,
        liveness_timeout: float = 5.0,
        liveness_normal_packet: Optional[bytes] = None,
    ):
        if serial is None:
            raise RuntimeError("You need pyserial. Install it with pip install pyserial .")
        self.port = port
        self.baudrate = baudrate
        self.read_timeout = read_timeout
        self.liveness_timeout = liveness_timeout
        self.liveness_normal_packet = liveness_normal_packet

        logger.info("Opening serial port %s (baud=%d)", port, baudrate)
        self.ser = serial.Serial(
            port=port,
            baudrate=baudrate,
            timeout=read_timeout,
        )

    def send_and_receive(self, data: bytes) -> Optional[bytes]:
        try:
            self.ser.write(data)
            self.ser.flush()
        except Exception as e:
            logger.error("Serial write error: %s", e)
            return None

        try:
            resp = self.ser.read(2048)
            if len(resp) == 0:
                return None
            return bytes(resp)
        except Exception as e:
            logger.error("Serial read error: %s", e)
            return None

    def _liveness_check(self) -> bool:
        if self.liveness_normal_packet is None:
            return True

        try:
            self.ser.write(self.liveness_normal_packet)
            self.ser.flush()
        except Exception as e:
            logger.error("Serial write error in liveness_check: %s", e)
            return False

        start = time.time()
        buf = bytearray()
        while time.time() - start < self.liveness_timeout:
            try:
                chunk = self.ser.read(2048)
            except Exception as e:
                logger.error("Serial read error in liveness_check: %s", e)
                return False
            if chunk:
                buf.extend(chunk)
                return True
        return False

    def send_sequence_and_check_crash(self, seq: Iterable[bytes]) -> "CrashResult":
        for data in seq:
            try:
                self.ser.write(data)
            except Exception as e:
                logger.error("Serial write error in sequence: %s", e)
                
        self.ser.flush()

        alive = self._liveness_check()
        if not alive:
            return CrashResult(crashed=True, reason="liveness_failed_during_sequence")
        return CrashResult(crashed=False)


class UDPDeviceInterface(DeviceInterface):
    def __init__(
        self,
        target_ip: str,
        target_port: int,
        local_ip: str = "0.0.0.0",
        local_port: int = 0,
        recv_timeout: float = 0.1,
        liveness_timeout: float = 5.0,
        liveness_normal_packet: Optional[bytes] = None,
    ):
        self.target = (target_ip, target_port)
        self.recv_timeout = recv_timeout
        self.liveness_timeout = liveness_timeout
        self.liveness_normal_packet = liveness_normal_packet

        logger.info(
            "Opening UDP socket local=%s:%d -> target=%s:%d",
            local_ip,
            local_port,
            target_ip,
            target_port,
        )
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((local_ip, local_port))
        self.sock.settimeout(recv_timeout)

    def send_and_receive(self, data: bytes) -> Optional[bytes]:
        try:
            self.sock.sendto(data, self.target)
        except Exception as e:
            logger.error("UDP send error: %s", e)
            return None
        try:
            resp, _ = self.sock.recvfrom(4096)
            return resp
        except socket.timeout:
            return None
        except Exception as e:
            logger.error("UDP recv error: %s", e)
            return None

    def _liveness_check(self) -> bool:
        if self.liveness_normal_packet is None:
            return True
        try:
            self.sock.sendto(self.liveness_normal_packet, self.target)
        except Exception as e:
            logger.error("UDP send error in liveness_check: %s", e)
            return False

        start = time.time()
        while time.time() - start < self.liveness_timeout:
            try:
                resp, _ = self.sock.recvfrom(4096)
                if resp:
                    return True
            except socket.timeout:
                pass
            except Exception as e:
                logger.error("UDP recv error in liveness_check: %s", e)
                return False
        return False

    def send_sequence_and_check_crash(self, seq: Iterable[bytes]) -> "CrashResult":
        for data in seq:
            try:
                self.sock.sendto(data, self.target)
            except Exception as e:
                logger.error("UDP send error in sequence: %s", e)
        alive = self._liveness_check()
        if not alive:
            return CrashResult(crashed=True, reason="liveness_failed_during_sequence")
        return CrashResult(crashed=False)


class LogParser:

    def parse_line(self, line: str) -> Optional[Packet]:
        raise NotImplementedError


class HexWithSpacesParser(LogParser):
    def parse_line(self, line: str) -> Optional[Packet]:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            return None
        tokens = line.split()
        try:
            data = [int(tok, 16) for tok in tokens]
        except ValueError:
            return None
        if not data:
            return None
        return Packet(data)


class RawHexParser(LogParser):

    def parse_line(self, line: str) -> Optional[Packet]:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            return None
        if len(line) % 2 != 0:
            return None
        try:
            raw = bytes.fromhex(line)
        except ValueError:
            return None
        if not raw:
            return None
        return Packet(raw)


class WiresharkStyleParser(LogParser):
    def parse_line(self, line: str) -> Optional[Packet]:
        line = line.strip()
        if not line:
            return None
        if line.startswith("#") or line.startswith("//"):
            return None
        parts = line.split()
        if len(parts) < 2:
            return None
        if all(ch in "0123456789abcdefABCDEF" for ch in parts[0]) and len(parts[0]) <= 4:
            parts = parts[1:]
        tokens = []
        for tok in parts:
            if len(tok) != 2:
                continue
            try:
                tokens.append(int(tok, 16))
            except ValueError:
                continue
        if not tokens:
            return None
        return Packet(tokens)


def detect_log_parser_example(line: str) -> LogParser:
    line = line.strip()
    if not line:
        return HexWithSpacesParser()
    if " " in line or "\t" in line:
        # "AA BB" style or Wireshark style
        parts = line.split()
        if len(parts[0]) == 4 and parts[0].isdigit():
            return WiresharkStyleParser()
        return HexWithSpacesParser()
    else:
        # 공백 없이 raw hex
        return RawHexParser()


def load_normal_packets_from_log(
    log_path: str,
    parser: Optional[LogParser] = None,
) -> List[Packet]:
    path = Path(log_path)
    if not path.is_file():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    packets: List[Packet] = []

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    if not lines:
        raise ValueError("The log file is empty.")

    # parser auto-detect
    if parser is None:
        for line in lines:
            if line.strip() and not line.lstrip().startswith(("#", "//")):
                parser = detect_log_parser_example(line)
                logger.info("Auto-detected log parser: %s", parser.__class__.__name__)
                break
        if parser is None:
            parser = HexWithSpacesParser()

    for line in lines:
        pkt = parser.parse_line(line)
        if pkt is not None:
            packets.append(pkt)

    if not packets:
        raise ValueError(f"No valid packets were read from the log: {log_path}")

    length = len(packets[0])
    filtered = [p for p in packets if len(p) == length]
    dropped = len(packets) - len(filtered)
    if dropped > 0:
        logger.warning(
            "%d ignored (length used = %d bytes).",
            dropped,
            length,
        )
    if not filtered:
        raise ValueError("Length Error")
    logger.info("Total %d normal packets loaded (length=%d bytes).", len(filtered), length)
    return filtered

class PacketSemanticInterpreter:

    def __init__(
        self,
        device: DeviceInterface,
        cfg: PSIConfig,
        is_invalid_response: Optional[Callable[[Optional[bytes]], bool]] = None,
    ):
        self.device = device
        self.cfg = cfg
        self.is_invalid_response = is_invalid_response or (lambda resp: resp is None)
        self.logger = logging.getLogger("cr_fuzz.PSI")

    def classify_fields(self, packets: Sequence[Packet]) -> List[FieldInfo]:
        if not packets:
            raise ValueError("At least one packet is required for PSI.")

        length = len(packets[0])
        for p in packets:
            if len(p) != length:
                raise ValueError("All packets must be of the same length.")

        results: List[FieldInfo] = []

        # 1단계: Frequency-based
        for i in range(length):
            unique_values = set(pkt[i] for pkt in packets)
            if len(unique_values) == 1:
                field_type = FieldType.FIXED
                values = list(unique_values)
            elif 1 < len(unique_values) <= self.cfg.threshold_specific:
                field_type = FieldType.SPECIFIC
                values = sorted(unique_values)
            else:
                field_type = FieldType.MUTABLE
                values = []
            results.append(FieldInfo(index=i, field_type=field_type, values=values))

        self.logger.info("PSI Step 1 Completed: Number of Fields = %d", len(results))
        cnt_fixed = sum(1 for f in results if f.field_type == FieldType.FIXED)
        cnt_spec = sum(1 for f in results if f.field_type == FieldType.SPECIFIC)
        cnt_mut = sum(1 for f in results if f.field_type == FieldType.MUTABLE)
        self.logger.info(
            "Fixed=%d, Specific=%d, Mutable=%d", cnt_fixed, cnt_spec, cnt_mut
        )

        # 2단계: Dependent determination
        max_samples = min(self.cfg.test_mutable_samples, len(packets))
        for field in results:
            if field.field_type != FieldType.MUTABLE:
                continue
            idx = field.index
            is_dep = False
            for j in range(max_samples):
                base = packets[j].copy()
                orig = base[idx]
                new_val = orig
                for _ in range(10):
                    new_val = random.randint(0, 255)
                    if new_val != orig:
                        break
                base[idx] = new_val
                resp = self.device.send_and_receive(base.to_bytes())
                if self.is_invalid_response(resp):
                    is_dep = True
                    break
            if is_dep:
                field.field_type = FieldType.DEPENDENT
                field.values = []
                self.logger.debug("Field %d marked as DEPENDENT", idx)

        cnt_dep = sum(1 for f in results if f.field_type == FieldType.DEPENDENT)
        cnt_mut_after = sum(1 for f in results if f.field_type == FieldType.MUTABLE)
        self.logger.info(
            "PSI Phase 2 Complete: Dependent=%d, Mutable(Remaining)=%d",
            cnt_dep,
            cnt_mut_after,
        )
        return results

class DependentFieldCalculator:
    
    def __init__(self):
        self._calculators: Dict[int, Callable[[Packet], int]] = {}

    def register_calculator(self, idx: int, func: Callable[[Packet], int]) -> None:
        logger.info("Registering dependent calculator at index %d", idx)
        self._calculators[idx] = func

    def apply(self, pkt: Packet) -> None:
        for idx, func in self._calculators.items():
            pkt[idx] = func(pkt) & 0xFF


class DependentFieldPlugin:  
    name: str = "base"

    def register_all(self, calc: DependentFieldCalculator, pkt_len: int) -> None:        
        raise NotImplementedError


class ExampleLengthCrcPlugin(DependentFieldPlugin):   

    name = "example_len_crc"

    @staticmethod
    def calc_length(pkt: Packet) -> int:
        return len(pkt) - 4

    @staticmethod
    def calc_crc(pkt: Packet) -> int:
        end = len(pkt) - 1
        total = 0
        for i in range(end):
            total = (total + pkt[i]) & 0xFF
        return (~total) & 0xFF

    def register_all(self, calc: DependentFieldCalculator, pkt_len: int) -> None:
        calc.register_calculator(2, self.calc_length)
        calc.register_calculator(pkt_len - 1, self.calc_crc)


class ResponseKnowledgeBase:
    """
    Store previous responses and determine if they are new.
    """

    def __init__(self):
        self._seen: set[bytes] = set()

    def is_new(self, resp: Optional[bytes]) -> bool:
        if resp is None:
            return False
        if resp not in self._seen:
            self._seen.add(resp)
            return True
        return False


class ResponseNormalizer:
    
    def __init__(
        self,
        mask_ranges: Optional[List[Tuple[int, int]]] = None,
        zero_ranges: Optional[List[Tuple[int, int]]] = None,
    ):
        """
        :param mask_ranges: (start, end) Only the range survives, the rest is masked with 0x00
        :param zero_ranges: (start, end) The range is overwritten with 0x00
        """
        self.mask_ranges = mask_ranges or []
        self.zero_ranges = zero_ranges or []

    def normalize(self, resp: Optional[bytes]) -> Optional[bytes]:
        if resp is None:
            return None
        b = bytearray(resp)

        # zero_ranges processing
        for s, e in self.zero_ranges:
            e = min(e, len(b))
            s = max(0, s)
            for i in range(s, e):
                b[i] = 0

        if not self.mask_ranges:
            return bytes(b)

        masked = bytearray(len(b))
        for s, e in self.mask_ranges:
            e = min(e, len(b))
            s = max(0, s)
            masked[s:e] = b[s:e]
        return bytes(masked)


class NormalizedResponseKB:
    """
    Knowledge Base combined with ResponseNormalizer.
    """

    def __init__(self, normalizer: ResponseNormalizer):
        self.normalizer = normalizer
        self._seen: set[bytes] = set()

    def is_new(self, resp: Optional[bytes]) -> bool:
        norm = self.normalizer.normalize(resp)
        if norm is None:
            return False
        if norm not in self._seen:
            self._seen.add(norm)
            return True
        return False


class FeedbackEngine:
    """
    Adaptive mutation targeting based on per-byte score.
    """

    def __init__(
        self,
        mutable_indices: List[int],
        cfg: FeedbackConfig,
    ):
        self.mutable_indices = mutable_indices
        self.cfg = cfg
        self.scores: Dict[int, float] = {idx: 1.0 for idx in mutable_indices}
        self.logger = logging.getLogger("cr_fuzz.Feedback")

    def _compute_probabilities(self) -> Dict[int, float]:
        if not self.mutable_indices:
            return {}

        total = sum(self.scores.get(i, 0.0) for i in self.mutable_indices)
        probs: Dict[int, float] = {}
        if total <= 0:
            # uniform distribution
            v = 1.0 / len(self.mutable_indices)
            for idx in self.mutable_indices:
                probs[idx] = v
            return probs

        for idx in self.mutable_indices:
            probs[idx] = (self.scores.get(idx, 0.0) / total) + self.cfg.epsilon

        s = sum(probs.values())
        for idx in probs:
            probs[idx] /= s
        return probs

    def select_mutation_positions(self) -> List[int]:
        if not self.mutable_indices:
            return []

        m_max = max(1, int(len(self.mutable_indices) * self.cfg.m_max_ratio))
        m = random.randint(self.cfg.m_min, max(self.cfg.m_min, m_max))

        probs = self._compute_probabilities()
        indices = list(self.mutable_indices)
        chosen: List[int] = []

        for _ in range(m):
            if not indices:
                break
            r = random.random()
            cum = 0.0
            selected = indices[-1]
            for idx in indices:
                cum += probs.get(idx, 0.0)
                if r <= cum:
                    selected = idx
                    break
            chosen.append(selected)
            indices.remove(selected)
            probs.pop(selected, None)
            # Renormalization
            total = sum(probs.values())
            if total <= 0:
                for idx in indices:
                    probs[idx] = 1.0 / len(indices)
            else:
                for idx in probs:
                    probs[idx] /= total

        return chosen

    def update_scores(self, mutated_indices: List[int], is_new_response: bool) -> None:
        if not is_new_response:
            return
        for idx in mutated_indices:
            if idx in self.scores:
                self.scores[idx] += self.cfg.learning_rate

    def get_scores_snapshot(self) -> Dict[int, float]:
        return dict(self.scores)


class MutationOperator(enum.Enum):
    BIT_FLIP = "bit_flip"
    ARITH = "arith"
    XOR = "xor"
    RANDOM_OVERWRITE = "random_overwrite"
    BYTE_SWAP = "byte_swap"
    SET_BOUNDARY = "set_boundary"  # A set of boundary values ​​such as 0x00, 0xFF, 0x7F, 0x80, etc.


@dataclass
class MutationStats:
    success: int = 0
    tried: int = 0

    @property
    def success_rate(self) -> float:
        if self.tried == 0:
            return 0.0
        return self.success / self.tried


class MutationScheduler:
    """
    Dynamically adjust weights for multiple mutation operators.
    """

    def __init__(self):
        self.stats: Dict[MutationOperator, MutationStats] = {
            op: MutationStats() for op in MutationOperator
        }
        self.logger = logging.getLogger("cr_fuzz.MutationScheduler")

    def choose_operator(self) -> MutationOperator:
        ops = list(MutationOperator)
        weights = []
        for op in ops:
            st = self.stats[op]
            w = st.success_rate + 0.1
            weights.append(w)
        total = sum(weights)
        if total <= 0:
            return random.choice(ops)
        r = random.random() * total
        cum = 0.0
        for op, w in zip(ops, weights):
            cum += w
            if r <= cum:
                return op
        return ops[-1]

    def report_trial(self, used_ops: List[MutationOperator], is_new_response: bool) -> None:
        for op in used_ops:
            st = self.stats[op]
            st.tried += 1
            if is_new_response:
                st.success += 1

    def get_stats_snapshot(self) -> Dict[str, Dict[str, float]]:
        snap: Dict[str, Dict[str, float]] = {}
        for op, st in self.stats.items():
            snap[op.value] = {
                "success": st.success,
                "tried": st.tried,
                "success_rate": st.success_rate,
            }
        return snap


class TestcaseGenerator:
    """
    Create a test case using PSI results + DependentFieldCalculator + FeedbackEngine + MutationScheduler.
    """

    def __init__(
        self,
        psi_results: List[FieldInfo],
        dep_calc: DependentFieldCalculator,
        feedback_engine: FeedbackEngine,
        scheduler: MutationScheduler,
    ):
        self.psi_results = psi_results
        self.dep_calc = dep_calc
        self.feedback_engine = feedback_engine
        self.scheduler = scheduler

        self.fixed_indices = [f.index for f in psi_results if f.field_type == FieldType.FIXED]
        self.specific_fields = [f for f in psi_results if f.field_type == FieldType.SPECIFIC]
        self.mutable_indices = [f.index for f in psi_results if f.field_type == FieldType.MUTABLE]
        self.dependent_indices = [f.index for f in psi_results if f.field_type == FieldType.DEPENDENT]

        self.logger = logging.getLogger("cr_fuzz.TestcaseGen")

    def _apply_specific_fields(self, pkt: Packet) -> None:
        for f in self.specific_fields:
            if not f.values:
                continue
            # 50% 확률로만 변경
            if random.random() < 0.5:
                pkt[f.index] = random.choice(f.values)

    def _mutate_byte(self, pkt: Packet, idx: int, op: MutationOperator) -> None:
        if op == MutationOperator.BIT_FLIP:
            bit = 1 << random.randint(0, 7)
            pkt[idx] = pkt[idx] ^ bit

        elif op == MutationOperator.ARITH:
            delta = random.choice([-4, -1, 1, 4])
            pkt[idx] = (pkt[idx] + delta) & 0xFF

        elif op == MutationOperator.XOR:
            mask = random.randint(1, 255)
            pkt[idx] = pkt[idx] ^ mask

        elif op == MutationOperator.RANDOM_OVERWRITE:
            pkt[idx] = random.randint(0, 255)

        elif op == MutationOperator.BYTE_SWAP:
            candidates = [m for m in self.mutable_indices if m != idx]
            if candidates:
                j = random.choice(candidates)
                pkt[idx], pkt[j] = pkt[j], pkt[idx]

        elif op == MutationOperator.SET_BOUNDARY:
            pkt[idx] = random.choice([0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF])

    def generate_from_seed(self, seed: Packet) -> Tuple[Packet, List[int], List[MutationOperator]]:
        pkt = seed.copy()
        # Specific field processing
        self._apply_specific_fields(pkt)

        # Mutable field processing
        mutated_indices = self.feedback_engine.select_mutation_positions()
        used_ops: List[MutationOperator] = []
        for idx in mutated_indices:
            op = self.scheduler.choose_operator()
            used_ops.append(op)
            self._mutate_byte(pkt, idx, op)

        # Dependent field recompution
        self.dep_calc.apply(pkt)

        return pkt, mutated_indices, used_ops


@dataclass
class CrashResult:
    crashed: bool
    reason: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)


class CrashFilter:
    """
    Algorithm 2: Crash-Inducing Input Filtering using binary search.
    """

    def __init__(
        self,
        window_size: int,
        transmit_sequence: Callable[[Iterable[bytes]], CrashResult],
    ):
        self.window_size = window_size
        self.transmit_sequence = transmit_sequence
        self.buffer: List[bytes] = []
        self.logger = logging.getLogger("cr_fuzz.CrashFilter")

    def append_input(self, data: bytes) -> None:
        self.buffer.append(data)
        if len(self.buffer) > self.window_size:
            self.buffer.pop(0)

    def locate_crash_inducing_input(self) -> Optional[bytes]:
        if not self.buffer:
            return None
        lower = 0
        upper = len(self.buffer) - 1

        while upper - lower > 0:
            mid = (lower + upper) // 2
            res_a = self.transmit_sequence(self.buffer[lower : mid + 1])
            if res_a.crashed:
                upper = mid
                continue
            res_b = self.transmit_sequence(self.buffer[mid + 1 : upper + 1])
            if res_b.crashed:
                lower = mid + 1
                continue
            # 둘 다 crash가 아니면 false positive
            self.logger.warning("CrashFilter: Reproducibility failed (false positive suspected)")
            return None

        return self.buffer[lower]


class LivenessChecker:
    """
    A simple liveness checker that can be hooked into every input in the CRFuzz.fuzz loop.
    """

    def __init__(
        self,
        device: DeviceInterface,
        normal_packet: bytes,
        timeout_sec: float,
        check_interval: int,
    ):
        self.device = device
        self.normal_packet = normal_packet
        self.timeout_sec = timeout_sec
        self.check_interval = check_interval
        self._counter = 0
        self.logger = logging.getLogger("cr_fuzz.Liveness")

    def on_input_sent(self) -> Optional[CrashResult]:
        self._counter += 1
        if self._counter % self.check_interval != 0:
            return None

        start = time.time()
        resp = self.device.send_and_receive(self.normal_packet)
        elapsed = time.time() - start
        if resp is None or elapsed > self.timeout_sec:
            self.logger.warning(
                "Liveness timeout: resp=%s, elapsed=%.3f", resp, elapsed
            )
            return CrashResult(
                crashed=True,
                reason="liveness_timeout",
                detail={"elapsed": elapsed},
            )
        return None


@dataclass
class SeedInfo:
    data: bytes
    source: str  # "log", "new_response", "crash"
    timestamp: float
    note: str = ""


class SeedCorpusManager:
    """
    seed corpus management: normal/log seed + interesting/new/crash seed store/load.
    """

    def __init__(self, corpus_dir: str):
        self.corpus_dir = Path(corpus_dir)
        self.corpus_dir.mkdir(parents=True, exist_ok=True)
        self.seeds: List[SeedInfo] = []
        self.logger = logging.getLogger("cr_fuzz.SeedCorpus")

    def add_seed(self, data: bytes, source: str, note: str = "") -> None:
        info = SeedInfo(
            data=data,
            source=source,
            timestamp=time.time(),
            note=note,
        )
        self.seeds.append(info)

    def random_seed(self) -> Optional[Packet]:
        if not self.seeds:
            return None
        info = random.choice(self.seeds)
        return Packet(info.data)

    def save_to_disk(self) -> None:
        # Simply: save each seed to a file + manage index csv
        index_file = self.corpus_dir / "index.csv"
        with index_file.open("w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["filename", "source", "timestamp", "note"])
            for i, s in enumerate(self.seeds):
                fname = f"seed_{i:06d}.bin"
                path = self.corpus_dir / fname
                with path.open("wb") as f:
                    f.write(s.data)
                writer.writerow([fname, s.source, s.timestamp, s.note])
        self.logger.info("Saved %d seeds to %s", len(self.seeds), self.corpus_dir)


@dataclass
class RunStats:
    total_inputs: int = 0
    new_responses: int = 0
    crashes: int = 0
    start_time: float = field(default_factory=time.time)
    last_report_time: float = field(default_factory=time.time)

    def record_input(self) -> None:
        self.total_inputs += 1

    def record_new_response(self) -> None:
        self.new_responses += 1

    def record_crash(self) -> None:
        self.crashes += 1

    def elapsed(self) -> float:
        return time.time() - self.start_time

    def inputs_per_sec(self) -> float:
        t = self.elapsed()
        return self.total_inputs / t if t > 0 else 0.0

    def summary_dict(self) -> Dict[str, Any]:
        return {
            "total_inputs": self.total_inputs,
            "new_responses": self.new_responses,
            "crashes": self.crashes,
            "elapsed_sec": self.elapsed(),
            "inputs_per_sec": self.inputs_per_sec(),
        }


class StatsLogger:
    """
    Periodically log RunStats and Mutation/Feedback status to CSV.
    """

    def __init__(self, csv_path: str):
        self.csv_path = Path(csv_path)
        self.csv_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialized = False
        self.logger = logging.getLogger("cr_fuzz.StatsLogger")

    def log(
        self,
        iteration: int,
        stats: RunStats,
        mutation_snapshot: Dict[str, Dict[str, float]],
        feedback_snapshot: Dict[int, float],
    ) -> None:
        header = [
            "iteration",
            "total_inputs",
            "new_responses",
            "crashes",
            "elapsed_sec",
            "inputs_per_sec",
            "mutation_json",
            "feedback_json",
        ]
        import json

        row = [
            iteration,
            stats.total_inputs,
            stats.new_responses,
            stats.crashes,
            stats.elapsed(),
            stats.inputs_per_sec(),
            json.dumps(mutation_snapshot, ensure_ascii=False),
            json.dumps(feedback_snapshot, ensure_ascii=False),
        ]
        mode = "a"
        if not self._initialized or not self.csv_path.exists():
            mode = "w"
        with self.csv_path.open(mode, newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if mode == "w":
                writer.writerow(header)
                self._initialized = True
            writer.writerow(row)
        self.logger.debug("Stats logged at iteration %d", iteration)

class CRFuzz:

    def __init__(
        self,
        device: DeviceInterface,
        normal_packets: List[Packet],
        dep_calc: DependentFieldCalculator,
        psi_cfg: PSIConfig,
        fb_cfg: FeedbackConfig,
        crash_cfg: CrashConfig,
        resp_kb: Union[ResponseKnowledgeBase, NormalizedResponseKB],
        corpus_mgr: SeedCorpusManager,
        stats_logger: Optional[StatsLogger] = None,
        is_invalid_response: Optional[Callable[[Optional[bytes]], bool]] = None,
    ):
        self.device = device
        self.normal_packets = normal_packets
        self.dep_calc = dep_calc
        self.psi_cfg = psi_cfg
        self.fb_cfg = fb_cfg
        self.crash_cfg = crash_cfg
        self.resp_kb = resp_kb
        self.corpus_mgr = corpus_mgr
        self.stats_logger = stats_logger
        self.is_invalid_response = is_invalid_response or (lambda resp: resp is None)

        self.logger = logging.getLogger("cr_fuzz.CRFuzz")

        # Registering initial normal seeds in the seed corpus
        for p in normal_packets:
            self.corpus_mgr.add_seed(p.to_bytes(), source="log", note="normal")

        # PSI
        self.logger.info("Running PSI...")
        self.psi = PacketSemanticInterpreter(
            device=device,
            cfg=psi_cfg,
            is_invalid_response=self.is_invalid_response,
        )
        self.psi_results = self.psi.classify_fields(normal_packets)
        mutable_indices = [f.index for f in self.psi_results if f.field_type == FieldType.MUTABLE]

        self.feedback_engine = FeedbackEngine(mutable_indices=mutable_indices, cfg=fb_cfg)
        self.scheduler = MutationScheduler()
        self.testcase_gen = TestcaseGenerator(
            psi_results=self.psi_results,
            dep_calc=dep_calc,
            feedback_engine=self.feedback_engine,
            scheduler=self.scheduler,
        )

        self.crash_filter = CrashFilter(
            window_size=crash_cfg.window_size,
            transmit_sequence=self.device.send_sequence_and_check_crash,
        )

        self.stats = RunStats()

    def fuzz(
        self,
        iterations: int,
        save_interval: int,
        liveness_checker: Optional[LivenessChecker] = None,
        on_new_response: Optional[Callable[[bytes, bytes], None]] = None,
        on_crash_found: Optional[Callable[[bytes, CrashResult], None]] = None,
    ) -> None:
        if not self.corpus_mgr.seeds:
            raise RuntimeError("Seed corpus is empty.")

        for i in range(1, iterations + 1):
            seed_pkt = self.corpus_mgr.random_seed()
            if seed_pkt is None:
                raise RuntimeError("Failed to retrieve seed from seed corpus.")
            testcase, mutated_indices, used_ops = self.testcase_gen.generate_from_seed(seed_pkt)
            data = testcase.to_bytes()

            resp = self.device.send_and_receive(data)
            self.crash_filter.append_input(data)
            self.stats.record_input()

            is_new = self.resp_kb.is_new(resp)
            if is_new and resp is not None:
                self.stats.record_new_response()
                self.feedback_engine.update_scores(mutated_indices, True)
                self.scheduler.report_trial(used_ops, True)
                # Promote new response to seed
                self.corpus_mgr.add_seed(data, source="new_response")
                if on_new_response:
                    on_new_response(data, resp)
            else:
                self.feedback_engine.update_scores(mutated_indices, False)
                self.scheduler.report_trial(used_ops, False)

            if liveness_checker is not None:
                crash_res = liveness_checker.on_input_sent()
                if crash_res and crash_res.crashed:
                    self.stats.record_crash()
                    crash_input = self.crash_filter.locate_crash_inducing_input()
                    if crash_input is not None:
                        self.corpus_mgr.add_seed(
                            crash_input, source="crash", note=crash_res.reason
                        )
                        if on_crash_found:
                            on_crash_found(crash_input, crash_res)

            # Periodically save/record statistics
            if save_interval > 0 and i % save_interval == 0:
                self.logger.info(
                    "Iteration %d: inputs=%d, new_responses=%d, crashes=%d, ips=%.2f",
                    i,
                    self.stats.total_inputs,
                    self.stats.new_responses,
                    self.stats.crashes,
                    self.stats.inputs_per_sec(),
                )
                self.corpus_mgr.save_to_disk()
                if self.stats_logger:
                    self.stats_logger.log(
                        iteration=i,
                        stats=self.stats,
                        mutation_snapshot=self.scheduler.get_stats_snapshot(),
                        feedback_snapshot=self.feedback_engine.get_scores_snapshot(),
                    )


def build_device(
    cfg: DeviceConfig,
    normal_packet_bytes: bytes,
) -> DeviceInterface:
    if cfg.mode == "serial":
        if serial is None:
            raise RuntimeError("Serial mode cannot be used because pyserial is not installed.")
        dev = SerialDeviceInterface(
            port=cfg.serial_port,
            baudrate=cfg.serial_baudrate,
            read_timeout=cfg.serial_read_timeout,
            liveness_timeout=cfg.serial_liveness_timeout,
            liveness_normal_packet=normal_packet_bytes,
        )
        return dev
    elif cfg.mode == "udp":
        dev = UDPDeviceInterface(
            target_ip=cfg.udp_target_ip,
            target_port=cfg.udp_target_port,
            local_ip=cfg.udp_local_ip,
            local_port=cfg.udp_local_port,
            recv_timeout=cfg.udp_recv_timeout,
            liveness_timeout=cfg.udp_liveness_timeout,
            liveness_normal_packet=normal_packet_bytes,
        )
        return dev
    else:
        raise ValueError(f"Unknown device mode: {cfg.mode}")


def default_invalid_response(resp: Optional[bytes]) -> bool:
    if resp is None:
        return True
    if len(resp) < 3:
        return True
    return False


def build_example_dep_calc(pkt_len: int) -> DependentFieldCalculator:
    dep_calc = DependentFieldCalculator()
    plugin = ExampleLengthCrcPlugin()
    plugin.register_all(dep_calc, pkt_len=pkt_len)
    return dep_calc


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="CR-Fuzz extended Python implementation",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--log", dest="log_path", default="./normal_packets.log", help=".log file path")
    p.add_argument("--mode", choices=["serial", "udp"], default="udp", help="Device mode")
    p.add_argument("--serial-port", default="COM3", help="Serial port name")
    p.add_argument("--baudrate", type=int, default=115200, help="Serial baudrate")
    p.add_argument("--udp-ip", dest="udp_ip", default="127.0.0.1", help="UDP target IP")
    p.add_argument("--udp-port", dest="udp_port", type=int, default=14550, help="UDP target port")
    p.add_argument("--iterations", type=int, default=100000, help="fuzzing iteration")
    p.add_argument("--save-interval", type=int, default=1000, help="seed/statistics save cycle")
    p.add_argument("--corpus-dir", default="./corpus", help="seed corpus directory")
    p.add_argument("--stats-csv", default="./fuzz_stats.csv", help="statistics CSV file path")
    p.add_argument("--log-level", default="INFO", help="Log level (DEBUG/INFO/WARN/ERROR)")
    p.add_argument("--log-file", default=None, help="Log file path")
    p.add_argument("--dry-run", action="store_true", help="TODO")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)
    log_cfg = LogConfig(log_level=args.log_level, log_file=args.log_file)
    log_cfg.init_logging()

    logger.info("CR-Fuzz extended start")

    fuzz_cfg = FuzzConfig(
        iterations=args.iterations,
        log_path=args.log_path,
        corpus_dir=args.corpus_dir,
        stats_csv=args.stats_csv,
        dry_run=args.dry_run,
        save_interval=args.save_interval,
    )

    dev_cfg = DeviceConfig(
        mode=args.mode,
        serial_port=args.serial_port,
        serial_baudrate=args.baudrate,
        udp_target_ip=args.udp_ip,
        udp_target_port=args.udp_port,
    )

    # 1) Normal packet loading
    normal_packets = load_normal_packets_from_log(fuzz_cfg.log_path)
    normal_packet_bytes = normal_packets[0].to_bytes()

    # 2) Device interface
    device = build_device(dev_cfg, normal_packet_bytes=normal_packet_bytes)

    # 3) DependentFieldCalculator
    pkt_len = len(normal_packets[0])
    dep_calc = build_example_dep_calc(pkt_len=pkt_len)

    # 4) PSI/Feedback/Crash configuration
    psi_cfg = PSIConfig()
    fb_cfg = FeedbackConfig()
    crash_cfg = CrashConfig(
        window_size=10_000,
        liveness_check_interval=2000,
        liveness_timeout=5.0,
    )

    # 5) Response KB
    resp_kb = ResponseKnowledgeBase()
    # if necessary:
    # normalizer = ResponseNormalizer(mask_ranges=[(0, 16)], zero_ranges=[(4, 8)])
    # resp_kb = NormalizedResponseKB(normalizer)

    # 6) Seed corpus + Stats logger
    corpus_mgr = SeedCorpusManager(corpus_dir=fuzz_cfg.corpus_dir)
    stats_logger = StatsLogger(csv_path=fuzz_cfg.stats_csv)

    # 7) CRFuzz instance
    fuzzer = CRFuzz(
        device=device,
        normal_packets=normal_packets,
        dep_calc=dep_calc,
        psi_cfg=psi_cfg,
        fb_cfg=fb_cfg,
        crash_cfg=crash_cfg,
        resp_kb=resp_kb,
        corpus_mgr=corpus_mgr,
        stats_logger=stats_logger,
        is_invalid_response=default_invalid_response,
    )

    # 8) LivenessChecker
    live_checker = LivenessChecker(
        device=device,
        normal_packet=normal_packet_bytes,
        timeout_sec=crash_cfg.liveness_timeout,
        check_interval=crash_cfg.liveness_check_interval,
    )

    # 9) callback definition
    def on_new_response(inp: bytes, resp: bytes) -> None:
        logger.info(
            "[NEW RESPONSE] input_len=%d, resp_len=%d",
            len(inp),
            len(resp),
        )

    def on_crash(inp: bytes, crash_res: CrashResult) -> None:
        logger.error("[CRASH] reason=%s, input_len=%d", crash_res.reason, len(inp))

    # 10) fuzzing start
    fuzzer.fuzz(
        iterations=fuzz_cfg.iterations,
        save_interval=fuzz_cfg.save_interval,
        liveness_checker=live_checker,
        on_new_response=on_new_response,
        on_crash_found=on_crash,
    )

    logger.info(
        "CR-Fuzz end: total_inputs=%d, new_responses=%d, crashes=%d, ips=%.2f",
        fuzzer.stats.total_inputs,
        fuzzer.stats.new_responses,
        fuzzer.stats.crashes,
        fuzzer.stats.inputs_per_sec(),
    )


if __name__ == "__main__":
    main()
	
# ============================================================
# 12. Simulation / Dry-Run Device
# ============================================================

class DummyCrashPattern(enum.Enum):
    NONE = "none"
    RANDOM = "random"
    PERIODIC = "periodic"
    THRESHOLD = "threshold"


@dataclass
class DummyDeviceScenario:
    """
    Define scenarios to use in the DummyDeviceInterface.

    - base_response: Default response pattern (any length or value)
    - noise_prob: Probability of mixing random noise
    - new_response_prob: Probability of generating a completely new response
    - crash_pattern: Crash pattern (NONE/RANDOM/PERIODIC/THRESHOLD)
    - crash_period: When periodic, how many inputs will cause a crash simulation
    - crash_threshold: When THRESHOLD, a crash will occur if the input length exceeds this value
    """

    base_response: bytes = b"\x00\x01\x02\x03"
    noise_prob: float = 0.05
    new_response_prob: float = 0.1
    crash_pattern: DummyCrashPattern = DummyCrashPattern.NONE
    crash_period: int = 5000
    crash_threshold: int = 128


class DummyDeviceInterface(DeviceInterface):
    """
    A dummy device used to dry-test the entire CRFuzz pipeline without actual equipment.

    - send_and_receive: Returns a slightly modified response based on the input.    
    - send_sequence_and_check_crash: Returns crash results according to the DummyCrashPattern.
    """

    def __init__(self, scenario: Optional[DummyDeviceScenario] = None):
        self.scenario = scenario or DummyDeviceScenario()
        self.counter = 0
        self.logger = logging.getLogger("cr_fuzz.DummyDevice")

    def _generate_base_response(self, data: bytes) -> bytes:
        """
        Basic response generation logic.
        - Mix the input length/some bytes and merge them into base_response.
        """
        base = bytearray(self.scenario.base_response)
        if not data:
            return bytes(base)

        # XOR the first 4 bytes of input with base_response
        for i in range(min(4, len(base), len(data))):
            base[i] ^= data[i]

        # Add a little length information
        if len(base) < 6:
            base.extend(b"\x00" * (6 - len(base)))
        base[4] = len(data) & 0xFF
        base[5] = (len(data) >> 8) & 0xFF

        return bytes(base)

    def _add_noise(self, resp: bytes) -> bytes:
        """
        Slightly break up the response according to noise_prob.
        """
        if random.random() > self.scenario.noise_prob:
            return resp
        b = bytearray(resp)
        # One or two random locations noise
        for _ in range(random.randint(1, 2)):
            idx = random.randint(0, len(b) - 1)
            b[idx] ^= random.randint(1, 255)
        return bytes(b)

    def _maybe_new_response(self, resp: bytes) -> bytes:
        """
        Generates a completely random new response with a certain probability.
        """
        if random.random() > self.scenario.new_response_prob:
            return resp
        length = max(4, len(resp))
        return bytes(random.getrandbits(8) for _ in range(length))

    def send_and_receive(self, data: bytes) -> Optional[bytes]:
        self.counter += 1
        # Simulates "no response" with very low probability
        if random.random() < 0.01:
            return None
        resp = self._generate_base_response(data)
        resp = self._add_noise(resp)
        resp = self._maybe_new_response(resp)
        return resp

    def send_sequence_and_check_crash(self, seq: Iterable[bytes]) -> CrashResult:
        """
        Crash detection based on the DummyCrashPattern.
        - RANDOM: Crash with a certain probability.
        - PERIODIC: Crash after every N transmissions.
        - THRESHOLD: Crash if any input exceeds the threshold length.
        """
        crashed = False
        reason = ""
        detail: Dict[str, Any] = {}

        if self.scenario.crash_pattern == DummyCrashPattern.NONE:
            return CrashResult(crashed=False)

        if self.scenario.crash_pattern == DummyCrashPattern.RANDOM:
            for d in seq:
                if random.random() < 0.0005:  # Very low probability
                    crashed = True
                    reason = "dummy_random"
                    detail = {"input_len": len(d)}
                    break

        elif self.scenario.crash_pattern == DummyCrashPattern.PERIODIC:
            # Increment counter by the length of seq
            for d in seq:
                self.counter += 1
            if self.counter % self.scenario.crash_period == 0:
                crashed = True
                reason = "dummy_periodic"
                detail = {"counter": self.counter}

        elif self.scenario.crash_pattern == DummyCrashPattern.THRESHOLD:
            for d in seq:
                if len(d) >= self.scenario.crash_threshold:
                    crashed = True
                    reason = "dummy_threshold"
                    detail = {"input_len": len(d)}
                    break

        return CrashResult(crashed=crashed, reason=reason, detail=detail)

@dataclass
class FuzzCampaignConfig:
    device: DeviceConfig
    fuzz: FuzzConfig
    psi: PSIConfig = field(default_factory=PSIConfig)
    feedback: FeedbackConfig = field(default_factory=FeedbackConfig)
    crash: CrashConfig = field(default_factory=CrashConfig)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "FuzzCampaignConfig":
        """
        dict structure example:

        {
          "device": {
            "mode": "udp",
            "serial_port": "COM3",
            "serial_baudrate": 115200,
            ...
          },
          "fuzz": {
            "iterations": 100000,
            "log_path": "./normal_packets.log",
            ...
          },
          "psi": {
            "threshold_specific": 4,
            "test_mutable_samples": 3
          },
          "feedback": {
            "learning_rate": 1.0,
            "epsilon": 0.01,
            ...
          },
          "crash": {
            "window_size": 10000,
            "liveness_check_interval": 2000,
            ...
          }
        }
        """
        dev_cfg = DeviceConfig(
            mode=d.get("device", {}).get("mode", "udp"),
            serial_port=d.get("device", {}).get("serial_port", "COM3"),
            serial_baudrate=d.get("device", {}).get("serial_baudrate", 115200),
            serial_read_timeout=d.get("device", {}).get("serial_read_timeout", 0.1),
            serial_liveness_timeout=d.get("device", {}).get("serial_liveness_timeout", 5.0),
            udp_target_ip=d.get("device", {}).get("udp_target_ip", "127.0.0.1"),
            udp_target_port=d.get("device", {}).get("udp_target_port", 14550),
            udp_local_ip=d.get("device", {}).get("udp_local_ip", "0.0.0.0"),
            udp_local_port=d.get("device", {}).get("udp_local_port", 0),
            udp_recv_timeout=d.get("device", {}).get("udp_recv_timeout", 0.1),
            udp_liveness_timeout=d.get("device", {}).get("udp_liveness_timeout", 5.0),
        )

        fuzz_cfg = FuzzConfig(
            iterations=d.get("fuzz", {}).get("iterations", 100000),
            log_path=d.get("fuzz", {}).get("log_path", "./normal_packets.log"),
            corpus_dir=d.get("fuzz", {}).get("corpus_dir", "./corpus"),
            stats_csv=d.get("fuzz", {}).get("stats_csv", "./fuzz_stats.csv"),
            dry_run=d.get("fuzz", {}).get("dry_run", False),
            save_interval=d.get("fuzz", {}).get("save_interval", 1000),
        )

        psi_cfg = PSIConfig(
            threshold_specific=d.get("psi", {}).get("threshold_specific", 4),
            test_mutable_samples=d.get("psi", {}).get("test_mutable_samples", 3),
        )
        fb_cfg = FeedbackConfig(
            learning_rate=d.get("feedback", {}).get("learning_rate", 1.0),
            epsilon=d.get("feedback", {}).get("epsilon", 0.01),
            m_min=d.get("feedback", {}).get("m_min", 1),
            m_max_ratio=d.get("feedback", {}).get("m_max_ratio", 0.5),
        )
        crash_cfg = CrashConfig(
            window_size=d.get("crash", {}).get("window_size", 10000),
            liveness_check_interval=d.get("crash", {}).get("liveness_check_interval", 2000),
            liveness_timeout=d.get("crash", {}).get("liveness_timeout", 5.0),
        )

        return FuzzCampaignConfig(
            device=dev_cfg,
            fuzz=fuzz_cfg,
            psi=psi_cfg,
            feedback=fb_cfg,
            crash=crash_cfg,
        )

    @staticmethod
    def from_json_file(path: str) -> "FuzzCampaignConfig":
        import json

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return FuzzCampaignConfig.from_dict(data)

@dataclass
class ResponseRecord:
    input_data: bytes
    response_data: Optional[bytes]
    is_new: bool
    timestamp: float
    note: str = ""


class ResponseRecorder:    

    def __init__(self, max_records: int = 50_000):
        self.max_records = max_records
        self.records: List[ResponseRecord] = []
        self.logger = logging.getLogger("cr_fuzz.ResponseRecorder")

    def record(self, inp: bytes, resp: Optional[bytes], is_new: bool, note: str = "") -> None:
        if len(self.records) >= self.max_records:            
            self.records.pop(0)
        self.records.append(
            ResponseRecord(
                input_data=inp,
                response_data=resp,
                is_new=is_new,
                timestamp=time.time(),
                note=note,
            )
        )

    def save_as_log(self, dir_path: str, prefix: str = "resp") -> None:
        path = Path(dir_path)
        path.mkdir(parents=True, exist_ok=True)
        in_log = path / f"{prefix}_inputs.log"
        out_log = path / f"{prefix}_responses.log"

        with in_log.open("w", encoding="utf-8") as fin, out_log.open("w", encoding="utf-8") as fout:
            for rec in self.records:
                fin.write(rec.input_data.hex(" ") + "\n")
                if rec.response_data is not None:
                    fout.write(rec.response_data.hex(" ") + "\n")
                else:
                    fout.write("NONE\n")
        self.logger.info(
            "Saved %d response records to %s (inputs) and %s (responses)",
            len(self.records),
            in_log,
            out_log,
        )

    def save_as_csv(self, csv_path: str) -> None:
        path = Path(csv_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                ["timestamp", "is_new", "note", "input_len", "input_hex", "resp_len", "resp_hex"]
            )
            for rec in self.records:
                resp_len = len(rec.response_data) if rec.response_data is not None else 0
                resp_hex = rec.response_data.hex(" ") if rec.response_data is not None else "NONE"
                writer.writerow(
                    [
                        rec.timestamp,
                        int(rec.is_new),
                        rec.note,
                        len(rec.input_data),
                        rec.input_data.hex(" "),
                        resp_len,
                        resp_hex,
                    ]
                )
        self.logger.info("Saved response metadata CSV to %s", path)


class ReplayEngine:
   

    def __init__(self, device: DeviceInterface):
        self.device = device
        self.logger = logging.getLogger("cr_fuzz.ReplayEngine")

    def replay_inputs(
        self,
        inputs: List[bytes],
        delay_sec: float = 0.0,
        max_count: Optional[int] = None,
    ) -> List[Optional[bytes]]:       
        responses: List[Optional[bytes]] = []
        count = 0
        for d in inputs:
            if max_count is not None and count >= max_count:
                break
            resp = self.device.send_and_receive(d)
            responses.append(resp)
            count += 1
            if delay_sec > 0:
                time.sleep(delay_sec)
        self.logger.info("Replayed %d inputs", count)
        return responses

    def replay_and_check_crash(
        self,
        inputs: List[bytes],
        crash_detector: Optional[Callable[[], bool]] = None,
    ) -> CrashResult:
        if crash_detector is None:
            # Using sequence check in DeviceInterface
            return self.device.send_sequence_and_check_crash(inputs)

        crashed = False
        for d in inputs:
            _ = self.device.send_and_receive(d)
            if crash_detector():
                crashed = True
                break
        return CrashResult(crashed=crashed, reason="replay_custom_detector")

class ReportFormat(enum.Enum):
    MARKDOWN = "markdown"
    HTML = "html"


@dataclass
class ReportSection:
    title: str
    content: str


class ReportBuilder:

    def __init__(self, title: str):
        self.title = title
        self.sections: List[ReportSection] = []

    def add_section(self, title: str, content: str) -> None:
        self.sections.append(ReportSection(title, content))

    def build_markdown(self) -> str:
        lines: List[str] = [f"# {self.title}", ""]
        for sec in self.sections:
            lines.append(f"## {sec.title}")
            lines.append("")
            lines.extend(sec.content.splitlines())
            lines.append("")
        return "\n".join(lines)

    def build_html(self) -> str:
        from html import escape

        parts: List[str] = [
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            f"<meta charset='utf-8'><title>{escape(self.title)}</title>",
            "</head>",
            "<body>",
            f"<h1>{escape(self.title)}</h1>",
        ]
        for sec in self.sections:
            parts.append(f"<h2>{escape(sec.title)}</h2>")
            parts.append("<pre>")
            parts.append(escape(sec.content))
            parts.append("</pre>")
        parts.append("</body></html>")
        return "\n".join(parts)


class FuzzReportGenerator:

    def __init__(
        self,
        stats: RunStats,
        scheduler: MutationScheduler,
        feedback: FeedbackEngine,
        corpus: SeedCorpusManager,
        recorder: Optional[ResponseRecorder] = None,
    ):
        self.stats = stats
        self.scheduler = scheduler
        self.feedback = feedback
        self.corpus = corpus
        self.recorder = recorder

    def _section_summary(self) -> str:
        s = self.stats.summary_dict()
        lines = [
            f"Total input: {s['total_inputs']}",
            f"New response: {s['new_responses']}",
            f"Crashes: {s['crashes']}",
            f"Total execution time (seconds): {s['elapsed_sec']:.2f}",
            f"Inputs per sec(IPS): {s['inputs_per_sec']:.2f}",
        ]
        return "\n".join(lines)

    def _section_mutation(self) -> str:
        snap = self.scheduler.get_stats_snapshot()
        lines = ["Mutation Operator statistics:"]
        for op, st in snap.items():
            lines.append(
                f"- {op}: tried={st['tried']}, success={st['success']}, "
                f"success_rate={st['success_rate']:.4f}"
            )
        return "\n".join(lines)

    def _section_feedback(self) -> str:
        snap = self.feedback.get_scores_snapshot()
        top_n = 20
        sorted_items = sorted(snap.items(), key=lambda kv: kv[1], reverse=True)
        lines = [f"Top {top_n} bytes of feedback score:"]
        for idx, score in sorted_items[:top_n]:
            lines.append(f"- index {idx}: score={score:.2f}")
        return "\n".join(lines)

    def _section_corpus(self) -> str:
        lines = [
            "Seed corpus:",
            f"- 총 seed 개수: {len(self.corpus.seeds)}",
        ]
        by_source: Dict[str, int] = {}
        for s in self.corpus.seeds:
            by_source[s.source] = by_source.get(s.source, 0) + 1
        for src, cnt in by_source.items():
            lines.append(f"  - {src}: {cnt}")
        return "\n".join(lines)

    def _section_responses(self) -> str:
        if not self.recorder:
            return "ResponseRecorder was not provided."
        lines = [
            f"Number of records stored in ResponseRecorder: {len(self.recorder.records)}",
            "예시 5개:",
        ]
        for rec in self.recorder.records[:5]:
            resp_len = len(rec.response_data) if rec.response_data is not None else 0
            lines.append(
                f"- t={rec.timestamp:.2f}, is_new={rec.is_new}, "
                f"in_len={len(rec.input_data)}, resp_len={resp_len}"
            )
        return "\n".join(lines)

    def build_report(self, fmt: ReportFormat = ReportFormat.MARKDOWN) -> str:
        builder = ReportBuilder(title="CR-Fuzz Fuzzing Report")
        builder.add_section("Summary", self._section_summary())
        builder.add_section("Mutation statistics", self._section_mutation())
        builder.add_section("Feedback distribution", self._section_feedback())
        builder.add_section("Seed Corpus", self._section_corpus())
        builder.add_section("Response information", self._section_responses())

        if fmt == ReportFormat.MARKDOWN:
            return builder.build_markdown()
        else:
            return builder.build_html()

    def save_report(self, path: str, fmt: ReportFormat = ReportFormat.MARKDOWN) -> None:
        content = self.build_report(fmt=fmt)
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8") as f:
            f.write(content)


class MavlinkV2DependentPlugin(DependentFieldPlugin):
    name = "mavlink_v2"

    def __init__(self, crc_extra_table: Optional[Dict[int, int]] = None):
        """
        :param crc_extra_table: msgid(int) -> crc_extra(int) mapping
        """
        self.crc_extra_table = crc_extra_table or {}
        self.logger = logging.getLogger("cr_fuzz.MavlinkV2Plugin")

    @staticmethod
    def _mavlink_crc_x25(data: bytes) -> int:
        crc = 0xFFFF
        for b in data:
            tmp = b ^ (crc & 0xFF)
            tmp ^= (tmp << 4) & 0xFF
            crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
        return crc & 0xFFFF

    def _calc_len(self, pkt: Packet) -> int:
        total_len = len(pkt)
        if total_len < 12:
            return pkt[1] 
        payload_len = total_len - 12
        if payload_len < 0:
            payload_len = 0
        return payload_len

    def _calc_crc(self, pkt: Packet) -> Tuple[int, int]:
        if len(pkt) < 12:
            return pkt[-2], pkt[-1]

        payload_len = pkt[1]
        header_and_payload = pkt[1 : 10 + payload_len]

        msgid = pkt[7] | (pkt[8] << 8) | (pkt[9] << 16)
        crc_extra = self.crc_extra_table.get(msgid, 0)
        data = bytes(header_and_payload) + bytes([crc_extra & 0xFF])
        crc = self._mavlink_crc_x25(data)
        return crc & 0xFF, (crc >> 8) & 0xFF

    def register_all(self, calc: DependentFieldCalculator, pkt_len: int) -> None:
        def _len_func(pkt: Packet) -> int:
            return self._calc_len(pkt)

        def _crc_l(pkt: Packet) -> int:
            c_l, _ = self._calc_crc(pkt)
            return c_l

        def _crc_h(pkt: Packet) -> int:
            _, c_h = self._calc_crc(pkt)
            return c_h

        calc.register_calculator(1, _len_func)
        if pkt_len >= 2:
            calc.register_calculator(pkt_len - 2, _crc_l)
            calc.register_calculator(pkt_len - 1, _crc_h)
        self.logger.info(
            "MavlinkV2DependentPlugin registered: len_idx=1, crc_idx=%d,%d",
            pkt_len - 2,
            pkt_len - 1,
        )


class DumlDependentPlugin(DependentFieldPlugin):
    name = "duml"

    def __init__(self):
        self.logger = logging.getLogger("cr_fuzz.DUMLPlugin")

    @staticmethod
    def _crc16_ccitt(data: bytes, init: int = 0xFFFF) -> int:
        crc = init
        for b in data:
            crc ^= (b << 8) & 0xFFFF
            for _ in range(8):
                if crc & 0x8000:
                    crc = ((crc << 1) ^ 0x1021) & 0xFFFF
                else:
                    crc = (crc << 1) & 0xFFFF
        return crc & 0xFFFF

    @staticmethod
    def _calc_len(pkt: Packet) -> Tuple[int, int]:
        total_len = len(pkt)
        return total_len & 0xFF, (total_len >> 8) & 0xFF

    def _calc_crc(self, pkt: Packet) -> Tuple[int, int]:
        if len(pkt) < 4:
            return pkt[-2], pkt[-1]
        data = bytes(pkt[:-2])
        crc = self._crc16_ccitt(data)
        return crc & 0xFF, (crc >> 8) & 0xFF

    def register_all(self, calc: DependentFieldCalculator, pkt_len: int) -> None:
        def _len_l(pkt: Packet) -> int:
            l, _ = self._calc_len(pkt)
            return l

        def _len_h(pkt: Packet) -> int:
            _, h = self._calc_len(pkt)
            return h

        def _crc_l(pkt: Packet) -> int:
            c_l, _ = self._calc_crc(pkt)
            return c_l

        def _crc_h(pkt: Packet) -> int:
            _, c_h = self._calc_crc(pkt)
            return c_h

        calc.register_calculator(2, _len_l)
        calc.register_calculator(3, _len_h)
        if pkt_len >= 2:
            calc.register_calculator(pkt_len - 2, _crc_l)
            calc.register_calculator(pkt_len - 1, _crc_h)
        self.logger.info(
            "DumlDependentPlugin registered: len_idx=2,3, crc_idx=%d,%d",
            pkt_len - 2,
            pkt_len - 1,
        )


class BleAttDependentPlugin(DependentFieldPlugin):
    name = "ble_att"

    def __init__(self, length_index: int = 1, header_size: int = 3):
        self.length_index = length_index
        self.header_size = header_size
        self.logger = logging.getLogger("cr_fuzz.BLEAttPlugin")

    def register_all(self, calc: DependentFieldCalculator, pkt_len: int) -> None:
        def _len_func(pkt: Packet) -> int:
            # ex: total_length - header_size
            l = len(pkt) - self.header_size
            if l < 0:
                l = 0
            return l

        calc.register_calculator(self.length_index, _len_func)
        self.logger.info(
            "BleAttDependentPlugin registered: length_index=%d, header_size=%d",
            self.length_index,
            self.header_size,
        )

@dataclass
class FuzzScenario:
    name: str
    campaign: FuzzCampaignConfig
    protocol_plugin: Optional[type[DependentFieldPlugin]] = None
    use_dummy_device: bool = False
    dummy_scenario: Optional[DummyDeviceScenario] = None


class FuzzScenarioRunner:
    
    def __init__(self, scenario: FuzzScenario):
        self.scenario = scenario
        self.logger = logging.getLogger("cr_fuzz.ScenarioRunner")

    def _build_device(self, normal_packet_bytes: bytes) -> DeviceInterface:
        if self.scenario.use_dummy_device:
            self.logger.info("Using DummyDeviceInterface for scenario '%s'", self.scenario.name)
            return DummyDeviceInterface(self.scenario.dummy_scenario)
        else:
            dev_cfg = self.scenario.campaign.device
            return build_device(dev_cfg, normal_packet_bytes=normal_packet_bytes)

    def _build_dep_calc(self, pkt_len: int) -> DependentFieldCalculator:
        dep_calc = DependentFieldCalculator()
        if self.scenario.protocol_plugin is not None:
            plugin = self.scenario.protocol_plugin()  # type: ignore[call-arg]
            plugin.register_all(dep_calc, pkt_len=pkt_len)
        else:
            self.logger.info("No protocol plugin specified; using empty DependentFieldCalculator")
        return dep_calc

    def run(
        self,
        record_responses: bool = True,
        report_path: Optional[str] = None,
        report_format: ReportFormat = ReportFormat.MARKDOWN,
    ) -> None:
        fuzz_cfg = self.scenario.campaign.fuzz
        normal_packets = load_normal_packets_from_log(fuzz_cfg.log_path)
        pkt_len = len(normal_packets[0])
        normal_packet_bytes = normal_packets[0].to_bytes()
        self.logger.info(
            "Scenario '%s': loaded %d normal packets (len=%d)",
            self.scenario.name,
            len(normal_packets),
            pkt_len,
        )

        device = self._build_device(normal_packet_bytes=normal_packet_bytes)

        dep_calc = self._build_dep_calc(pkt_len=pkt_len)

        psi_cfg = self.scenario.campaign.psi
        fb_cfg = self.scenario.campaign.feedback
        crash_cfg = self.scenario.campaign.crash

        resp_kb = ResponseKnowledgeBase()

        corpus_mgr = SeedCorpusManager(corpus_dir=fuzz_cfg.corpus_dir)
        stats_logger = StatsLogger(csv_path=fuzz_cfg.stats_csv)
        recorder = ResponseRecorder(max_records=50_000) if record_responses else None

        fuzzer = CRFuzz(
            device=device,
            normal_packets=normal_packets,
            dep_calc=dep_calc,
            psi_cfg=psi_cfg,
            fb_cfg=fb_cfg,
            crash_cfg=crash_cfg,
            resp_kb=resp_kb,
            corpus_mgr=corpus_mgr,
            stats_logger=stats_logger,
            is_invalid_response=default_invalid_response,
        )

        live_checker = LivenessChecker(
            device=device,
            normal_packet=normal_packet_bytes,
            timeout_sec=crash_cfg.liveness_timeout,
            check_interval=crash_cfg.liveness_check_interval,
        )

        def on_new_response(inp: bytes, resp: bytes) -> None:
            if recorder is not None:
                recorder.record(inp, resp, is_new=True, note="new_response")
            self.logger.info(
                "[Scenario:%s] NEW RESPONSE: in_len=%d, resp_len=%d",
                self.scenario.name,
                len(inp),
                len(resp),
            )

        def on_crash(inp: bytes, crash_res: CrashResult) -> None:
            if recorder is not None:
                recorder.record(inp, None, is_new=False, note=f"crash:{crash_res.reason}")
            self.logger.error(
                "[Scenario:%s] CRASH: reason=%s, in_len=%d",
                self.scenario.name,
                crash_res.reason,
                len(inp),
            )

        self.logger.info(
            "Scenario '%s' fuzzing start: iterations=%d",
            self.scenario.name,
            fuzz_cfg.iterations,
        )
        fuzzer.fuzz(
            iterations=fuzz_cfg.iterations,
            save_interval=fuzz_cfg.save_interval,
            liveness_checker=live_checker,
            on_new_response=on_new_response,
            on_crash_found=on_crash,
        )
        self.logger.info(
            "Scenario '%s' fuzzing done: inputs=%d, new_responses=%d, crashes=%d, ips=%.2f",
            self.scenario.name,
            fuzzer.stats.total_inputs,
            fuzzer.stats.new_responses,
            fuzzer.stats.crashes,
            fuzzer.stats.inputs_per_sec(),
        )

        corpus_mgr.save_to_disk()
        if recorder is not None:
            resp_dir = os.path.join(fuzz_cfg.corpus_dir, "responses")
            recorder.save_as_log(resp_dir)
            recorder.save_as_csv(os.path.join(resp_dir, "responses.csv"))

        if report_path is not None:
            report_gen = FuzzReportGenerator(
                stats=fuzzer.stats,
                scheduler=fuzzer.scheduler,
                feedback=fuzzer.feedback_engine,
                corpus=corpus_mgr,
                recorder=recorder,
            )
            report_gen.save_report(report_path, fmt=report_format)
            self.logger.info("Scenario '%s' report saved to %s", self.scenario.name, report_path)

def parse_extended_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="CR-Fuzz extended CLI (scenario-based)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--scenario-name", default="default_scenario", help="Scenario name")
    p.add_argument("--campaign-json", default=None, help="FuzzCampaignConfig JSON file")
    p.add_argument("--protocol", choices=["none", "mavlink", "duml", "ble"], default="none")
    p.add_argument("--dummy-device", action="store_true", help="DummyDevice")
    p.add_argument("--dummy-crash", choices=["none", "random", "periodic", "threshold"], default="none")
    p.add_argument("--dummy-crash-period", type=int, default=5000)
    p.add_argument("--dummy-crash-threshold", type=int, default=128)
    p.add_argument("--report", default=None, help="report file path")
    p.add_argument(
        "--report-format",
        choices=["md", "markdown", "html"],
        default="md",
        help="report format",
    )
    p.add_argument("--log", dest="log_path", default="./normal_packets.log", help=".log file path")
    p.add_argument("--mode", choices=["serial", "udp"], default="udp", help="Device mode")
    p.add_argument("--serial-port", default="COM3", help="Serial port name")
    p.add_argument("--baudrate", type=int, default=115200, help="Serial baudrate")
    p.add_argument("--udp-ip", dest="udp_ip", default="127.0.0.1", help="UDP target IP")
    p.add_argument("--udp-port", dest="udp_port", type=int, default=14550, help="UDP target port")
    p.add_argument("--iterations", type=int, default=100000, help="fuzzing iteration")
    p.add_argument("--save-interval", type=int, default=1000, help="seed/statistics save cycle")
    p.add_argument("--corpus-dir", default="./corpus", help="seed corpus directory")
    p.add_argument("--stats-csv", default="./fuzz_stats_ext.csv", help="CSV file path")
    p.add_argument("--log-level", default="INFO", help="Log level (DEBUG/INFO/WARN/ERROR)")
    p.add_argument("--log-file", default=None, help="Log file path")
    return p.parse_args(argv)


def extended_main(argv: Optional[List[str]] = None) -> None:
    args = parse_extended_args(argv)

    log_cfg = LogConfig(log_level=args.log_level, log_file=args.log_file)
    log_cfg.init_logging()
    logger = logging.getLogger("cr_fuzz.ext_main")
    logger.info("CR-Fuzz extended scenario-based main start")

    if args.campaign_json:
        campaign_cfg = FuzzCampaignConfig.from_json_file(args.campaign_json)
    else:
        dev_cfg = DeviceConfig(
            mode=args.mode,
            serial_port=args.serial_port,
            serial_baudrate=args.baudrate,
            udp_target_ip=args.udp_ip,
            udp_target_port=args.udp_port,
        )
        fuzz_cfg = FuzzConfig(
            iterations=args.iterations,
            log_path=args.log_path,
            corpus_dir=args.corpus_dir,
            stats_csv=args.stats_csv,
            dry_run=False,
            save_interval=args.save_interval,
        )
        campaign_cfg = FuzzCampaignConfig(device=dev_cfg, fuzz=fuzz_cfg)

    protocol_plugin: Optional[type[DependentFieldPlugin]] = None
    if args.protocol == "mavlink":
        protocol_plugin = MavlinkV2DependentPlugin
    elif args.protocol == "duml":
        protocol_plugin = DumlDependentPlugin
    elif args.protocol == "ble":
        protocol_plugin = BleAttDependentPlugin
    else:
        protocol_plugin = None

    dummy_scenario: Optional[DummyDeviceScenario] = None
    if args.dummy_device:
        pattern = DummyCrashPattern.NONE
        if args.dummy_crash == "random":
            pattern = DummyCrashPattern.RANDOM
        elif args.dummy_crash == "periodic":
            pattern = DummyCrashPattern.PERIODIC
        elif args.dummy_crash == "threshold":
            pattern = DummyCrashPattern.THRESHOLD
        dummy_scenario = DummyDeviceScenario(
            crash_pattern=pattern,
            crash_period=args.dummy_crash_period,
            crash_threshold=args.dummy_crash_threshold,
        )

    scenario = FuzzScenario(
        name=args.scenario_name,
        campaign=campaign_cfg,
        protocol_plugin=protocol_plugin,
        use_dummy_device=args.dummy_device,
        dummy_scenario=dummy_scenario,
    )

    runner = FuzzScenarioRunner(scenario)
    fmt = ReportFormat.MARKDOWN
    if args.report_format in ("html",):
        fmt = ReportFormat.HTML
    runner.run(
        record_responses=True,
        report_path=args.report,
        report_format=fmt,
    )

    logger.info("CR-Fuzz extended scenario-based main end")

