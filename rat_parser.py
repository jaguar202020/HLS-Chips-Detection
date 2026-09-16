# RAT (Register Allocation Table) Parser and Constraint Extractor
# Parses hardware design data to extract storage variable constraints

import json
import re
from typing import Dict, List, Tuple, Optional

class RATParser:
    """Parse and analyze Register Allocation Tables from HLS output."""

    def __init__(self):
        self.variables = {}
        self.registers = {}
        self.control_steps = 0

    def parse_from_dict(self, rat_data: dict) -> bool:
        """
        Parse RAT from dictionary format.

        Expected format:
        {
            'variables': [{'name': 'V0', 'start': 0, 'end': 5, 'type': 'temp'}, ...],
            'assignments': {'V0': {'register': 0, 'control_steps': [0,1,2,3,4,5]}, ...},
            'num_control_steps': 31
        }
        """
        try:
            self.variables = {v['name']: v for v in rat_data.get('variables', [])}
            self.assignments = rat_data.get('assignments', {})
            self.control_steps = rat_data.get('num_control_steps', 31)
            self._build_register_map()
            return True
        except Exception as e:
            print(f"Parse error: {e}")
            return False

    def parse_from_json(self, json_path: str) -> bool:
        """Parse RAT from JSON file."""
        try:
            with open(json_path, 'r') as f:
                data = json.load(f)
            return self.parse_from_dict(data)
        except Exception as e:
            print(f"JSON parse error: {e}")
            return False

    def parse_from_text(self, text_data: str) -> bool:
        """
        Parse RAT from text/table format.

        Example format:
        Variable | Start | End | Register
        V0       | 0     | 5   | R0
        V1       | 2     | 8   | R1
        """
        lines = text_data.strip().split('\n')
        variables = []
        assignments = {}

        for line in lines:
            # Skip header lines
            if 'Variable' in line or '---' in line or '|' not in line:
                continue

            parts = [p.strip() for p in line.split('|')]
            if len(parts) >= 4:
                var_name = parts[0]
                start = int(parts[1])
                end = int(parts[2])
                register = int(parts[3].replace('R', ''))

                variables.append({
                    'name': var_name,
                    'start': start,
                    'end': end,
                    'type': 'temp'
                })
                assignments[var_name] = {
                    'register': register,
                    'control_steps': list(range(start, end + 1))
                }

        return self.parse_from_dict({
            'variables': variables,
            'assignments': assignments
        })

    def _build_register_map(self):
        """Build reverse mapping: register -> variables."""
        self.registers = {}
        for var_name, assignment in self.assignments.items():
            reg = assignment['register']
            if reg not in self.registers:
                self.registers[reg] = []
            self.registers[reg].append(var_name)

    def get_register_count(self) -> int:
        """Get total number of physical registers used."""
        return len(self.registers)

    def get_variable_count(self) -> int:
        """Get total number of storage variables."""
        return len(self.variables)

    def extract_non_sharing_constraints(self) -> List[Tuple[str, str]]:
        """
        Extract variable pairs that DO NOT share registers.
        These are the actual constraints in the design.

        Returns:
            List of (var1, var2) tuples that cannot share registers.
        """
        constraints = []
        var_names = list(self.variables.keys())

        for i, v1 in enumerate(var_names):
            for v2 in var_names[i+1:]:
                # Check if they share a register
                r1 = self.assignments.get(v1, {}).get('register')
                r2 = self.assignments.get(v2, {}).get('register')

                # Check if their lifetimes overlap
                v1_data = self.variables[v1]
                v2_data = self.variables[v2]

                overlap = (v1_data['start'] <= v2_data['end'] and
                          v2_data['start'] <= v1_data['end'])

                # If lifetimes overlap but different registers -> non-sharing constraint
                if overlap and r1 != r2:
                    constraints.append((v1, v2))

        return constraints

    def extract_sharing_constraints(self) -> List[Tuple[str, str]]:
        """
        Extract variable pairs that DO share registers.
        These represent the actual sharing in the design.

        Returns:
            List of (var1, var2) tuples that share a register.
        """
        sharing_pairs = []

        for reg, vars_in_reg in self.registers.items():
            if len(vars_in_reg) > 1:
                for i, v1 in enumerate(vars_in_reg):
                    for v2 in vars_in_reg[i+1:]:
                        # Verify lifetimes don't overlap
                        v1_data = self.variables[v1]
                        v2_data = self.variables[v2]

                        no_overlap = (v1_data['end'] < v2_data['start'] or
                                     v2_data['end'] < v1_data['start'])

                        if no_overlap:
                            sharing_pairs.append((v1, v2))

        return sharing_pairs

    def build_interference_graph(self) -> Dict[str, List[str]]:
        """
        Build interference graph from RAT.

        Returns:
            Adjacency list: {variable: [interfering variables]}
        """
        graph = {var: [] for var in self.variables}
        var_names = list(self.variables.keys())

        for i, v1 in enumerate(var_names):
            for v2 in var_names[i+1:]:
                v1_data = self.variables[v1]
                v2_data = self.variables[v2]

                # Variables interfere if lifetimes overlap
                overlap = (v1_data['start'] <= v2_data['end'] and
                          v2_data['start'] <= v1_data['end'])

                if overlap:
                    graph[v1].append(v2)
                    graph[v2].append(v1)

        return graph

    def get_watermark_constraints(self, watermark_bits: str,
                                   max_variable: int = 890) -> List[Tuple[int, int, str]]:
        """
        Extract watermark-based non-sharing constraints from design.
        Compare against expected watermark to verify authenticity.

        Args:
            watermark_bits: Expected 445-bit watermark
            max_variable: Maximum variable index to check

        Returns:
            List of (v1_idx, v2_idx, 'found'/'missing') tuples
        """
        found_constraints = []
        expected_constraints = []

        for bit_idx, bit in enumerate(watermark_bits):
            if bit == '0':
                v1 = bit_idx * 2
                v2 = bit_idx * 2 + 2
            else:
                v1 = bit_idx * 2 + 1
                v2 = bit_idx * 2 + 3

            if v2 > max_variable:
                break

            expected_constraints.append((v1, v2))

            # Check if this constraint exists in the design
            v1_name = f"V{v1}"
            v2_name = f"V{v2}"

            if v1_name in self.variables and v2_name in self.variables:
                r1 = self.assignments.get(v1_name, {}).get('register')
                r2 = self.assignments.get(v2_name, {}).get('register')

                if r1 is not None and r2 is not None and r1 != r2:
                    found_constraints.append((v1, v2, 'found'))
                else:
                    found_constraints.append((v1, v2, 'missing'))
            else:
                found_constraints.append((v1, v2, 'not_present'))

        return found_constraints

    def compute_design_cost(self, L_max: int = 200, A_max: int = 200,
                            w1: float = 0.5, w2: float = 0.5) -> float:
        """
        Compute design cost metric.

        Design Cost = w1 * (L/L_max) + w2 * (A/A_max)
        Where L = latency, A = area (register count)
        """
        L = self.control_steps
        A = self.get_register_count()

        cost = w1 * (L / L_max) + w2 * (A / A_max)
        return cost

    def to_summary_dict(self) -> dict:
        """Generate summary statistics."""
        return {
            'num_variables': self.get_variable_count(),
            'num_registers': self.get_register_count(),
            'num_control_steps': self.control_steps,
            'register_sharing_ratio': self.get_variable_count() / max(1, self.get_register_count()),
            'design_cost': self.compute_design_cost(),
            'non_sharing_constraints': len(self.extract_non_sharing_constraints()),
            'sharing_constraints': len(self.extract_sharing_constraints())
        }


class ConstraintAnalyzer:
    """Analyze and compare constraint patterns for watermark verification."""

    @staticmethod
    def extract_watermark_from_constraints(constraints: List[Tuple[int, int]],
                                           num_bits: int = 445) -> str:
        """
        Reconstruct watermark bits from constraint pairs.

        Args:
            constraints: List of (v1, v2) variable index pairs
            num_bits: Expected watermark length

        Returns:
            Reconstructed binary watermark string
        """
        bits = ['?'] * num_bits  # Unknown bits

        for v1, v2 in constraints:
            if v1 % 2 == 0 and v2 % 2 == 0 and v2 == v1 + 2:
                # Even-even pair -> bit 0
                bit_idx = v1 // 2
                if bit_idx < num_bits:
                    bits[bit_idx] = '0'
            elif v1 % 2 == 1 and v2 % 2 == 1 and v2 == v1 + 2:
                # Odd-odd pair -> bit 1
                bit_idx = (v1 - 1) // 2
                if bit_idx < num_bits:
                    bits[bit_idx] = '1'

        return ''.join(bits)

    @staticmethod
    def compare_watermarks(expected: str, extracted: str) -> dict:
        """
        Compare expected vs extracted watermarks.

        Returns:
            Dictionary with match statistics
        """
        if len(expected) != len(extracted):
            return {
                'match': False,
                'error': 'Length mismatch',
                'expected_len': len(expected),
                'extracted_len': len(extracted)
            }

        matches = 0
        unknowns = 0
        mismatches = []

        for i, (e, x) in enumerate(zip(expected, extracted)):
            if x == '?':
                unknowns += 1
            elif e == x:
                matches += 1
            else:
                mismatches.append(i)

        total_known = len(expected) - unknowns
        match_rate = matches / max(1, total_known)

        return {
            'match': match_rate == 1.0 and unknowns == 0,
            'match_rate': match_rate,
            'matches': matches,
            'mismatches': len(mismatches),
            'mismatch_positions': mismatches[:20],  # First 20
            'unknowns': unknowns,
            'total_bits': len(expected)
        }

    @staticmethod
    def compute_tamper_tolerance(watermark_len: int = 445) -> float:
        """
        Compute tamper tolerance (search space size).

        TT = 2^n where n = watermark length
        """
        return 2 ** watermark_len

    @staticmethod
    def compute_coincidence_probability(watermark_len: int = 445,
                                         filter_ratio: float = 0.037) -> float:
        """
        Compute probability of coincidence (false positive rate).

        PC = (1/2)^n * filter_ratio
        """
        return (0.5 ** watermark_len) * filter_ratio


if __name__ == "__main__":
    sample_rat = {
        'variables': [
            {'name': 'V0', 'start': 0, 'end': 5, 'type': 'temp'},
            {'name': 'V1', 'start': 2, 'end': 8, 'type': 'temp'},
            {'name': 'V2', 'start': 6, 'end': 12, 'type': 'temp'},
            {'name': 'V3', 'start': 1, 'end': 4, 'type': 'accumulator'},
            {'name': 'V4', 'start': 9, 'end': 15, 'type': 'temp'},
            {'name': 'V5', 'start': 3, 'end': 7, 'type': 'temp'},
        ],
        'assignments': {
            'V0': {'register': 0, 'control_steps': [0, 1, 2, 3, 4, 5]},
            'V1': {'register': 1, 'control_steps': [2, 3, 4, 5, 6, 7, 8]},
            'V2': {'register': 0, 'control_steps': [6, 7, 8, 9, 10, 11, 12]},  # Shares R0 with V0
            'V3': {'register': 2, 'control_steps': [1, 2, 3, 4]},
            'V4': {'register': 1, 'control_steps': [9, 10, 11, 12, 13, 14, 15]},  # Shares R1 with V1
            'V5': {'register': 3, 'control_steps': [3, 4, 5, 6, 7]},
        },
        'num_control_steps': 16
    }

    parser = RATParser()
    parser.parse_from_dict(sample_rat)

    print("=== RAT Summary ===")
    summary = parser.to_summary_dict()
    for k, v in summary.items():
        print(f"  {k}: {v}")

    print("\n=== Interference Graph ===")
    graph = parser.build_interference_graph()
    for var, neighbors in graph.items():
        print(f"  {var}: interferes with {neighbors}")

    print("\n=== Sharing Pairs ===")
    sharing = parser.extract_sharing_constraints()
    print(f"  {sharing}")