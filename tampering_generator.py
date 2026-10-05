# Tampering Test Case Generator
# Generates synthetic modified RAT designs to simulate piracy scenarios

import random
from typing import Dict, List, Tuple, Optional
from copy import deepcopy

class TamperingGenerator:
    """Generate synthetic tampering scenarios for watermark detection testing."""

    # Tampering types
    MODIFIED_REGISTER = "modified_register"      # Changed register assignment
    PARTIAL_WATERMARK = "partial_watermark"       # Partial watermark removal
    REGISTER_SWAP = "register_swap"              # Swapped two variable registers
    CONSTRAINT_RELAXED = "constraint_relaxed"    # Removed non-sharing constraint
    FAKE_WATERMARK = "fake_watermark"            # Injected fake watermark
    FULL_COPY = "full_copy"                      # Exact copy (pirated)

    def __init__(self, base_rat: dict, watermark: str):
        """
        Initialize with base RAT and watermark.

        Args:
            base_rat: Register Allocation Table dictionary
            watermark: Original 445-bit watermark string
        """
        self.base_rat = deepcopy(base_rat)
        self.watermark = watermark
        self.tampered_rats = {}

    def generate_modified_register(self, num_changes: int = 5) -> dict:
        """
        Randomly change register assignments for variables involved in watermark constraints.
        This directly affects watermark match rate.

        Args:
            num_changes: Number of watermark constraint pairs to modify

        Returns:
            Tampered RAT dictionary
        """
        rat = deepcopy(self.base_rat)
        assignments = rat['assignments']

        # Find watermark constraint pairs that exist in the design
        constraint_pairs = []
        for bit_idx, bit in enumerate(self.watermark[:100]):
            if bit == '0':
                v1, v2 = f"V{bit_idx * 2}", f"V{bit_idx * 2 + 2}"
            else:
                v1, v2 = f"V{bit_idx * 2 + 1}", f"V{bit_idx * 2 + 3}"

            if v1 in assignments and v2 in assignments:
                constraint_pairs.append((v1, v2))

        # Modify register assignments for watermark constraint variables
        modified_pairs = random.sample(constraint_pairs, min(num_changes, len(constraint_pairs)))

        for v1, v2 in modified_pairs:
            # Force them to share a register (violates watermark constraint)
            reg = assignments[v1]['register']
            assignments[v2]['register'] = reg

        rat['tamper_type'] = self.MODIFIED_REGISTER
        rat['tamper_params'] = {'num_changes': len(modified_pairs)}
        return rat

    def generate_partial_watermark_removal(self, num_bits_removed: int = 45) -> dict:
        """
        Remove constraints for a portion of watermark bits (10%).

        Args:
            num_bits_removed: Number of watermark bits to neutralize

        Returns:
            Tampered RAT dictionary
        """
        rat = deepcopy(self.base_rat)
        assignments = rat['assignments']

        # Get constraint pairs for random bits
        bit_indices = list(range(len(self.watermark)))
        remove_bits = random.sample(bit_indices, min(num_bits_removed, len(bit_indices)))

        modified_vars = []
        for bit_idx in remove_bits:
            if self.watermark[bit_idx] == '0':
                # Even-even pair: V{2*bit_idx}, V{2*bit_idx+2}
                v1, v2 = f"V{bit_idx * 2}", f"V{bit_idx * 2 + 2}"
            else:
                # Odd-odd pair: V{2*bit_idx+1}, V{2*bit_idx+3}
                v1, v2 = f"V{bit_idx * 2 + 1}", f"V{bit_idx * 2 + 3}"

            if v1 in assignments and v2 in assignments:
                # Make them share a register (relax constraint)
                reg = assignments[v1]['register']
                assignments[v2]['register'] = reg
                modified_vars.extend([v1, v2])

        rat['tamper_type'] = self.PARTIAL_WATERMARK
        rat['tamper_params'] = {'bits_removed': len(set(modified_vars))}
        return rat

    def generate_register_swap(self, num_swaps: int = 3) -> dict:
        """
        Simulate register swaps that break watermark non-sharing constraints.

        Args:
            num_swaps: Number of swap operations

        Returns:
            Tampered RAT dictionary
        """
        rat = deepcopy(self.base_rat)
        assignments = rat['assignments']
        watermark_pairs = []
        for bit_idx, bit in enumerate(self.watermark):
            if bit == '0':
                v1, v2 = f"V{bit_idx * 2}", f"V{bit_idx * 2 + 2}"
            else:
                v1, v2 = f"V{bit_idx * 2 + 1}", f"V{bit_idx * 2 + 3}"
            if v1 in assignments and v2 in assignments:
                watermark_pairs.append((v1, v2))

        for v1, v2 in random.sample(watermark_pairs, min(num_swaps, len(watermark_pairs))):
            assignments[v1]['register'] = assignments[v2]['register']

        rat['tamper_type'] = self.REGISTER_SWAP
        rat['tamper_params'] = {'num_swaps': num_swaps}
        return rat

    def generate_constraint_relaxation(self, num_relaxed: int = 10) -> dict:
        """
        Relax some watermark constraints by making non-sharing pairs share.

        Args:
            num_relaxed: Number of constraints to relax

        Returns:
            Tampered RAT dictionary
        """
        rat = deepcopy(self.base_rat)
        assignments = rat['assignments']

        constraint_pairs = []
        for bit_idx, bit in enumerate(self.watermark[:100]):  # Use first 100 bits
            if bit == '0':
                v1, v2 = f"V{bit_idx * 2}", f"V{bit_idx * 2 + 2}"
            else:
                v1, v2 = f"V{bit_idx * 2 + 1}", f"V{bit_idx * 2 + 3}"

            if v1 in assignments and v2 in assignments:
                r1, r2 = assignments[v1]['register'], assignments[v2]['register']
                if r1 != r2:
                    constraint_pairs.append((v1, v2))

        relax_pairs = random.sample(constraint_pairs, min(num_relaxed, len(constraint_pairs)))

        for v1, v2 in relax_pairs:
            assignments[v2]['register'] = assignments[v1]['register']

        rat['tamper_type'] = self.CONSTRAINT_RELAXED
        rat['tamper_params'] = {'num_relaxed': len(relax_pairs)}
        return rat

    def generate_fake_watermark(self, num_fake_bits: int = 50) -> dict:
        """
        Inject fake watermark bits (different from original).

        Args:
            num_fake_bits: Number of bits to change

        Returns:
            Tampered RAT dictionary
        """
        rat = deepcopy(self.base_rat)
        assignments = rat['assignments']

        # Flip random bits
        bit_indices = list(range(len(self.watermark)))
        flip_bits = random.sample(bit_indices, min(num_fake_bits, len(bit_indices)))

        for bit_idx in flip_bits:
            if self.watermark[bit_idx] == '0':
                v1, v2 = f"V{bit_idx * 2}", f"V{bit_idx * 2 + 2}"
            else:
                v1, v2 = f"V{bit_idx * 2 + 1}", f"V{bit_idx * 2 + 3}"

            if v1 in assignments and v2 in assignments:
                # Change: make them share if they didn't, or don't share if they did
                r1, r2 = assignments[v1]['register'], assignments[v2]['register']
                if r1 == r2:
                    # Force non-sharing
                    new_reg = (r2 + 1) % 137
                    assignments[v2]['register'] = new_reg
                else:
                    # Force sharing
                    assignments[v2]['register'] = r1

        rat['tamper_type'] = self.FAKE_WATERMARK
        rat['tamper_params'] = {'num_flip': num_fake_bits}
        return rat

    def generate_full_copy(self) -> dict:
        """
        Create exact copy of original (pirated) design.

        Returns:
            Deep copy of base RAT
        """
        rat = deepcopy(self.base_rat)
        rat['tamper_type'] = self.FULL_COPY
        rat['tamper_params'] = {}
        return rat

    def generate_all_scenarios(self, samples_per_type: int = 5) -> Dict[str, List[dict]]:
        """
        Generate all tampering scenarios.

        Args:
            samples_per_type: Number of samples per tampering type

        Returns:
            Dictionary mapping tamper_type to list of RATs
        """
        scenarios = {
            'authentic': [],
            self.MODIFIED_REGISTER: [],
            self.PARTIAL_WATERMARK: [],
            self.REGISTER_SWAP: [],
            self.CONSTRAINT_RELAXED: [],
            self.FAKE_WATERMARK: [],
            self.FULL_COPY: []
        }

        # Authentic (original)
        scenarios['authentic'].append(deepcopy(self.base_rat))

        # Generate tampered versions
        for _ in range(samples_per_type):
            scenarios[self.MODIFIED_REGISTER].append(
                self.generate_modified_register(random.randint(3, 10))
            )
            scenarios[self.PARTIAL_WATERMARK].append(
                self.generate_partial_watermark_removal(random.randint(20, 50))
            )
            scenarios[self.REGISTER_SWAP].append(
                self.generate_register_swap(random.randint(2, 5))
            )
            scenarios[self.CONSTRAINT_RELAXED].append(
                self.generate_constraint_relaxation(random.randint(5, 15))
            )
            scenarios[self.FAKE_WATERMARK].append(
                self.generate_fake_watermark(random.randint(30, 80))
            )

        # Full copy (pirated)
        for _ in range(samples_per_type):
            scenarios[self.FULL_COPY].append(self.generate_full_copy())

        self.tampered_rats = scenarios
        return scenarios

    def get_test_dataset(self) -> List[Tuple[dict, str]]:
        """
        Get flat list of (rat, label) pairs for testing.

        Returns:
            List of (RAT dictionary, label) tuples
        """
        if not self.tampered_rats:
            self.generate_all_scenarios()

        dataset = []
        for label, rats in self.tampered_rats.items():
            for rat in rats:
                dataset.append((rat, label))

        random.shuffle(dataset)
        return dataset


class TestCaseFormatter:
    """Format test cases for LLM analysis."""

    @staticmethod
    def rat_to_text(rat: dict, max_vars: int = 50) -> str:
        """
        Convert RAT to text description for LLM.

        Args:
            rat: RAT dictionary
            max_vars: Maximum variables to include

        Returns:
            Text description
        """
        lines = []
        lines.append(f"Register Allocation Table Analysis")
        lines.append(f"=" * 40)
        lines.append(f"Variables: {len(rat.get('variables', []))}")
        lines.append(f"Registers used: {len(set(a['register'] for a in rat.get('assignments', {}).values()))}")
        lines.append(f"Control steps: {rat.get('num_control_steps', 'N/A')}")

        if 'tamper_type' in rat:
            lines.append(f"\nTampering Type: {rat['tamper_type']}")
            lines.append(f"Tamper Parameters: {rat.get('tamper_params', {})}")

        lines.append(f"\nVariable Assignments (first {max_vars}):")
        assignments = rat.get('assignments', {})
        for i, (var, data) in enumerate(list(assignments.items())[:max_vars]):
            reg = data['register']
            steps = len(data.get('control_steps', []))
            lines.append(f"  {var} -> R{reg} (lifetime: {steps} steps)")

        if len(assignments) > max_vars:
            lines.append(f"  ... and {len(assignments) - max_vars} more")

        return "\n".join(lines)

    @staticmethod
    def create_detection_prompt(rat: dict, question: str = "") -> str:
        """
        Create prompt for LLM-based detection.

        Args:
            rat: RAT dictionary to analyze
            question: Optional specific question

        Returns:
            Formatted prompt
        """
        rat_text = TestCaseFormatter.rat_to_text(rat)

        base_prompt = f"""You are a hardware security expert analyzing Register Allocation Tables (RAT) from High-Level Synthesis.

Your task is to analyze the following RAT data and determine if the hardware IP core is:
- AUTHENTIC: Original design with valid watermark
- SUSPICIOUS: Contains irregularities suggesting tampering
- PIRATED: Clear evidence of copied/design theft

{rat_text}

{question if question else "Based on the register assignments and constraint patterns, classify this design and explain your reasoning."}

Provide your classification and reasoning."""

        return base_prompt


# Demo
if __name__ == "__main__":
    # Create sample base RAT
    base_rat = {
        'variables': [
            {'name': f'V{i}', 'start': i % 10, 'end': (i % 10) + 5, 'type': 'temp'}
            for i in range(50)
        ],
        'assignments': {
            f'V{i}': {
                'register': i % 20,
                'control_steps': list(range(i % 10, (i % 10) + 6))
            }
            for i in range(50)
        },
        'num_control_steps': 30
    }

    # Sample watermark (445 bits)
    watermark = "".join(random.choice('01') for _ in range(445))

    # Generate tampering scenarios
    generator = TamperingGenerator(base_rat, watermark)
    scenarios = generator.generate_all_scenarios(samples_per_type=2)

    print("=== Generated Test Scenarios ===")
    for scenario_type, rats in scenarios.items():
        print(f"{scenario_type}: {len(rats)} samples")

    # Get test dataset
    dataset = generator.get_test_dataset()
    print(f"\nTotal test cases: {len(dataset)}")

    # Sample LLM prompt
    sample_rat = dataset[0][0]
    sample_label = dataset[0][1]
    prompt = TestCaseFormatter.create_detection_prompt(sample_rat)
    print(f"\n=== Sample LLM Prompt ({sample_label}) ===")
    print(prompt[:500] + "...")