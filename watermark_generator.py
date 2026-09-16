# BioW-IPP Watermark Generator
# Converts proteogenomic sequences (DNA + insulin protein) into 445-bit watermark signature

def encode_dna(dna_sequence: str) -> list:
    """
    Encode DNA sequence to binary using alphabet-position mapping.
    A=0 (00), C=1 (01), G=2 (10), T=3 (11)
    Each nucleotide produces 2 bits.
    """
    dna = dna_sequence.upper().replace(" ", "").replace("\n", "")

    # Map: A=00, C=01, G=10, T=11
    mapping = {'A': 0, 'C': 1, 'G': 2, 'T': 3}

    bits = []
    for nucleotide in dna:
        if nucleotide in mapping:
            val = mapping[nucleotide]
            bits.append((val >> 1) & 1)  # First bit
            bits.append(val & 1)          # Second bit

    return bits

def encode_protein(protein_sequence: str) -> list:
    """
    Encode protein/amino acid sequence to binary.
    Uses alphabetical ordering: A=0, C=1, D=2, ... (standard 20 amino acids)
    Each amino acid produces bits based on required length.
    """
    protein = protein_sequence.upper().replace(" ", "").replace("\n", "").replace("-", "")

    # Standard amino acid ordering (alphabetical)
    amino_acids = 'ACDEFGHIKLMNPQRSTVWY'
    mapping = {aa: i for i, aa in enumerate(amino_acids)}

    # Determine bits needed per amino acid
    num_aa = len(amino_acids)  # 20
    bits_per_aa = (num_aa - 1).bit_length()  # 5 bits for 20 values

    bits = []
    for aa in protein:
        if aa in mapping:
            val = mapping[aa]
            # Convert to binary (MSB first)
            for i in range(bits_per_aa - 1, -1, -1):
                bits.append((val >> i) & 1)

    return bits

def generate_proteogenomic_watermark(dna: str, alpha_chain: str, beta_chain: str,
                                      dna_bits: int = 248, alpha_bits: int = 81,
                                      beta_bits: int = 116) -> str:
    """
    Generate 445-bit proteogenomic watermark signature.

    Args:
        dna: DNA sequence string
        alpha_chain: Insulin Alpha chain amino acid sequence
        beta_chain: Insulin Beta chain amino acid sequence
        dna_bits: Expected bits from DNA (default 248)
        alpha_bits: Expected bits from Alpha chain (default 81)
        beta_bits: Expected bits from Beta chain (default 116)

    Returns:
        445-bit binary string
    """
    # Encode each component
    dna_encoded = encode_dna(dna)
    alpha_encoded = encode_protein(alpha_chain)
    beta_encoded = encode_protein(beta_chain)

    # Truncate or pad to expected bit lengths
    dna_final = dna_encoded[:dna_bits] if len(dna_encoded) >= dna_bits else \
                dna_encoded + [0] * (dna_bits - len(dna_encoded))

    alpha_final = alpha_encoded[:alpha_bits] if len(alpha_encoded) >= alpha_bits else \
                  alpha_encoded + [0] * (alpha_bits - len(alpha_encoded))

    beta_final = beta_encoded[:beta_bits] if len(beta_encoded) >= beta_bits else \
                 beta_encoded + [0] * (beta_bits - len(beta_encoded))

    # Concatenate: Alpha + DNA + Beta = 81 + 248 + 116 = 445 bits
    watermark_bits = alpha_final + dna_final + beta_final

    # Convert to binary string
    return ''.join(str(b) for b in watermark_bits)

def watermark_to_constraints(watermark: str) -> list:
    """
    Convert 445-bit watermark to variable non-sharing constraint pairs.

    Bit 0 -> even-even pair: (V0, V2), (V2, V4), ...
    Bit 1 -> odd-odd pair: (V1, V3), (V3, V5), ...

    Args:
        watermark: 445-bit binary string

    Returns:
        List of tuples: [(variable1, variable2, constraint_type), ...]
        constraint_type: 'even_even' or 'odd_odd'
    """
    constraints = []

    for bit_index, bit in enumerate(watermark):
        if bit == '0':
            # Even-even pair constraint
            v1 = bit_index * 2      # V0, V2, V4, ...
            v2 = bit_index * 2 + 2  # V2, V4, V6, ...
            constraints.append((v1, v2, 'even_even'))
        else:
            # Odd-odd pair constraint
            v1 = bit_index * 2 + 1  # V1, V3, V5, ...
            v2 = bit_index * 2 + 3  # V3, V5, V7, ...
            constraints.append((v1, v2, 'odd_odd'))

    return constraints

def generate_synthetic_rat(num_variables: int = 273, num_control_steps: int = 31) -> dict:
    """
    Generate synthetic Register Allocation Table for testing.

    Args:
        num_variables: Number of storage variables (default 273 for JPEG-CODEC)
        num_control_steps: Number of control steps (default 31)

    Returns:
        Dictionary with 'variables' and 'assignments'
    """
    import random

    variables = []
    assignments = {}

    for i in range(num_variables):
        var_name = f"V{i}"
        # Random lifetime: start at control step 0-10, last for 2-15 steps
        start = random.randint(0, 10)
        lifetime = random.randint(2, min(15, num_control_steps - start))
        end = min(start + lifetime, num_control_steps - 1)

        variables.append({
            'name': var_name,
            'start': start,
            'end': end,
            'type': 'temp' if random.random() > 0.3 else 'accumulator'
        })

        # Assign to a random register (shared)
        reg = random.randint(0, 136)  # 137 registers
        assignments[var_name] = {
            'register': reg,
            'control_steps': list(range(start, end + 1))
        }

    return {
        'num_variables': num_variables,
        'num_control_steps': num_control_steps,
        'variables': variables,
        'assignments': assignments
    }

# Example usage
if __name__ == "__main__":
    # Example: Generate watermark from sample sequences
    sample_dna = "ATGCGATCG" * 28  # Shortened for demo (would be 248 bits worth)
    sample_alpha = "MALWMRLLPLL"   # Partial insulin alpha chain
    sample_beta = "MALWMRLLPLLALLALWGPDP"  # Partial insulin beta chain

    watermark = generate_proteogenomic_watermark(
        sample_dna,
        sample_alpha + "A" * 70,  # Pad to 81 bits
        sample_beta + "A" * 95    # Pad to 116 bits
    )

    print(f"Generated watermark ({len(watermark)} bits): {watermark[:50]}...")

    constraints = watermark_to_constraints(watermark)
    print(f"\nGenerated {len(constraints)} constraints")
    print(f"First 5 constraints: {constraints[:5]}")