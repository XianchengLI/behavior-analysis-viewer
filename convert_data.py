"""
CSV to JSON Converter for SharePoint Viewer (with AES Encryption)

Converts annotation and thread CSV files to JSON format.
Threads data is encrypted with AES-256-CBC for privacy protection.

Usage:
    python convert_data.py --password YOUR_PASSWORD

Input files (relative to webapp/data/):
    - all_annotated.csv
    - all_threads_anonymized.csv

Output files (in data/):
    - annotated.json      (not encrypted - no sensitive content)
    - threads.encrypted   (AES-256 encrypted)
    - encryption_config.json (salt and IV for decryption)
"""

import pandas as pd
import json
import argparse
import base64
import os
from pathlib import Path
from datetime import datetime

# Encryption imports
try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Util.Padding import pad
    from Crypto.Random import get_random_bytes
except ImportError:
    print("ERROR: pycryptodome is required for encryption.")
    print("Install it with: pip install pycryptodome")
    exit(1)

# Paths
SCRIPT_DIR = Path(__file__).parent
WEBAPP_DATA = SCRIPT_DIR.parent / "webapp" / "data"
OUTPUT_DIR = SCRIPT_DIR / "data"

# Input files
ANNOTATED_CSV = WEBAPP_DATA / "all_annotated.csv"
THREADS_CSV = WEBAPP_DATA / "all_threads_anonymized.csv"

# Output files
ANNOTATED_JSON = OUTPUT_DIR / "annotated.json"
THREADS_ENCRYPTED = OUTPUT_DIR / "threads.encrypted"
ENCRYPTION_CONFIG = OUTPUT_DIR / "encryption_config.json"


# ============================================================================
# Encryption Functions
# ============================================================================

def encrypt_data(data_str: str, password: str) -> tuple:
    """
    Encrypt data using AES-256-CBC with PBKDF2 key derivation.

    Args:
        data_str: JSON string to encrypt
        password: User password

    Returns:
        tuple: (encrypted_base64, salt_base64, iv_base64)
    """
    # Generate random salt and IV
    salt = get_random_bytes(16)
    iv = get_random_bytes(16)

    # Derive key from password using PBKDF2
    # Using 100000 iterations for security (matching CryptoJS default)
    key = PBKDF2(password, salt, dkLen=32, count=100000)

    # Create cipher and encrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data_str.encode('utf-8'), AES.block_size)
    encrypted = cipher.encrypt(padded_data)

    # Encode to base64 for storage
    encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    iv_b64 = base64.b64encode(iv).decode('utf-8')

    return encrypted_b64, salt_b64, iv_b64


# ============================================================================
# Data Conversion Functions
# ============================================================================

def parse_vaccine_types(value):
    """Parse vaccine_types field from JSON string to list."""
    if pd.isna(value) or value == "":
        return []
    try:
        if isinstance(value, str):
            return json.loads(value)
        return value
    except json.JSONDecodeError:
        return [value]


def convert_annotated(df):
    """Convert annotated DataFrame to list of dicts with parsed fields."""
    records = []
    parse_errors = []

    for idx, row in df.iterrows():
        record = row.to_dict()

        # Parse vaccine_types
        try:
            record['vaccine_types'] = parse_vaccine_types(row['vaccine_types'])
        except Exception as e:
            parse_errors.append(f"Row {idx}: vaccine_types parse error - {e}")
            record['vaccine_types'] = []

        # Convert numpy types to Python types
        for key, value in record.items():
            try:
                if pd.isna(value):
                    record[key] = None
                    continue
            except (ValueError, TypeError):
                pass

            if hasattr(value, 'item'):
                record[key] = value.item()

        records.append(record)

    return records, parse_errors


def convert_threads(df):
    """Convert threads DataFrame to dict grouped by thread_id."""
    threads = {}
    df = df.sort_values(['thread_id', 'timestamp'])

    for thread_id, group in df.groupby('thread_id'):
        posts = []
        for _, row in group.iterrows():
            post = {
                'post_id': int(row['post_id']) if pd.notna(row['post_id']) else None,
                'author_role': row['author_role'] if pd.notna(row['author_role']) else None,
                'timestamp': str(row['timestamp']) if pd.notna(row['timestamp']) else None,
                'content': str(row['content']) if pd.notna(row['content']) else "",
                'sentiment': row['sentiment'] if pd.notna(row['sentiment']) else 'neutral',
                'has_vaccine_keyword': bool(row['has_vaccine_keyword']) if pd.notna(row['has_vaccine_keyword']) else False,
                'replies_to_post_number': int(row['replies_to_post_number']) if pd.notna(row['replies_to_post_number']) else None
            }
            posts.append(post)
        threads[str(int(thread_id))] = posts

    return threads


def validate_data(annotated_records, threads_dict, annotated_df, threads_df):
    """Validate converted data."""
    errors = []
    warnings = []

    if len(annotated_records) != len(annotated_df):
        errors.append(f"Annotated count mismatch: {len(annotated_records)} vs {len(annotated_df)}")

    total_posts = sum(len(posts) for posts in threads_dict.values())
    if total_posts != len(threads_df):
        errors.append(f"Threads post count mismatch: {total_posts} vs {len(threads_df)}")

    annotated_thread_ids = set(r['thread_id'] for r in annotated_records)
    threads_thread_ids = set(int(k) for k in threads_dict.keys())

    missing_in_threads = annotated_thread_ids - threads_thread_ids
    if missing_in_threads:
        warnings.append(f"Thread IDs in annotated but not in threads: {len(missing_in_threads)}")

    empty_vaccine_types = sum(1 for r in annotated_records if not r['vaccine_types'])
    if empty_vaccine_types > 0:
        warnings.append(f"Records with empty vaccine_types: {empty_vaccine_types}")

    return errors, warnings


# ============================================================================
# Main Function
# ============================================================================

def main():
    # Parse arguments
    parser = argparse.ArgumentParser(description='Convert CSV to JSON with encryption')
    parser.add_argument('--password', '-p', required=True,
                        help='Password for encrypting threads data')
    args = parser.parse_args()

    password = args.password

    if len(password) < 8:
        print("ERROR: Password must be at least 8 characters long")
        return False

    print("=" * 60)
    print("CSV to JSON Converter (with AES Encryption)")
    print("=" * 60)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # Check input files
    print("Checking input files...")
    if not ANNOTATED_CSV.exists():
        print(f"ERROR: {ANNOTATED_CSV} not found!")
        return False
    if not THREADS_CSV.exists():
        print(f"ERROR: {THREADS_CSV} not found!")
        return False
    print(f"  - {ANNOTATED_CSV.name}: OK")
    print(f"  - {THREADS_CSV.name}: OK")
    print()

    # Load CSVs
    print("Loading CSV files...")
    annotated_df = pd.read_csv(ANNOTATED_CSV)
    threads_df = pd.read_csv(THREADS_CSV)
    print(f"  - Annotated: {len(annotated_df)} rows, {len(annotated_df.columns)} columns")
    print(f"  - Threads: {len(threads_df)} rows, {len(threads_df.columns)} columns")
    print()

    # Convert
    print("Converting data...")
    annotated_records, parse_errors = convert_annotated(annotated_df)
    threads_dict = convert_threads(threads_df)
    print(f"  - Annotated records: {len(annotated_records)}")
    print(f"  - Thread groups: {len(threads_dict)}")
    print()

    if parse_errors:
        print("Parse errors:")
        for err in parse_errors[:10]:
            print(f"  - {err}")
        if len(parse_errors) > 10:
            print(f"  ... and {len(parse_errors) - 10} more")
        print()

    # Validate
    print("Validating data...")
    errors, warnings = validate_data(annotated_records, threads_dict, annotated_df, threads_df)

    if errors:
        print("ERRORS:")
        for err in errors:
            print(f"  - {err}")
        print()
        print("Conversion FAILED due to errors.")
        return False

    if warnings:
        print("WARNINGS:")
        for warn in warnings:
            print(f"  - {warn}")
        print()

    # Ensure output directory exists
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Save annotated JSON (not encrypted)
    print("Saving files...")
    print()

    print("  [1/3] Saving annotated.json (not encrypted)...")
    with open(ANNOTATED_JSON, 'w', encoding='utf-8') as f:
        json.dump(annotated_records, f, ensure_ascii=False, indent=2)
    annotated_size = ANNOTATED_JSON.stat().st_size / 1024
    print(f"        Size: {annotated_size:.1f} KB")

    # Encrypt and save threads
    print("  [2/3] Encrypting threads data...")
    threads_json_str = json.dumps(threads_dict, ensure_ascii=False)
    original_size = len(threads_json_str.encode('utf-8')) / 1024 / 1024
    print(f"        Original size: {original_size:.1f} MB")

    encrypted_data, salt, iv = encrypt_data(threads_json_str, password)
    encrypted_size = len(encrypted_data) / 1024 / 1024
    print(f"        Encrypted size: {encrypted_size:.1f} MB")

    with open(THREADS_ENCRYPTED, 'w', encoding='utf-8') as f:
        f.write(encrypted_data)
    print(f"        Saved to: threads.encrypted")

    # Save encryption config
    print("  [3/3] Saving encryption config...")
    config = {
        'salt': salt,
        'iv': iv,
        'iterations': 100000,
        'keySize': 256,
        'algorithm': 'AES-CBC'
    }
    with open(ENCRYPTION_CONFIG, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2)
    print(f"        Saved to: encryption_config.json")
    print()

    # Summary
    print("=" * 60)
    print("CONVERSION COMPLETE")
    print("=" * 60)
    print(f"Output directory: {OUTPUT_DIR}")
    print()
    print("Files created:")
    print(f"  - annotated.json ({len(annotated_records)} records, {annotated_size:.1f} KB)")
    print(f"  - threads.encrypted ({len(threads_dict)} threads, {encrypted_size:.1f} MB)")
    print(f"  - encryption_config.json (salt, iv, settings)")
    print()
    print("Security notes:")
    print("  - threads.encrypted is AES-256-CBC encrypted")
    print("  - Password is NOT stored in any file")
    print("  - Share password securely with authorized users")
    print()
    print("Next steps:")
    print("  1. Start local server: python -m http.server 8000")
    print("  2. Open http://localhost:8000/index.html")
    print("  3. Enter password to access thread content")
    print("  4. Upload sharepoint_viewer/ folder to SharePoint")

    return True


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
