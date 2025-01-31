import pefile
import struct
import sys
import argparse

# Constants
IMAGE_ENCLAVE_POLICY_DEBUGGABLE = 0x01  # Debuggable enclave flag
IMAGE_ENCLAVE_SHORT_ID_LENGTH = 16  # Length of FamilyID and ImageID fields
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10

# Struct formats for IMAGE_ENCLAVE_CONFIG64 and IMAGE_ENCLAVE_CONFIG32
ENCLAVE_CONFIG64_FORMAT = "<IIIIII" + f"{IMAGE_ENCLAVE_SHORT_ID_LENGTH}s" * 2 + "IIQII"
ENCLAVE_CONFIG32_FORMAT = "<IIIIII" + f"{IMAGE_ENCLAVE_SHORT_ID_LENGTH}s" * 2 + "IIII"

SUPPORTED_ARCHITECTURES = {0x8664: "64-bit", 0x014c: "32-bit"}  # IMAGE_FILE_MACHINE_AMD64 & IMAGE_FILE_MACHINE_I386

def detect_architecture(pe):
    """Detect the architecture of the PE file and raise an exception if unsupported."""
    machine_type = pe.FILE_HEADER.Machine
    if machine_type not in SUPPORTED_ARCHITECTURES:
        raise ValueError(f"Unsupported architecture detected: 0x{machine_type:X}")
    return machine_type == 0x8664  # True for 64-bit, False for 32-bit

def extract_enclave_config(pe, is_64bit):
    """Extract the IMAGE_ENCLAVE_CONFIG structure via the Load Config Directory."""
    if not hasattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG"):
        return None, None

    enclave_config_va = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.EnclaveConfigurationPointer
    if enclave_config_va == 0:
        return None, None

    enclave_config_rva = enclave_config_va - pe.OPTIONAL_HEADER.ImageBase

    enclave_offset = pe.get_offset_from_rva(enclave_config_rva)
    enclave_format = ENCLAVE_CONFIG64_FORMAT if is_64bit else ENCLAVE_CONFIG32_FORMAT
    enclave_size = struct.calcsize(enclave_format)

    try:
        data = pe.__data__[enclave_offset: enclave_offset + enclave_size]
        config = struct.unpack(enclave_format, data)
        return config, enclave_offset
    except struct.error:
        return None, None


def modify_enclave_policy(pe, enclave_offset):
    """Toggle the PolicyFlags field in IMAGE_ENCLAVE_CONFIG"""
    if enclave_offset is None:
        print("No enclave configuration found, skipping modification.")
        return False, None

    policy_offset = enclave_offset + 8  # PolicyFlags is the 3rd DWORD (offset 8)

    # Read the original policy
    original_policy = pe.get_dword_from_offset(policy_offset)
    new_policy = original_policy ^ IMAGE_ENCLAVE_POLICY_DEBUGGABLE  # Toggle the flag

    # Modify the binary data using pefile's set_bytes_at_offset
    pe.set_bytes_at_offset(policy_offset, struct.pack("<I", new_policy))

    return True, new_policy

def show_exports(pe):
    """Display all exported functions of the PE file"""
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        print("No exports found in this PE file.")
        return

    print("\nExported Functions:")
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        name = exp.name.decode() if exp.name else "<unnamed>"
        print(f" - {hex(pe.OPTIONAL_HEADER.ImageBase + exp.address)}: {name}")

def process_pe(file_path, output_file=None, toggle_debuggable=False):
    """Process a PE file: extract enclave config, show exports, modify debuggable flag if requested"""
    pe = pefile.PE(file_path)
    try:
        is_64bit = detect_architecture(pe)
        print(f"\nDetected {SUPPORTED_ARCHITECTURES[pe.FILE_HEADER.Machine]} PE file.")
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    pe.parse_data_directories([IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG])

    # Extract enclave config
    config, enclave_offset = extract_enclave_config(pe, is_64bit)
    
    if config:
        policy_flags = config[2]
        print("\nIMAGE_ENCLAVE_CONFIG extracted:")
        print(f" - Size: {config[0]}")
        print(f" - MinimumRequiredConfigSize: {config[1]}")
        print(f" - PolicyFlags: {hex(policy_flags)} {'(Debuggable)' if policy_flags & IMAGE_ENCLAVE_POLICY_DEBUGGABLE else '(Not Debuggable)'}")
        print(f" - NumberOfImports: {config[3]}")
        print(f" - ImportList: {hex(config[4])}")
        print(f" - ImportEntrySize: {config[5]}")
        print(f" - ImageVersion: {hex(config[8])}")
        print(f" - SecurityVersion: {config[9]}")
        print(f" - EnclaveSize: {hex(config[10])}")
        print(f" - NumberOfThreads: {config[11]}")
        print(f" - EnclaveFlags: {hex(config[12])}")
    
    else:
        print("\nNo IMAGE_ENCLAVE_CONFIG found in this PE file.")

    # Show exports
    show_exports(pe)

    # Modify enclave policy if requested
    if toggle_debuggable:
        success, new_policy = modify_enclave_policy(pe, enclave_offset) 
        if success:
            pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
            print(f"\nModified IMAGE_ENCLAVE_POLICY to {hex(new_policy)} {'(Debuggable)' if new_policy & IMAGE_ENCLAVE_POLICY_DEBUGGABLE else '(Not Debuggable)'}")
            if output_file:
                pe.write(filename=output_file)
                print(f"Modified PE saved to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract and modify IMAGE_ENCLAVE_CONFIG in PE files.")
    parser.add_argument("input_pe", help="Path to the input PE file")
    parser.add_argument("--output", "-o", help="Path to save the modified PE file (required for --debuggable)")
    parser.add_argument("--debuggable", action="store_true", help="Toggle the IMAGE_ENCLAVE_POLICY_DEBUGGABLE field")

    args = parser.parse_args()

    if args.debuggable and not args.output:
        print("Error: --debuggable requires --output to save the modified PE file.")
        sys.exit(1)

    process_pe(args.input_pe, args.output, args.debuggable)
