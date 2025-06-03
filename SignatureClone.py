import pefile
import shutil
import sys
import os
from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates
from cryptography import x509
from cryptography.hazmat.primitives import serialization

def get_cert_data(file_path):
    """
    Retrieves certificate data from a PE file, including its location and size.
    This helps us locate the digital signature within the executable.
    """
    try:
        pe = pefile.PE(file_path)
        # Check if the file is a valid PE32 executable
        if pe.DOS_HEADER.e_magic != 0x5A4D or pe.NT_HEADERS.Signature != 0x4550:
            print(f"{file_path} is not a valid PE32 file.")
            return None
        # Access the security directory to find the certificate's location
        cert_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        cert_location = cert_entry.VirtualAddress
        cert_size = cert_entry.Size
        # Determine if the file is 64-bit to calculate the correct offset
        is_64bit = pe.OPTIONAL_HEADER.Magic == 0x20B
        offset_to_cert_table = pe.DOS_HEADER.e_lfanew + 4 + 20 + (144 if is_64bit else 128)
        print(f"Debug: {file_path} - Certificate RVA: {cert_location}, Size: {cert_size}, Offset: {offset_to_cert_table}, 64-bit: {is_64bit}")
        return {
            'current_offset': offset_to_cert_table,
            'cert_location': cert_location,
            'cert_size': cert_size
        }
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return None

def verify_certificate(file_path):
    """
    Checks if a PE file contains a valid digital certificate.
    Returns True if a certificate is found, False otherwise.
    """
    try:
        pe = pefile.PE(file_path)
        cert_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        if cert_entry.VirtualAddress == 0 or cert_entry.Size == 0:
            print(f"No certificate found in {file_path}")
            return False
        print(f"Certificate verified in {file_path}: RVA={cert_entry.VirtualAddress}, Size={cert_entry.Size}")
        return True
    except Exception as e:
        print(f"Error verifying certificate in {file_path}: {e}")
        return False

def validate_pe_file(file_path):
    """
    Validates if the given file is a proper PE executable.
    Useful to ensure we're working with a compatible file format.
    """
    try:
        pe = pefile.PE(file_path)
        is_64bit = pe.OPTIONAL_HEADER.Magic == 0x20B
        print(f"Debug: {file_path} is a valid PE file, 64-bit: {is_64bit}")
        return True
    except Exception as e:
        print(f"Error: {file_path} is not a valid PE file: {e}")
        return False

def extract_and_save_certificate(certificate_data, output_path):
    """
    Extracts and saves the certificate from the PKCS#7 structure to a .cer file.
    Also displays key certificate details like issuer and serial number.
    """
    try:
        certificates = load_der_pkcs7_certificates(certificate_data)
        if not certificates:
            print("Error: No certificates found in PKCS#7 structure")
            return False
        cert = certificates[0]
        # Save the certificate in DER format
        with open(output_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.DER))
        print(f"Debug: Saved certificate to {output_path}")
        # Display certificate details
        issuer = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        serial = cert.serial_number
        print(f"Debug: Certificate - Issuer: {issuer}, Serial: {serial}")
        return True
    except Exception as e:
        print(f"Error extracting certificate: {e}")
        return False

def main():
    """
    Main function to clone a certificate from one PE file to another.
    Takes three command-line arguments: source file, target file, and output file.
    """
    if len(sys.argv) != 4:
        print("\nIncorrect number of arguments provided.")
        print("Usage: python CertificateCloner.py SourceFile.exe TargetFile.exe OutputFile.exe")
        print("Example: python CertificateCloner.py ClipUp.exe myapp.exe SignedApp.exe\n")
        sys.exit(1)

    input_file = sys.argv[1]
    target_file = sys.argv[2]
    output_file = sys.argv[3]

    # Ensure input and target files exist
    if not os.path.exists(input_file):
        print(f"\nError: {input_file} not found.")
        print("Please ensure the file is in the same directory as the script.\n")
        sys.exit(1)
    if not os.path.exists(target_file):
        print(f"\nError: {target_file} not found.")
        print("Please ensure the file is in the same directory as the script.\n")
        sys.exit(1)

    # Validate the target file
    if not validate_pe_file(target_file):
        print(f"Error: {target_file} is not a valid PE file. Exiting.")
        sys.exit(1)

    # Retrieve certificate data from the source file
    input_cert_data = get_cert_data(input_file)
    if not input_cert_data:
        print(f"Failed to retrieve certificate data from {input_file}")
        sys.exit(1)

    # Read the certificate from the source file
    try:
        with open(input_file, 'rb') as f:
            f.seek(input_cert_data['cert_location'])
            certificate = f.read(input_cert_data['cert_size'])
            if len(certificate) != input_cert_data['cert_size']:
                print(f"\nError: Expected {input_cert_data['cert_size']} bytes, read {len(certificate)} from {input_file}")
                sys.exit(1)
        print(f"Debug: Successfully read certificate from {input_file} ({input_cert_data['cert_size']} bytes)")
    except Exception as e:
        print(f"\nError reading certificate from {input_file}: {e}")
        sys.exit(1)

    # Copy the target file to the output file
    try:
        shutil.copyfile(target_file, output_file)
        print(f"Debug: Copied {target_file} to {output_file}")
        os.chmod(output_file, 0o666)
    except Exception as e:
        print(f"\nError copying {target_file} to {output_file}: {e}")
        print("Ensure the target file exists and the destination is writable.\n")
        sys.exit(1)

    # Get certificate data for the output file
    target_cert_data = get_cert_data(output_file)
    if not target_cert_data:
        print(f"Failed to retrieve certificate data from {output_file}")
        sys.exit(1)

    # Append the certificate to the output file and update the PE header
    try:
        with open(output_file, 'r+b') as f:
            if not os.access(output_file, os.W_OK):
                print(f"\nError: No write permission for {output_file}")
                sys.exit(1)
            f.seek(0, os.SEEK_END)
            cert_rva = f.tell()
            f.write(certificate)
            written_bytes = f.tell() - cert_rva
            if written_bytes != input_cert_data['cert_size']:
                print(f"\nError: Expected {input_cert_data['cert_size']} bytes, wrote {written_bytes} to {output_file}")
                sys.exit(1)
            print(f"Debug: Appended certificate to {output_file} at offset {cert_rva}")
            f.seek(target_cert_data['current_offset'])
            f.write(cert_rva.to_bytes(4, byteorder='little'))
            f.write(input_cert_data['cert_size'].to_bytes(4, byteorder='little'))
            f.flush()
            print(f"Debug: Updated PE header in {output_file} at offset {target_cert_data['current_offset']} with RVA={cert_rva}, Size={input_cert_data['cert_size']}")
    except Exception as e:
        print(f"\nError modifying {output_file}: {e}")
        sys.exit(1)

    # Verify the certificate in the output file
    if verify_certificate(output_file):
        print(f"Certificate successfully cloned to {output_file}")
    else:
        print(f"Failed to verify certificate in {output_file}")
        sys.exit(1)

    # Extract and save the certificate for manual installation
    cert_file = "cloned_certificate.cer"
    if extract_and_save_certificate(certificate, cert_file):
        print(f"\nCertificate extracted to {cert_file}.")
        print("To trust the certificate, follow these steps:")
        print(f"1. Right-click {output_file} > Properties > Digital Signatures tab.")
        print("2. Select the signature, click Details > View Certificate > Install Certificate.")
        print("3. In the Certificate Import Wizard, select 'Local Machine' > Next.")
        print("4. Choose 'Place all certificates in the following store' > Browse.")
        print("5. Select 'Trusted Root Certification Authorities' > OK > Next > Finish.")
        print("Warning: The signature remains invalid due to a hash mismatch between the certificate and file contents.")
        print("Security Warning: Adding unverified certificates to the Trusted Root store is risky. Use only in controlled environments.")
        print("Note: For a fully valid signature, re-sign the file with a tool like signtool.exe using a valid code-signing certificate.")
    else:
        print("Failed to extract certificate. Manual installation not possible.")

if __name__ == "__main__":
    main()