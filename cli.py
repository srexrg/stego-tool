import argparse
from tools.encryption import encrypt_data, decrypt_data, CryptoError
from tools.image_stego import hide_data, extract_data, detect_anomalies, StegoError
import logging
import sys
from pathlib import Path

def setup_logging():

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def validate_paths(args):
    
    if hasattr(args, 'cover') and not Path(args.cover).exists():
        raise FileNotFoundError(f"Cover image not found: {args.cover}")
    if hasattr(args, 'secret') and not Path(args.secret).exists():
        raise FileNotFoundError(f"Secret file not found: {args.secret}")
    if hasattr(args, 'input') and not Path(args.input).exists():
        raise FileNotFoundError(f"Input file not found: {args.input}")

def main():
    parser = argparse.ArgumentParser(description="Steganography CLI Tool")
    subparsers = parser.add_subparsers(dest='command', required=True)

    
    hide_parser = subparsers.add_parser('hide', help="Hide encrypted data in an image")
    hide_parser.add_argument('-c', '--cover', required=True, help="Cover image path")
    hide_parser.add_argument('-s', '--secret', required=True, help="Secret file to hide")
    hide_parser.add_argument('-o', '--output', required=True, help="Output image path")
    hide_parser.add_argument('-p', '--password', required=True, help="Encryption password")

 
    extract_parser = subparsers.add_parser('extract', help="Extract and decrypt hidden data")
    extract_parser.add_argument('-i', '--input', required=True, help="Stego image path")
    extract_parser.add_argument('-o', '--output', required=True, help="Output file path")
    extract_parser.add_argument('-p', '--password', required=True, help="Decryption password")

  
    detect_parser = subparsers.add_parser('detect', help="Detect potential steganography")
    detect_parser.add_argument('-f', '--file', required=True, help="Image file to analyze")
    detect_parser.add_argument('-t', '--threshold', type=float, default=0.1, 
                             help="Detection threshold (default: 0.1)")

    args = parser.parse_args()
    setup_logging()
    logger = logging.getLogger(__name__)

    try:
        validate_paths(args)

        if args.command == 'hide':
            logger.info(f"Reading secret file: {args.secret}")
            with open(args.secret, 'rb') as f:
                secret_data = f.read()
            
            logger.info("Encrypting data...")
            encrypted = encrypt_data(args.password, secret_data)
            
            logger.info("Hiding encrypted data in image...")
            hide_data(args.cover, encrypted, args.output)
            logger.info(f"Data successfully hidden in: {args.output}")
        
        elif args.command == 'extract':
            logger.info("Extracting hidden data...")
            encrypted_data = extract_data(args.input)
            
            logger.info("Decrypting data...")
            decrypted_data = decrypt_data(args.password, encrypted_data)
            
            logger.info(f"Writing decrypted data to: {args.output}")
            with open(args.output, 'wb') as f:
                f.write(decrypted_data)
            logger.info("Data extracted and decrypted successfully")
        
        elif args.command == 'detect':
            logger.info(f"Analyzing image: {args.file}")
            is_suspicious, deviation = detect_anomalies(args.file, args.threshold)
            logger.info(f"Analysis results:")
            logger.info(f"  Suspicious: {is_suspicious}")
            logger.info(f"  Deviation from expected: {deviation:.4f}")

    except (CryptoError, StegoError) as e:
        logger.error(f"Operation failed: {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        logger.error(str(e))
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()

  
