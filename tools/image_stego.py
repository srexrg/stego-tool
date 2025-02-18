from PIL import Image
import numpy as np
import logging
from typing import Tuple, Optional

logger = logging.getLogger(__name__)

class StegoError(Exception):
    """Custom exception for steganographic operations."""
    pass

def calculate_image_capacity(image: Image.Image) -> int:
    """Calculate the maximum number of bytes that can be hidden."""
    width, height = image.size
    return (width * height * 3) // 8 - 4

def hide_data(cover_path: str, data: bytes, output_path: str) -> None:
    """Hide data in an image using LSB steganography with capacity checking."""
    try:
        with Image.open(cover_path) as img:
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            max_bytes = calculate_image_capacity(img)
            if len(data) > max_bytes:
                raise StegoError(f"Data too large: {len(data)} bytes exceeds capacity of {max_bytes} bytes")
            
            array = np.array(img)
            data_len = len(data).to_bytes(4, 'big')
            bits = ''.join(f"{byte:08b}" for byte in data_len + data)
            
            flat_array = array.reshape(-1, 3)
            total_pixels = len(flat_array) * 3
            
            bits = bits.ljust(total_pixels, '0')
            
            for idx, bit in enumerate(bits):
                pixel_idx = idx // 3
                color_idx = idx % 3
                if pixel_idx < len(flat_array):
                    flat_array[pixel_idx, color_idx] = (flat_array[pixel_idx, color_idx] & 0xFE) | int(bit)
            
            modified_array = flat_array.reshape(array.shape)
            Image.fromarray(modified_array).save(output_path, format='PNG')
            logger.info(f"Data hidden in {output_path}")
            
    except Exception as e:
        raise StegoError(f"Failed to hide data: {str(e)}")

def extract_data(stego_path: str) -> bytes:
    """Extract hidden data from an image, with validation."""
    try:
        with Image.open(stego_path) as img:
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            array = np.array(img)
            flat_array = array.reshape(-1, 3)
            
            bits = ''.join(str(pixel[i] & 1) for pixel in flat_array for i in range(3))
            
            length = int(bits[:32], 2)
            if length < 0 or length > calculate_image_capacity(img):
                raise StegoError("Invalid data length detected")
            
            data_bits = bits[32:32 + length * 8]
            if len(data_bits) % 8 != 0:
                raise StegoError("Invalid data format")
            
            return bytes(int(data_bits[i:i+8], 2) for i in range(0, len(data_bits), 8))
            
    except Exception as e:
        raise StegoError(f"Failed to extract data: {str(e)}")

def detect_anomalies(image_path: str, threshold: float = 0.1) -> Tuple[bool, float]:
    """
    Detect potential steganographic content.
    Returns (is_suspicious, deviation_from_expected).
    """
    try:
        with Image.open(image_path) as img:
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            array = np.array(img)
            lsb_values = array & 1
            
            lsb_mean = np.mean(lsb_values)
            deviation = abs(lsb_mean - 0.5)
            
            is_suspicious = deviation > threshold
            if is_suspicious:
                logger.warning(f"Suspicious LSB pattern detected in {image_path}")
            
            return is_suspicious, deviation
            
    except Exception as e:
        raise StegoError(f"Failed to analyze image: {str(e)}")