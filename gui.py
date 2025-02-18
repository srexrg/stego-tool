import streamlit as st
import tempfile
import os
import numpy as np
from PIL import Image
import io
from tools.encryption import encrypt_data, decrypt_data, CryptoError
from tools.image_stego import hide_data, extract_data, detect_anomalies, StegoError

def main():
    st.title("Secure Image Steganography")
    st.write("Hide, extract, and detect hidden data in images with encryption")

    tab1, tab2, tab3 = st.tabs(["Hide Data", "Extract Data", "Detect Steganography"])

    with tab1:
        hide_data_ui()

    with tab2:
        extract_data_ui()

    with tab3:
        detect_steganography_ui()

def hide_data_ui():
    st.header("Hide Data in Image")
    
    
    cover_image = st.file_uploader("Choose cover image", type=['png'])
    data_file = st.file_uploader("Choose file to hide (optional)", type=['txt'])
    
    text_input = st.text_area("Or enter text to hide")
    
  
    use_encryption = st.checkbox("Encrypt data before hiding")
    if use_encryption:
        password = st.text_input("Enter encryption password", type="password")
    
    if st.button("Hide Data"):
        if cover_image is not None and (data_file is not None or text_input):
            try:
        
                if data_file is not None:
                    data = data_file.read()
                else:
                    data = text_input.encode()
                

                if use_encryption and password:
                    data = encrypt_data(password, data)
                
                # Create temporary files for processing
                temp_cover = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
                temp_output = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
                
                try:
                    # Save uploaded image
                    temp_cover.write(cover_image.read())
                    temp_cover.flush()
                    temp_cover.close()  # Close the file explicitly
                    
                    # Hide data
                    hide_data(temp_cover.name, data, temp_output.name)
                    temp_output.close()  # Close the output file explicitly
                    
                    # Provide download link
                    with open(temp_output.name, 'rb') as f:
                        stego_image = f.read()
                    
                    st.download_button(
                        label="Download Image with Hidden Data",
                        data=stego_image,
                        file_name="stego_image.png",
                        mime="image/png"
                    )
                    
                finally:
                    # Clean up in finally block to ensure deletion
                    try:
                        os.unlink(temp_cover.name)
                        os.unlink(temp_output.name)
                    except:
                        pass  # Ignore errors during cleanup
                    
                st.success("Data hidden successfully!")
                
            except Exception as e:
                st.error(f"Error: {str(e)}")
        else:
            st.warning("Please provide both a cover image and data to hide.")

def extract_data_ui():
    st.header("Extract Hidden Data")
    
    stego_image = st.file_uploader("Choose image with hidden data", type=['png'])
    
    # Decryption options
    use_decryption = st.checkbox("Decrypt extracted data")
    if use_decryption:
        password = st.text_input("Enter decryption password", type="password")
    
    if st.button("Extract Data"):
        if stego_image is not None:
            try:
                # Create temporary file for processing
                temp_stego = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
                try:
                    # Save uploaded image
                    temp_stego.write(stego_image.read())
                    temp_stego.flush()
                    temp_stego.close()  # Close the file explicitly
                    
                    # Extract data
                    extracted_data = extract_data(temp_stego.name)
                    
                    # Decrypt if requested
                    if use_decryption and password:
                        extracted_data = decrypt_data(password, extracted_data)
                    
                    # Try to decode as text
                    try:
                        text_data = extracted_data.decode('utf-8')
                        st.text_area("Extracted Text", text_data, height=200)
                    except UnicodeDecodeError:
                        # If not text, provide as downloadable file
                        st.download_button(
                            label="Download Extracted Data",
                            data=extracted_data,
                            file_name="extracted_data.bin",
                            mime="application/octet-stream"
                        )
                    
                finally:
                    # Clean up in finally block
                    try:
                        os.unlink(temp_stego.name)
                    except:
                        pass  # Ignore cleanup errors
                    
                st.success("Data extracted successfully!")
                
            except Exception as e:
                st.error(f"Error: {str(e)}")
        else:
            st.warning("Please provide an image to analyze.")

def detect_steganography_ui():
    st.header("Detect Steganography")
    
    image_file = st.file_uploader("Choose image to analyze", type=['png', 'jpg', 'jpeg'])
    threshold = st.slider("Detection Threshold", 0.0, 0.5, 0.1, 0.01)
    
    if st.button("Analyze Image"):
        if image_file is not None:
            try:
                # Create temporary file for processing
                temp_image = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
                try:
                    temp_image.write(image_file.read())
                    temp_image.flush()
                    temp_image.close()  # Close the temp file
                    
                    # Analyze image
                    is_suspicious, deviation = detect_anomalies(temp_image.name, threshold)
                    
                    # Display results
                    if is_suspicious:
                        st.warning(f"⚠️ Suspicious patterns detected! Deviation: {deviation:.4f}")
                    else:
                        st.success(f"✓ No suspicious patterns detected. Deviation: {deviation:.4f}")
                    
                    # Create visualization
                    img = Image.open(temp_image.name)
                    img_array = np.array(img)
                    lsb_array = img_array & 1
                    
                    # Display original and LSB visualization
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write("Original Image")
                        st.image(img)
                    
                    img.close()  # Close the PIL Image
                    
                finally:
                    # Clean up in finally block
                    try:
                        os.unlink(temp_image.name)
                    except:
                        pass  # Ignore cleanup errors
                
            except Exception as e:
                st.error(f"Error: {str(e)}")
        else:
            st.warning("Please provide an image to analyze.")

if __name__ == "__main__":
    main()