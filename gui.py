import streamlit as st
import tempfile
import os
from pydub import AudioSegment
import numpy as np
from PIL import Image
from tools.audio_stego import hide_data_lsb, extract_data_lsb, detect_anomalies_lsb
from tools.encryption import encrypt_data, decrypt_data, CryptoError
from tools.image_stego import hide_data, extract_data, detect_anomalies, StegoError

def main():
    st.title("Secure Steganography Tool")
    st.write("Hide, extract, and detect hidden data in images and audio files")

    tab1, tab2, tab3 = st.tabs(["Hide Data", "Extract Data", "Detect Steganography"])
    
    with tab1:
        media_type = st.radio("Select media type", ["Image", "Audio"])
        if media_type == "Image":
            hide_data_ui()
        else:
            hide_audio_data_ui()

    with tab2:
        media_type = st.radio("Select media type to extract from", ["Image", "Audio"])
        if media_type == "Image":
            extract_data_ui()
        else:
            extract_audio_data_ui()

    with tab3:
        media_type = st.radio("Select media type to analyze", ["Image", "Audio"])
        if media_type == "Image":
            detect_steganography_ui()
        else:
            detect_audio_steganography_ui()

def hide_audio_data_ui():
    st.header("Hide Data in Audio")
    
    cover_audio = st.file_uploader("Choose cover audio", type=['wav', 'mp3'])
    
    text_input = st.text_area("Or enter text to hide")
    
    use_encryption = st.checkbox("Encrypt data before hiding")
    if use_encryption:
        password = st.text_input("Enter encryption password", type="password")
    
    if st.button("Hide Data"):
        if cover_audio is not None and (text_input):
            with st.spinner("Processing audio... This may take a moment"):
                try:
                    data = text_input.encode()

                    temp_cover_path = tempfile.mktemp(suffix='.wav')
                    temp_output_path = tempfile.mktemp(suffix='.wav')
                    
                    try:
                        audio = AudioSegment.from_file(cover_audio)
                        cover_audio.close()
                        
                        audio.export(temp_cover_path, format='wav')
                        del audio
                        
                        hide_data_lsb(temp_cover_path, data, temp_output_path, 
                                    password if use_encryption else None)
                        
                        with open(temp_output_path, 'rb') as f:
                            stego_audio = f.read()
                        
                        st.download_button(
                            label="Download Audio with Hidden Data",
                            data=stego_audio,
                            file_name="stego_audio.wav",
                            mime="audio/wav"
                        )
                        
                    finally:
                        for path in [temp_cover_path, temp_output_path]:
                            for _ in range(3):
                                try:
                                    if os.path.exists(path):
                                        os.close(os.open(path, os.O_RDONLY))
                                        os.remove(path)
                                    break
                                except Exception:
                                    import time
                                    time.sleep(0.1)
                    
                    st.success("Data hidden successfully!")
                    
                except Exception as e:
                    st.error(f"Error processing audio: {str(e)}")
        else:
            st.warning("Please provide both an audio file and data to hide.")

def extract_audio_data_ui():
    st.header("Extract Hidden Data from Audio")
    
    stego_audio = st.file_uploader("Choose audio with hidden data", type=['wav', 'mp3'])
    
    use_decryption = st.checkbox("Decrypt extracted data")
    if use_decryption:
        password = st.text_input("Enter decryption password", type="password")
    
    if st.button("Extract Data"):
        if stego_audio is not None:
            with st.spinner("Extracting data... Please wait"):
                try:
                    temp_stego_path = tempfile.mktemp(suffix='.wav')
                    
                    try:
                        audio = AudioSegment.from_file(stego_audio)
                        stego_audio.close()
                        
                        audio.export(temp_stego_path, format='wav')
                        del audio
                        
                        extracted_data = extract_data_lsb(temp_stego_path, 
                                                        password if use_decryption else None)
                        
                        try:
                            text_data = extracted_data.decode('utf-8')
                            st.text_area("Extracted Text", text_data, height=200)
                        except UnicodeDecodeError:
                            st.download_button(
                                label="Download Extracted Data",
                                data=extracted_data,
                                file_name="extracted_data.bin",
                                mime="application/octet-stream"
                            )
                        
                    finally:
                        for _ in range(3):
                            try:
                                if os.path.exists(temp_stego_path):
                                    os.close(os.open(temp_stego_path, os.O_RDONLY))
                                    os.remove(temp_stego_path)
                                break
                            except Exception:
                                import time
                                time.sleep(0.1)
                    
                    st.success("Data extracted successfully!")
                    
                except Exception as e:
                    st.error(f"Error processing audio: {str(e)}")
        else:
            st.warning("Please provide an audio file to extract data from.")

def detect_audio_steganography_ui():
    st.header("Detect Audio Steganography")
    
    audio_file = st.file_uploader("Choose audio to analyze", type=['wav', 'mp3'])
    
    if st.button("Analyze Audio"):
        if audio_file is not None:
            with st.spinner("Analyzing audio... Please wait"):
                try:
                    temp_dir = tempfile.gettempdir()
                    temp_audio_path = os.path.join(temp_dir, 'temp_analysis.wav')
                    
                    try:
                        audio = AudioSegment.from_file(audio_file)
                        audio.export(temp_audio_path, format='wav')
                        
                        is_suspicious = detect_anomalies_lsb(temp_audio_path)
                        
                        if is_suspicious:
                            st.warning("⚠️ Suspicious patterns detected!")
                        else:
                            st.success("✓ No suspicious patterns detected")
                        
                    finally:
                        try:
                            if os.path.exists(temp_audio_path):
                                os.remove(temp_audio_path)
                        except:
                            pass
                    
                except Exception as e:
                    st.error(f"Error: {str(e)}")

def hide_data_ui():
    st.header("Hide Data in Image")
    
    cover_image = st.file_uploader("Choose cover image", type=['png'])
    
    text_input = st.text_area("Or enter text to hide")
    
    use_encryption = st.checkbox("Encrypt data before hiding")
    if use_encryption:
        password = st.text_input("Enter encryption password", type="password")
    
    if st.button("Hide Data"):
        if cover_image is not None and (text_input):
            with st.spinner("Processing image... Please wait"):
                try:
 
                    data = text_input.encode()

                    if use_encryption and password:
                        data = encrypt_data(password, data)
                    
                    temp_cover = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
                    temp_output = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
                    
                    try:
                        temp_cover.write(cover_image.read())
                        temp_cover.flush()
                        temp_cover.close()
                        
                        hide_data(temp_cover.name, data, temp_output.name)
                        temp_output.close()
                        
                        with open(temp_output.name, 'rb') as f:
                            stego_image = f.read()
                        
                        st.download_button(
                            label="Download Image with Hidden Data",
                            data=stego_image,
                            file_name="stego_image.png",
                            mime="image/png"
                        )
                        
                    finally:
                        try:
                            os.unlink(temp_cover.name)
                            os.unlink(temp_output.name)
                        except:
                            pass
                        
                    st.success("Data hidden successfully!")
                    
                except Exception as e:
                    st.error(f"Error: {str(e)}")
        else:
            st.warning("Please provide both a cover image and data to hide.")

def extract_data_ui():
    st.header("Extract Hidden Data")
    
    stego_image = st.file_uploader("Choose image with hidden data", type=['png'])
    
    use_decryption = st.checkbox("Decrypt extracted data")
    if use_decryption:
        password = st.text_input("Enter decryption password", type="password")
    
    if st.button("Extract Data"):
        if stego_image is not None:
            with st.spinner("Extracting data... Please wait"):
                try:
                    temp_stego = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
                    try:
                        temp_stego.write(stego_image.read())
                        temp_stego.flush()
                        temp_stego.close()
                        
                        extracted_data = extract_data(temp_stego.name)
                        
                        if use_decryption and password:
                            extracted_data = decrypt_data(password, extracted_data)
                        
                        try:
                            text_data = extracted_data.decode('utf-8')
                            st.text_area("Extracted Text", text_data, height=200)
                        except UnicodeDecodeError:
                            st.download_button(
                                label="Download Extracted Data",
                                data=extracted_data,
                                file_name="extracted_data.bin",
                                mime="application/octet-stream"
                            )
                        
                    finally:
                        try:
                            os.unlink(temp_stego.name)
                        except:
                            pass
                        
                    st.success("Data extracted successfully!")
                    
                except Exception as e:
                    st.error(f"Error: {str(e)}")
        else:
            st.warning("Please provide an image to analyze.")

def detect_steganography_ui():
    st.header("Detect Steganography")
    
    image_file = st.file_uploader("Choose image to analyze", type=['png', 'jpg', 'jpeg'])
    
    if st.button("Analyze Image"):
        if image_file is not None:
            with st.spinner("Analyzing image... Please wait"):
                try:
                    temp_image = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
                    try:
                        temp_image.write(image_file.read())
                        temp_image.flush()
                        temp_image.close()
                        
                        is_suspicious, deviation = detect_anomalies(temp_image.name)
                        
                        if is_suspicious:
                            st.warning(f"⚠️ Suspicious patterns detected! Deviation: {deviation:.4f}")
                        else:
                            st.success(f"✓ No suspicious patterns detected. Deviation: {deviation:.4f}")
                        
                        img = Image.open(temp_image.name)
                        img_array = np.array(img)
                        lsb_array = img_array & 1
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.write("Original Image")
                            st.image(img)
                        
                        img.close()
                        
                    finally:
                        try:
                            os.unlink(temp_image.name)
                        except:
                            pass
                    
                except Exception as e:
                    st.error(f"Error: {str(e)}")
        else:
            st.warning("Please provide an image to analyze.")

if __name__ == "__main__":
    main()