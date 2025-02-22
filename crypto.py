#crypto.py
import numpy as np
from PIL import Image, ImageDraw, ImageFont
from hashlib import sha256
import os

# Utility Functions
def secure_next_int(min: int, max: int) -> int:
    if min > max: raise Exception("Random number range max cannot be less than min.")
    i_range = max - min
    if i_range == 0: return min
    num_size = (i_range.bit_length() + 7) // 8
    mask = (1 << (num_size * 8)) - 1
    while True:
        result = int.from_bytes(os.urandom(num_size), "little") & mask
        if result <= i_range: return result + min

# Lattice-Based Encryption
def generate_lattice_keypair(n=512, q=12289):
    import random
    random.seed(42)
    s = [random.randint(-1, 1) for _ in range(n)]
    e = [random.randint(-1, 1) for _ in range(n)]
    A = [[random.randint(0, q - 1) for _ in range(n)] for _ in range(n)]
    b = [(sum((A[i][j] * s[j]) % q for j in range(n)) + e[i]) % q for i in range(n)]
    return ((A, b), s)

def encrypt_lattice(public_key, message, q=12289, n=512):
    A, b = public_key
    message_bytes = message.encode('utf-8')
    
    # Dynamically split message into chunks
    max_chunk_bytes = (n - 32) // 8  # Reserve 32 bits for length prefix
    chunks = [message_bytes[i:i+max_chunk_bytes] for i in range(0, len(message_bytes), max_chunk_bytes)]
    
    ciphertexts = []
    for chunk in chunks:
        chunk_length = len(chunk)
        length_bytes = chunk_length.to_bytes(4, 'big')
        padded_chunk = length_bytes + chunk
        
        binary = ''.join(format(byte, '08b') for byte in padded_chunk)
        # Pad or truncate to exactly n bits
        if len(binary) > n:
            binary = binary[:n]
        else:
            binary += '0' * (n - len(binary))
        
        m = [int(bit) for bit in binary]
        
        import random
        random.seed(42)
        r = [random.randint(0, 1) for _ in range(n)]
        c1 = [(sum((A[i][j] * r[j]) % q for j in range(n))) % q for i in range(n)]
        c2 = [(sum((b[j] * r[j]) % q for j in range(n)) + (q // 2) * m[i]) % q for i in range(n)]
        
        ciphertexts.append((c1, c2))
    
    return ciphertexts

def decrypt_lattice(private_key, ciphertexts, q=12289):
    decrypted_chunks = []
    
    for ciphertext in ciphertexts:
        c1, c2 = ciphertext
        s = private_key
        n = len(s)
        
        decrypted = [(c2[i] - sum((c1[j] * s[j]) % q for j in range(n))) % q for i in range(n)]
        binary = ''.join('1' if x >= q // 2 else '0' for x in decrypted)
        
        try:
            message_bytes = bytes(int(binary[i:i+8], 2) for i in range(0, len(binary), 8))
            message_length = int.from_bytes(message_bytes[:4], 'big')
            
            if message_length <= 0 or message_length > len(message_bytes) - 4:
                raise ValueError("Invalid message length")
            
            chunk = message_bytes[4:4+message_length]
            decrypted_chunks.append(chunk)
        
        except Exception as e:
            print(f"Decryption error: {e}")
            return None
    
    return b''.join(decrypted_chunks).decode('utf-8')

# Steganography Functions
# Utility to generate a secure sequence of random indices for embedding data
def generate_secure_sequence(data_length, key, total_pixels):
    seed = int(sha256(key.encode()).hexdigest(), 16) % (2**32)
    rng = np.random.default_rng(seed)
    return rng.choice(total_pixels, size=data_length, replace=False)

def embed_data(image_path, data, output_path, key):
    """Embed the provided data into the image and save the modified image."""
    # Open the image and flatten the pixel array
    img = Image.open(image_path)
    pixels = np.array(img)
    flat_pixels = pixels.flatten()

    # Calculate the maximum data length that can be embedded based on image size
    max_capacity = len(flat_pixels)  # Each pixel can hold 1 bit of data
    
    # Print the total size of the image in pixels and bits
    print(f"Total image size: {len(flat_pixels)} pixels, which can hold {len(flat_pixels)} bits of data.")
    
    # Ensure that the data fits within the available embedding capacity
    if len(data) * 8 > max_capacity:
        raise Exception("Message exceeds embedding capacity of image.")
    
    # Convert data to binary string
    binary_data = ''.join(format(byte, '08b') for byte in data)
    
    # Check if binary data fits within the image capacity
    if len(binary_data) > max_capacity:
        raise Exception("Message exceeds embedding capacity of image.")
    
    # Split the binary data into chunks that fit within the image's capacity
    chunk_size = len(flat_pixels) // 8  # Each pixel can hold 1 bit of data
    chunks = [binary_data[i:i + chunk_size] for i in range(0, len(binary_data), chunk_size)]
    
    print(f"Embedding {len(chunks)} chunks of data...")  # Debug statement
    
    for chunk in chunks:
        embedding_indices = generate_secure_sequence(len(chunk), key, len(flat_pixels))
        for i, bit in zip(embedding_indices, chunk):
            flat_pixels[i] = (flat_pixels[i] & ~1) | int(bit)
    
    # Reshape the modified pixel array back into the image's shape
    modified_pixels = flat_pixels.reshape(pixels.shape)
    stego_image = Image.fromarray(modified_pixels)
    
    # Save the stego image
    stego_image.save(output_path)
    print(f"Data successfully embedded into {output_path}.")


def extract_data(image_data, data_length, key):
    # Check if the input is a numpy.ndarray (image data) or a file path
    if isinstance(image_data, np.ndarray):
        # If it's an ndarray, convert it to a PIL Image
        pil_image = Image.fromarray(image_data)
    else:
        # Otherwise, open the image using the file path
        pil_image = Image.open(image_data)
    
    # Flatten the image pixels
    pixels = np.array(pil_image).flatten()
    
    # Generate the embedding indices based on the key
    embedding_indices = generate_secure_sequence(data_length * 8, key, len(pixels))
    
    # Extract the binary data from the image's pixels
    binary_data = ''.join(str(pixels[i] & 1) for i in embedding_indices)
    
    print(f"Extracted {len(binary_data) // 8} bytes of data...")  # Debug statement
    
    # Convert binary data back into byte chunks
    extracted_data = bytes(int(binary_data[i:i + 8], 2) for i in range(0, len(binary_data), 8))
    
    return extracted_data


class WatermarkProtection:
    def __init__(self, image_path):
        self.image = Image.open(image_path)
        self.width, self.height = self.image.size
        self.pixels = np.array(self.image)
        
    def add_visible_watermark(self, text, opacity=0.3):
        """Add visible watermark text in corners and center"""
        # Create a transparent layer for the watermark
        watermark = Image.new('RGBA', (self.width, self.height), (0, 0, 0, 0))
        draw = ImageDraw.Draw(watermark)
        
        # Calculate text size for scaling
        font_size = min(self.width, self.height) // 20
        try:
            font = ImageFont.truetype("arial.ttf", font_size)
        except:
            font = ImageFont.load_default()
            
        text_width, text_height = draw.textsize(text, font=font)
        
        # Positions for watermarks (corners and center)
        positions = [
            (10, 10),  # Top-left
            (self.width - text_width - 10, 10),  # Top-right
            (10, self.height - text_height - 10),  # Bottom-left
            (self.width - text_width - 10, self.height - text_height - 10),  # Bottom-right
            ((self.width - text_width) // 2, (self.height - text_height) // 2)  # Center
        ]
        
        # Add text at each position
        for pos in positions:
            draw.text(pos, text, font=font, fill=(255, 255, 255, int(255 * opacity)))
            
        # Composite the watermark with the original image
        self.image = Image.alpha_composite(self.image.convert('RGBA'), watermark)
        
    def add_invisible_watermark(self, data, key):
        """Add invisible LSB watermarks in corners and center"""
        pixels = np.array(self.image)
        binary_data = ''.join(format(byte, '08b') for byte in data.encode())
        
        # Calculate region sizes for corners and center
        corner_size = min(self.width, self.height) // 8
        center_size = min(self.width, self.height) // 4
        
        # Define regions for embedding
        regions = [
            (0, 0, corner_size, corner_size),  # Top-left
            (self.width - corner_size, 0, self.width, corner_size),  # Top-right
            (0, self.height - corner_size, corner_size, self.height),  # Bottom-left
            (self.width - corner_size, self.height - corner_size, self.width, self.height),  # Bottom-right
            ((self.width - center_size)//2, (self.height - center_size)//2,  # Center
             (self.width + center_size)//2, (self.height + center_size)//2)
        ]
        
        # Embed data in each region
        for region in regions:
            x1, y1, x2, y2 = region
            region_pixels = pixels[y1:y2, x1:x2].flatten()
            
            # Generate secure sequence for this region
            embedding_indices = generate_secure_sequence(
                min(len(binary_data), len(region_pixels)),
                f"{key}_{x1}_{y1}",
                len(region_pixels)
            )
            
            # Embed data
            for idx, bit in zip(embedding_indices, binary_data):
                region_pixels[idx] = (region_pixels[idx] & ~1) | int(bit)
                
            pixels[y1:y2, x1:x2] = region_pixels.reshape(y2-y1, x2-x1, -1)
            
        self.pixels = pixels
        
    def extract_invisible_watermark(self, key, data_length):
        """Extract invisible watermarks from all regions"""
        extracted_data = []
        corner_size = min(self.width, self.height) // 8
        center_size = min(self.width, self.height) // 4
        
        regions = [
            (0, 0, corner_size, corner_size),
            (self.width - corner_size, 0, self.width, corner_size),
            (0, self.height - corner_size, corner_size, self.height),
            (self.width - corner_size, self.height - corner_size, self.width, self.height),
            ((self.width - center_size)//2, (self.height - center_size)//2,
             (self.width + center_size)//2, (self.height + center_size)//2)
        ]
        
        for region in regions:
            x1, y1, x2, y2 = region
            region_pixels = self.pixels[y1:y2, x1:x2].flatten()
            
            embedding_indices = generate_secure_sequence(
                data_length * 8,
                f"{key}_{x1}_{y1}",
                len(region_pixels)
            )
            
            binary_data = ''.join(str(region_pixels[i] & 1) for i in embedding_indices)
            try:
                data = bytes(int(binary_data[i:i+8], 2) for i in range(0, len(binary_data), 8))
                extracted_data.append(data.decode().rstrip('\x00'))
            except:
                continue
                
        return list(set(extracted_data))  # Return unique extracted watermarks
        
    def save(self, output_path):
        """Save the watermarked image"""
        # Convert RGBA to RGB if necessary
        if self.pixels.shape[2] == 4:  # If the image has an alpha channel
            img = Image.fromarray(self.pixels, 'RGBA').convert('RGB')
        else:
            img = Image.fromarray(self.pixels)
    
        img.save(output_path)

        
    def verify_integrity(self, key, original_data):
        """Verify if any watermarks match the original data"""
        extracted = self.extract_invisible_watermark(key, len(original_data))
        return any(mark == original_data for mark in extracted)

# Example usage
def protect_image(input_path, output_path, watermark_text, secret_key):
    protector = WatermarkProtection(input_path)
    
    # Add visible watermarks
    protector.add_visible_watermark(watermark_text)
    
    # Add invisible watermarks
    protector.add_invisible_watermark(watermark_text, secret_key)
    
    # Save protected image
    protector.save(output_path)
    return protector

def main():
    # Input details
    input_image = "original_image.png"  # Path to the original image
    output_image = "watermarked_image.png"  # Path for the output watermarked image
    watermark_text = "Protected by Watermark"
    secret_key = "supersecretkey123"
    message_to_embed = "Hidden watermark message"
    
    # Protect the image with visible and invisible watermarks
    print("\n=== Embedding Watermarks ===")
    protector = WatermarkProtection(input_image)
    
    # Add visible watermark
    print("Adding visible watermark...")
    protector.add_visible_watermark(watermark_text)
    
    # Add invisible watermark
    print("Adding invisible watermark...")
    protector.add_invisible_watermark(message_to_embed, secret_key)
    
    # Save the watermarked image
    protector.save(output_image)
    print(f"Watermarked image saved as {output_image}")
    
    # Verify the invisible watermark
    print("\n=== Verifying Watermark ===")
    extracted_watermarks = protector.extract_invisible_watermark(secret_key, len(message_to_embed))
    if message_to_embed in extracted_watermarks:
        print("Invisible watermark verification successful!")
    else:
        print("Invisible watermark verification failed.")
    
    # Encryption test
    print("\n=== Testing Encryption/Decryption ===")
    print("Generating lattice-based keypair...")
    public_key, private_key = generate_lattice_keypair()
    
    message = "This is a secure message for encryption"
    print(f"Original Message: {message}")
    
    print("Encrypting message...")
    ciphertexts = encrypt_lattice(public_key, message)
    print("Encryption complete.")
    
    print("Decrypting message...")
    decrypted_message = decrypt_lattice(private_key, ciphertexts)
    
    if decrypted_message == message:
        print(f"Decryption successful! Decrypted Message: {decrypted_message}")
    else:
        print("Decryption failed.")
    
    print("\n=== Process Completed ===")

if __name__ == "__main__":
    main()
