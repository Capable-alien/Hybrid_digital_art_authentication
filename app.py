from flask import Flask, request, render_template, redirect, url_for, send_from_directory, flash
from werkzeug.utils import secure_filename
import os
from crypto import WatermarkProtection, encrypt_lattice, decrypt_lattice, generate_lattice_keypair
import hashlib

app = Flask(__name__)

# Configurations
UPLOAD_FOLDER = 'D:/New1/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Check allowed extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/submit_artwork', methods=['POST'])
def submit_artwork():
    if 'image' not in request.files:
        return redirect(request.url)
    
    image = request.files['image']
    if image.filename == '' or not allowed_file(image.filename):
        return redirect(request.url)
    
    # Collect artist authentication data
    artist_name = request.form.get('artist_name')
    artwork_title = request.form.get('artwork_title')
    creation_date = request.form.get('creation_date')
    unique_identifier = request.form.get('unique_identifier')
    
    if not (artist_name and artwork_title and creation_date and unique_identifier):
        return "All fields are required", 400

    # Encryption: Generate encryption keys and encrypt artist details
    public_key, private_key = generate_lattice_keypair()
    artist_details = f"{artist_name}|{artwork_title}|{creation_date}|{unique_identifier}"
    encrypted_details = encrypt_lattice(public_key, artist_details)
    
    # Save the original image file
    filename = secure_filename(image.filename)
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    image.save(image_path)
    
    # Watermark Protection
    secret_key = "static_secret_key"  # Static secret key for watermark embedding
    protector = WatermarkProtection(image_path)
    protector.add_visible_watermark(artist_name)
    combined_watermark = f"Encrypted:{str(encrypted_details)}"
    protector.add_invisible_watermark(combined_watermark, secret_key)
    
    # Save the watermarked image
    watermarked_image_path = os.path.join(app.config['UPLOAD_FOLDER'], f"watermarked_{filename}")
    protector.save(watermarked_image_path)
    
    # Compute the final integrity hash based on the watermarked image
    with open(watermarked_image_path, 'rb') as f:
        watermarked_image_data = f.read()
    final_integrity_hash = hashlib.blake2b(watermarked_image_data).hexdigest()
    
    # Save the final integrity hash to a file
    hash_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}_hash.txt")
    with open(hash_file_path, 'w') as hash_file:
        hash_file.write(final_integrity_hash)
    
    # **Automatic Verification Step**
    with open(watermarked_image_path, 'rb') as f:
        current_image_data = f.read()
    recomputed_hash = hashlib.blake2b(current_image_data).hexdigest()

    verification_result = "Integrity Verified: The image is unaltered." if recomputed_hash == final_integrity_hash else "Integrity Check Failed: The image has been modified."

    # Decrypt the artist details (for demonstration)
    decrypted_details = decrypt_lattice(private_key, encrypted_details)
    print(f"Decrypted Artist Details: {decrypted_details}")
    
    return render_template('success.html', 
                           watermarked_image=watermarked_image_path, 
                           hash_file=hash_file_path, 
                           verification_result=verification_result)


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True)
