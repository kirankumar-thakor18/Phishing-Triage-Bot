import os
from flask import Flask, render_template, request, redirect, url_for
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_email():
    # Yahan hum aage email parsing aur API integration ka logic likhenge
    if 'email_file' not in request.files:
        return redirect(request.url)
    
    file = request.files['email_file']
    if file.filename == '':
        return redirect(request.url)
    
    if file:
        # Filhal ke liye sirf file ka naam print karke check karte hain
        filename = file.filename
        return f"File uploaded successfully: {filename}. Next step mein iska parsing code add karenge!"

if __name__ == '__main__':
    app.run(debug=True)