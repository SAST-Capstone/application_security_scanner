from flask import Flask, request, redirect
import subprocess
import os

# Instantiate the Flask application
app = Flask(__name__)

@app.route('/')
def index():
    return redirect('/static/index.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files.get('fileToUpload')
        if file and file.filename:
            uploads_dir = os.path.join(app.root_path, 'uploads')
            os.makedirs(uploads_dir, exist_ok=True)
            filepath = os.path.join(uploads_dir, file.filename)
            file.save(filepath)

            json_output_path = os.path.join(uploads_dir, 'output.json')
            try:
                subprocess.run(['python3', '/home/ahmed/application_security_scanner/scanner_code/scanner_wrapper/webappscan.py', filepath, '/home/ahmed/application_security_scanner/scanner_code/scanner_rules/custom_rules', json_output_path], check=True)
                subprocess.run(['python3', '/home/ahmed/application_security_scanner/scanner_code/scanner_wrapper/json_to_html.py', json_output_path, '/var/www/html/static/'], check=True)
            except subprocess.CalledProcessError as e:
                print(f"An error occurred: {e}")
                return "An error occurred during file processing."

            return redirect('/static/index.html')
        else:
            return "No file uploaded."
    else:
        return '''
            <!doctype html>
            <html>
            <head><title>Upload new File</title></head>
            <body>
                <h1>Upload new File</h1>
                <form method="post" action="/upload" enctype="multipart/form-data">
                    <input type="file" name="fileToUpload">
                    <input type="submit" value="Upload">
                </form>
            </body>
            </html>
            '''

if __name__ == '__main__':
    app.run()
