import json
import sys

def generate_html(errors, results):
    html = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <title>Results</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container">
            <h1 class="mt-4 mb-4">Results and Errors</h1>
            
            <h2>Errors</h2>
            <table class="table table-bordered">
                <thead>
                    <tr>
                        <th>Error</th>
                    </tr>
                </thead>
                <tbody>
    '''
    if errors:
        for error in errors:
            html += f'<tr><td>{error}</td></tr>'
    else:
        html += '<tr><td>No errors found</td></tr>'
    
    html += '''
                </tbody>
            </table>
            
            <h2>Results</h2>
            <table class="table table-bordered">
                <thead>
                    <tr>
                        <th>Check ID</th>
                        <th>Path</th>
                        <th>Lines</th>
                        <th>Message</th>
                        <th>Fingerprint</th>
                    </tr>
                </thead>
                <tbody>
    '''
    for result in results:
        check_id = result.get('check_id', '')
        path = result.get('path', '')
        lines = result.get('extra', {}).get('lines', '')
        message = result.get('extra', {}).get('message', '')
        fingerprint = result.get('extra', {}).get('fingerprint', '')
        html += f'<tr><td>{check_id}</td><td>{path}</td><td>{lines}</td><td>{message}</td><td>{fingerprint}</td></tr>'
    
    html += '''
                </tbody>
            </table>
        </div>
        
        <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js"></script>
        <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js"></script>
    </body>
    </html>
    '''
    
    return html

def main():
    file_path = sys.argv[1]
    output_path = sys.argv[2]
    with open(file_path, 'r') as file:
        data = json.load(file)
        
    errors = data.get('errors', [])
    results = data.get('results', [])
    
    html = generate_html(errors, results)
    
    with open(output_path + 'index.html', 'w') as file:
        file.write(html)

if __name__ == "__main__":
    main()
