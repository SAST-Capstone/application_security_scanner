import json
import sys

def generate_html(results):
    html = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <title>Results</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body, html {
                height: 100%;
                margin: 0;
            }
            .container {
                max-width: 100%;
            }
            .center-div {
                display: flex;
                justify-content: center;
            }
            .center-table {
                margin: auto;
                float: none;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1 class="mt-4 mb-4 text-center">Results</h1>
            <div class="center-div">
                <table class="table table-bordered center-table">
                    <thead>
                        <tr>
                            <th>Rules</th>
                            <th>Path</th>
                            <th>Suspected Code</th>
                            <th>Message</th>
                            <th>Suggestion</th>
                        </tr>
                    </thead>
                    <tbody>
    '''
    for result in results:
        rule = result.get('check_id', '')
        path = result.get('path', '')
        suspected_code = result.get('extra', {}).get('lines', '')
        message = result.get('extra', {}).get('message', '')
        suggestion = result.get('extra', {}).get('fix', '')

        # Extract the last part of the rule
        rule_parts = rule.split('.')
        last_part = rule_parts[-1]

        html += f'<tr><td>{last_part}</td><td>{path}</td><td>{suspected_code}</td><td>{message}</td><td>{suggestion}</td></tr>'

    html += '''
                    </tbody>
                </table>
            </div>
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

    results = data.get('results', [])

    html = generate_html(results)

    with open(output_path + 'index.html', 'w') as file:
        file.write(html)

if __name__ == "__main__":
    main()
