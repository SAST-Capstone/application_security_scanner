import json
import sys
from collections import Counter

def count_rules(results):
    rule_counts = Counter(result.get('check_id', '').split('.')[-1] for result in results)
    return dict(rule_counts)

def generate_html(results):
    rule_counts = count_rules(results)
    total_vulnerabilities = sum(rule_counts.values())
    unique_rules = set(result.get('check_id', '').split('.')[-1] for result in results)
    unique_paths = set(result.get('path', '') for result in results)

    # Construct the summary section
    summary_html = '<div class="summary-section">'
    summary_html += f'<h3>Summary</h3>'
    summary_html += f'<p>Total Number of Vulnerabilities: {total_vulnerabilities}</p>'
    summary_html += '<ul>'
    for rule, count in rule_counts.items():
        summary_html += f'<li>{rule}: {count}</li>'
    summary_html += '</ul>'
    summary_html += '</div>'

    # Construct dropdown menus for rules and paths
    rules_dropdown = '<select id="rulesDropdown" onchange="filterResults()"><option value="">Select Rule</option>'
    for rule in unique_rules:
        rules_dropdown += f'<option value="{rule}">{rule}</option>'
    rules_dropdown += '</select>'

    paths_dropdown = '<select id="pathsDropdown" onchange="filterResults()"><option value="">Select Path</option>'
    for path in unique_paths:
        paths_dropdown += f'<option value="{path}">{path}</option>'
    paths_dropdown += '</select>'

    rules_json = json.dumps(list(rule_counts.keys()))
    counts_json = json.dumps(list(rule_counts.values()))

    html = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <title>Results</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet">
        <style>
            /* Your existing CSS styles */
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
            .centered-tabs {
                display: flex;
                justify-content: center;
            }
            .nav-tabs {
                float: none;
                display: inline-block;
            }
            .tab-content {
                text-align: center;
            }
            .chart-container {
                width: 50%;
                margin: auto;
            }
            .summary-section {
                margin-bottom: 20px;
            }
            .filter-section {
                text-align: center;
                margin-bottom: 20px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1 class="mt-4 mb-4 text-center">Results</h1>
    '''

    html += summary_html  # Add the summary section here

    # Add the dropdown menus
    html += '<div class="filter-section">'
    html += '<label for="rulesDropdown">Filter by Rule:</label>' + rules_dropdown
    html += '<label for="pathsDropdown">Filter by Path:</label>' + paths_dropdown
    html += '</div>'

    html += '''
            <!-- Centered Tab navigation -->
            <div class="centered-tabs">
                <ul class="nav nav-tabs" id="resultTabs" role="tablist">
                    <li class="nav-item">
                        <a class="nav-link active" id="table-tab" data-toggle="tab" href="#table" role="tab" aria-controls="table" aria-selected="true">Table View</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" id="chart-tab" data-toggle="tab" href="#chart" role="tab" aria-controls="chart" aria-selected="false">Chart View</a>
                    </li>
                </ul>
            </div>

            <div class="tab-content" id="resultTabsContent">
                <div class="tab-pane fade show active" id="table" role="tabpanel" aria-labelledby="table-tab">
                    <div class="center-div">
                        <table class="table table-bordered center-table" id="resultsTable">
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
        rule = result.get('check_id', '').split('.')[-1]
        path = result.get('path', '')
        suspected_code = result.get('extra', {}).get('lines', '')
        message = result.get('extra', {}).get('message', '')
        suggestion = result.get('extra', {}).get('fix', '')

        html += f'<tr><td>{rule}</td><td>{path}</td><td>{suspected_code}</td><td>{message}</td><td>{suggestion}</td></tr>'

    html += '''
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="tab-pane fade" id="chart" role="tabpanel" aria-labelledby="chart-tab">
                    <div class="chart-container">
                        <canvas id="resultChart"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <!-- Chart.js Library -->
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <!-- Custom Script for Pie Chart -->
        <script>
            const ctx = document.getElementById('resultChart').getContext('2d');
            const ruleNames = ''' + rules_json + ''';
            const ruleCounts = ''' + counts_json + ''';
            new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: ruleNames,
                    datasets: [{
                        label: 'Rule Count',
                        data: ruleCounts,
                        backgroundColor: [
                            'rgba(255, 99, 132, 0.2)',
                            'rgba(54, 162, 235, 0.2)',
                            'rgba(255, 206, 86, 0.2)',
                            'rgba(75, 192, 192, 0.2)',
                            'rgba(153, 102, 255, 0.2)',
                            'rgba(255, 159, 64, 0.2)'
                        ],
                        borderColor: [
                            'rgba(255, 99, 132, 1)',
                            'rgba(54, 162, 235, 1)',
                            'rgba(255, 206, 86, 1)',
                            'rgba(75, 192, 192, 1)',
                            'rgba(153, 102, 255, 1)',
                            'rgba(255, 159, 64, 1)'
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false
                }
            });
        </script>

        <!-- JavaScript for Filtering -->
        <script>
            function filterResults() {
                var ruleFilter = document.getElementById('rulesDropdown').value.toLowerCase();
                var pathFilter = document.getElementById('pathsDropdown').value.toLowerCase();
                var table = document.getElementById('resultsTable');
                var tr = table.getElementsByTagName('tr');

                for (var i = 0; i < tr.length; i++) {
                    var tdRule = tr[i].getElementsByTagName('td')[0];
                    var tdPath = tr[i].getElementsByTagName('td')[1];
                    if (tdRule && tdPath) {
                        var textRule = tdRule.textContent || tdRule.innerText;
                        var textPath = tdPath.textContent || tdPath.innerText;
                        if (textRule.toLowerCase().indexOf(ruleFilter) > -1 && textPath.toLowerCase().indexOf(pathFilter) > -1) {
                            tr[i].style.display = '';
                        } else {
                            tr[i].style.display = 'none';
                        }
                    }
                }
            }
        </script>

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

