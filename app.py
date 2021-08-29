from json import loads
from io import StringIO
from requests import post
from pandas import DataFrame, read_csv
from flask import Flask, request, render_template, url_for, redirect

app = Flask(__name__)

@app.route('/results', methods=['GET'])
def results():
    return render_template('results.html', predicted=DataFrame.from_dict(loads(request.args['predicted'])))

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files['log_file'].read()
        df = read_csv(StringIO(file.decode('utf-8')), sep=',')
        predicted = post("http://localhost:5000/predict", json={"features": df.to_json(orient='records')}).json()
        return redirect(url_for('results', predicted=predicted))

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, port=3000)