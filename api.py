import json
from config import *
import tensorflow as tf
from infer import predict
from pickle import load as pload
from flask import Flask, jsonify, request
from tensorflow.keras.models import load_model
from tensorflow.config import list_physical_devices
from pandas import json_normalize, DataFrame, Series
from tensorflow.config.experimental import set_memory_growth

app = Flask(__name__)

for device in list_physical_devices('GPU') : set_memory_growth(device, True)

model = load_model(MODEL_PATH)
scaler = pload(open(SCALER_PATH, 'rb'))

@app.route('/predict', methods=['POST'])
def predict_api():
  if request.method == 'POST':
    df = json_normalize(json.loads(request.json['features']))
    
    X = scaler.transform(df[SELECTED_FEATURES].values)
    
    class_name, class_id, confidence_score = predict(X, model=model, labels=LABELS)
    
    result = DataFrame(columns=['Packet ID', 'Class ID', 'Class Name', 'Confidence Score'])
    
    ids = [i for i in range(len(class_id))]
    
    result['Source IP Address'] = df['src_ip_address']
    result['Server IP'] = df['vm_ip_address']
    result['VM Name'] = df['machine_name']
    result['Packet ID'] = Series(ids, index=df.index[:len(ids)])
    result['Class ID'] = Series(class_id, index=df.index[:len(class_id)])
    result['Class Name'] = Series(class_name, index=df.index[:len(class_name)])
    result['Confidence Score'] = Series(confidence_score, index=df.index[:len(confidence_score)])

    return jsonify(result.to_json(orient='records'))

  else:
    return 'Invalid request'

if __name__ == '__main__':
  app.run(debug=True, port=5000)