import pickle
import gzip
import time
from flask import Flask, request, render_template, jsonify, Response
import requests
import json
from url_processing import feature_extractor, url_fetcher
from cybercrime_stations import get_stations

# Load the ML model
with gzip.open('ML_Model/rf_phishing_model.pkl.gz', 'rb') as file:
    detection_model = pickle.load(file)

app = Flask(__name__)

# ------------- Phishing Detection Routes --------------

@app.route('/')
def homepage():
    return render_template('input_based.html')

@app.route('/predict', methods=['GET', 'POST'])
def predictor():
    if request.method == 'POST':
        websiteurl = request.form['websiteurl']
        features = feature_extractor(websiteurl)
        probabilities = detection_model.predict_proba(features)
        
        phishing_percentage = probabilities[0][1] * 100
        genuine_percentage = probabilities[0][0] * 100
        
        if phishing_percentage > 50:
            prediction = 'Likely Phishing'
        else:
            prediction = 'Likely Genuine'
        
        return render_template('input_based.html',
                               prediction=prediction,
                               phishing_percentage=round(phishing_percentage, 2),
                               genuine_percentage=round(genuine_percentage, 2))

@app.route('/detect')
def detect_ui():
    return render_template('real_time.html')

def real_time_detect(urls):
    for some_url in urls:
        time.sleep(2)
        features = feature_extractor(some_url)
        probabilities = detection_model.predict_proba(features)
        
        phishing_percentage = probabilities[0][1] * 100
        genuine_percentage = probabilities[0][0] * 100
        
        if phishing_percentage > 50:
            yield f'data: May be phishing: {some_url} Chance of phishing: {phishing_percentage:.2f}%, Chance of genuine: {genuine_percentage:.2f}%\n\n'
        else:
            yield f'data: May be safe: {some_url} Chance of phishing: {phishing_percentage:.2f}%, Chance of genuine: {genuine_percentage:.2f}%\n\n'

@app.route('/phishstream')
def phishstream():
    urls = url_fetcher()
    if not urls:
        return render_template('real_time.html', error_line='Sorry, URLs could not be fetched.')
    else:
        return Response(real_time_detect(urls), mimetype='text/event-stream')

# ------------- Cybercrime Station Locator Routes --------------

@app.route('/map')
def police_locator():
    return render_template('map.html')

@app.route('/api/search-stations')
def search_stations():
    city = request.args.get('city', '').strip().lower()
    country = request.args.get('country', 'india').strip().lower()
    
    if not city:
        return jsonify({"error": "City parameter is required"}), 400
    
    # 1. Check our verified dataset first
    stations = get_stations(country, city)
    
    # 2. If no results, try OpenStreetMap as fallback
    if not stations:
        stations = query_osm_cyber_stations(city)
    
    # 3. If still no results, try government APIs
    if not stations and country == "india":
        stations = query_india_gov_api(city)
    
    if not stations:
        return jsonify({"error": "No cybercrime stations found for this location"}), 404
    
    return jsonify({
        "city": city.capitalize(),
        "country": country.capitalize(),
        "stations": stations
    })

def query_osm_cyber_stations(city):
    try:
        overpass_url = "https://overpass-api.de/api/interpreter"
        query = f"""
        [out:json];
        area["name"="{city}"]->.searchArea;
        (
          node["police"="cybercrime"](area.searchArea);
          way["police"="cybercrime"](area.searchArea);
          relation["police"="cybercrime"](area.searchArea);
        );
        out center;
        """
        response = requests.get(overpass_url, params={'data': query}, timeout=10)
        data = response.json()
        
        return [{
            'name': element['tags'].get('name', 'Cyber Crime Police Station'),
            'address': element['tags'].get('addr:full', ''),
            'lat': element.get('lat', element.get('center', {}).get('lat')),
            'lng': element.get('lon', element.get('center', {}).get('lon')),
            'source': 'OpenStreetMap',
            'verified': False
        } for element in data.get('elements', []) if element.get('tags')]
    except Exception:
        return []

def query_india_gov_api(city):
    """Placeholder for actual government API integration"""
    return []

# ------------- Run the App --------------

if __name__ == '__main__':
    app.run(debug=True)
