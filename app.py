from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
import os

dotenv_loaded_successfully = load_dotenv()
if dotenv_loaded_successfully:
    print("DEBUG: Arquivo .env carregado com sucesso por app.py.")
else:
    print("DEBUG: Arquivo .env não encontrado ou não pôde ser carregado por app.py.")

from modules.basic_checks import check_url as perform_basic_checks
from modules.api_checks import APIChecker
from modules import advanced_checks

app = Flask(__name__)
api_checker = APIChecker()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check_basic', methods=['POST'])
def route_check_basic_only():
    data = request.get_json()
    url_to_check = data.get('url', '')
    if not url_to_check:
        return jsonify({'error': 'URL não fornecida'}), 400
    
    print(f"DEBUG (app.py /check_basic): Iniciando verificações BÁSICAS para: {url_to_check}")
    basic_results = perform_basic_checks(url_to_check)
    print(f"DEBUG (app.py /check_basic): Resultados básicos retornados: {basic_results.get('is_suspicious')}, {basic_results.get('risk_level')}")
    return jsonify(basic_results)

@app.route('/check/google', methods=['POST'])
def check_google_route():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({'success': False, 'error': 'URL não fornecida'}), 400
    
    result = api_checker.check_google_safe_Browse(url) 
    return jsonify(result)

@app.route('/check/virustotal', methods=['POST'])
def check_virustotal_route():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({'success': False, 'error': 'URL não fornecida'}), 400
    
    result = api_checker.check_virustotal(url)
    return jsonify(result)

@app.route('/check/urlscan', methods=['POST'])
def check_urlscan_route():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({'success': False, 'error': 'URL não fornecida'}), 400
    
    result = api_checker.check_urlscan(url)
    return jsonify(result)

@app.route('/check/phishing_initiative', methods=['POST'])
def check_phishing_initiative_route():
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({'success': False, 'error': 'URL não fornecida'}), 400
    
    print(f"DEBUG: Verificando URL no Phishing Initiative: {url}")
    result = api_checker.check_phishing_initiative(url)
    print(f"DEBUG: Resultado do Phishing Initiative: {result}")
    return jsonify(result)

@app.route('/advanced/domain_age', methods=['POST'])
def route_advanced_domain_age():
    data = request.get_json()
    url_to_check = data.get('url', '')
    if not url_to_check: return jsonify({'success': False, 'error': 'URL não fornecida'}), 400
    
    hostname = advanced_checks.get_domain_from_url(url_to_check)
    main_domain_for_whois = advanced_checks.extract_main_domain(hostname) if hostname else None
    
    if not main_domain_for_whois:
        return jsonify({'success': False, 'error': 'Hostname inválido para WHOIS'}), 400
        
    result = advanced_checks.analyze_domain_age(main_domain_for_whois)
    return jsonify(result)

@app.route('/advanced/dynamic_dns', methods=['POST'])
def route_advanced_dynamic_dns():
    data = request.get_json()
    url_to_check = data.get('url', '')
    if not url_to_check: return jsonify({'success': False, 'error': 'URL não fornecida'}), 400
    
    hostname = advanced_checks.get_domain_from_url(url_to_check)
    if not hostname:
        return jsonify({'success': False, 'error': 'Hostname não pôde ser extraído da URL'}), 400
        
    result = advanced_checks.check_dynamic_dns(hostname)
    return jsonify(result)

@app.route('/advanced/ssl_certificate', methods=['POST'])
def route_advanced_ssl_certificate():
    data = request.get_json()
    url_to_check = data.get('url', '')
    if not url_to_check: return jsonify({'success': False, 'error': 'URL não fornecida'}), 400
        
    hostname = advanced_checks.get_domain_from_url(url_to_check)
    if not hostname:
        return jsonify({'success': False, 'error': 'Hostname não pôde ser extraído da URL'}), 400
        
    result = advanced_checks.analyze_ssl_certificate(hostname)
    return jsonify(result)

@app.route('/advanced/redirects', methods=['POST'])
def route_advanced_redirects():
    data = request.get_json()
    url_to_check = data.get('url', '')
    if not url_to_check: return jsonify({'success': False, 'error': 'URL não fornecida'}), 400
        
    result = advanced_checks.check_redirects(url_to_check)
    return jsonify(result)

@app.route('/advanced/brand_similarity', methods=['POST'])
def route_advanced_brand_similarity():
    data = request.get_json()
    url_to_check = data.get('url', '')
    if not url_to_check: return jsonify({'success': False, 'error': 'URL não fornecida'}), 400
        
    hostname = advanced_checks.get_domain_from_url(url_to_check)
    if not hostname:
        return jsonify({'success': False, 'error': 'Hostname não pôde ser extraído da URL'}), 400
        
    result = advanced_checks.check_brand_similarity(hostname)
    return jsonify(result)

@app.route('/advanced/page_content', methods=['POST'])
def route_advanced_page_content():
    data = request.get_json()
    url_to_check = data.get('url', '')
    if not url_to_check: return jsonify({'success': False, 'error': 'URL não fornecida'}), 400
        
    result = advanced_checks.analyze_page_content(url_to_check)
    return jsonify(result)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)