import requests
import os
import base64 # Para VirusTotal API v3
import time
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

REQUEST_TIMEOUT = 50
URLSCAN_WAIT_TIME = 120

class APIChecker:
    def __init__(self):
        self.google_api_key = os.getenv('GOOGLE_API_KEY')
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.urlscan_api_key = os.getenv('URLSCAN_API_KEY')
        self.phishing_initiative_key = os.getenv('PHISHING_INITIATIVE_KEY')
        self.session = requests.Session()

    def _make_request(self, method, url, **kwargs):
        """Helper para fazer requisições com timeout e tratamento básico."""
        try:
            kwargs.setdefault('headers', {}).setdefault('User-Agent', 'Phishing-Detector-App/1.1')
            kwargs.setdefault('timeout', REQUEST_TIMEOUT)
            
            response = self.session.request(method, url, **kwargs)
            return response
        except requests.exceptions.Timeout:
            return {'success': False, 'error': f"Timeout na requisição para {url}"}
        except requests.exceptions.RequestException as e:
            return {'success': False, 'error': f"Erro na requisição para {url}: {str(e)}"}

    def check_google_safe_Browse(self, url):
        """
        Verifica URL no Google Safe Browse API v4. # NOME DO SERVIÇO CORRIGIDO
        """
        if not self.google_api_key:
            return {'success': False, 'error': "Chave de API do Google Safe Browse não configurada. Adicione GOOGLE_API_KEY no arquivo .env"}
            
        # URL DA API CORRIGIDA
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.google_api_key}"
        
        payload = {
            "client": {
                "clientId": "phishing-detector-app",
                "clientVersion": "1.5.2"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        response_or_error = self._make_request("POST", api_url, json=payload)
        if isinstance(response_or_error, dict) and not response_or_error.get('success', True):
            return response_or_error
        
        response = response_or_error
        if response.status_code == 200:
            try:
                result = response.json()
                is_safe = not bool(result.get('matches'))
                return {
                    'success': True,
                    'is_safe': is_safe,
                    'threat_types_found': [match['threatType'] for match in result.get('matches', [])] if not is_safe else [],
                    'details': result
                }
            except ValueError:
                return {'success': False, 'error': f"Erro ao decodificar JSON do Google Safe Browse: {response.text[:200]}"}
        elif response.status_code == 400:
             return {'success': False, 'error': f"Requisição inválida para Google Safe Browse (400): {response.text[:200]}"}
        elif response.status_code == 403:
            return {'success': False, 'error': "Chave de API do Google Safe Browse inválida, API não habilitada no projeto ou problema de permissão (403). Verifique sua chave e as configurações no Google Cloud Console."}
        else:
            print(response.text)
            return {
                'success': False,
                'error': f"Erro na API do Google Safe Browse: {response.status_code} - {response.text[:200]}"
            }
            
    def check_virustotal(self, url):
        """
        Verifica URL no VirusTotal usando a API v3.
        """
        if not self.virustotal_api_key:
            return {'success': False, 'error': "Chave de API do VirusTotal não configurada. Adicione VIRUSTOTAL_API_KEY no arquivo .env"}

        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        except Exception as e:
            return {'success': False, 'error': f"Erro ao codificar URL para VirusTotal: {str(e)}"}

        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {
            "x-apikey": self.virustotal_api_key,
            "Accept": "application/json"
        }
        
        response_or_error = self._make_request("GET", api_url, headers=headers)
        if isinstance(response_or_error, dict) and not response_or_error.get('success', True):
            return response_or_error

        response = response_or_error
        if response.status_code == 200:
            try:
                result = response.json()
                attributes = result.get('data', {}).get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                malicious_count = stats.get('malicious', 0)
                suspicious_count = stats.get('suspicious', 0)
                total_scans = sum(stats.values())

                return {
                    'success': True,
                    'malicious': malicious_count,
                    'suspicious': suspicious_count,
                    'total_scans': total_scans,
                    'details': result
                }
            except ValueError:
                return {'success': False, 'error': f"Erro ao decodificar JSON do VirusTotal: {response.text[:200]}"}
        elif response.status_code == 401:
            return {'success': False, 'error': "Chave de API do VirusTotal inválida ou não autorizada (401). Verifique sua chave."}
        elif response.status_code == 404:
            return {'success': True, 'malicious': 0, 'suspicious': 0, 'total_scans': 0, 'status_note': 'URL não encontrada no VirusTotal (404).'}
        elif response.status_code == 429:
            return {'success': False, 'error': "Limite de requisições excedido no VirusTotal (429). Tente novamente mais tarde."}
        else:
            return {
                'success': False,
                'error': f"Erro na API do VirusTotal: {response.status_code} - {response.text[:200]}"
            }

    def check_urlscan(self, url):
        if not self.urlscan_api_key:
            return {'success': False, 'error': "Chave API URLScan.io não configurada."}

        submit_api_url = "https://urlscan.io/api/v1/scan/"
        submit_headers = {
            "API-Key": self.urlscan_api_key,
            "Content-Type": "application/json"
        }
        submit_payload = {"url": url, "visibility": "public"}

        submit_response_obj = self._make_request("POST", submit_api_url, json=submit_payload, headers=submit_headers)
        if isinstance(submit_response_obj, dict) and not submit_response_obj.get('success', True):
            return submit_response_obj

        if submit_response_obj.status_code == 200:
            try:
                submit_result = submit_response_obj.json()
                scan_uuid = submit_result.get('uuid')
                if not scan_uuid:
                    return {'success': False, 'error': "URLScan.io: scan_uuid não encontrado na resposta de submissão.", 'details': submit_result}

                print(f"URLScan.io: Scan submetido para {url}. UUID: {scan_uuid}. Aguardando {URLSCAN_WAIT_TIME}s...")
                time.sleep(URLSCAN_WAIT_TIME)

                result_api_url = f"https://urlscan.io/api/v1/result/{scan_uuid}/"
                get_headers = {
                    "API-Key": self.urlscan_api_key,
                    "Accept": "application/json"
                }
                result_response_obj = self._make_request("GET", result_api_url, headers=get_headers)

                if isinstance(result_response_obj, dict) and not result_response_obj.get('success', True):
                    return result_response_obj
                
                if result_response_obj.status_code == 200:
                    try:
                        scan_report = result_response_obj.json()
                        verdicts = scan_report.get('verdicts', {})
                        overall_verdict = verdicts.get('overall', {})
                        urlscan_verdict = verdicts.get('urlscan', {})

                        is_malicious = overall_verdict.get('malicious', False) or urlscan_verdict.get('malicious', False)
                        score = overall_verdict.get('score', 0)
                        is_suspicious_by_score = score > 0 and not is_malicious

                        return {
                            'success': True,
                            'malicious_verdict': is_malicious,
                            'suspicious_by_score': is_suspicious_by_score,
                            'score': score,
                            'scan_page_url': scan_report.get('task', {}).get('reportURL'),
                            'details': scan_report
                        }
                    except ValueError:
                        return {'success': False, 'error': f"Erro JSON ao buscar resultado URLScan: {result_response_obj.text[:200]}"}
                elif result_response_obj.status_code == 404:
                    return {'success': False, 'error': f"Scan do URLScan.io não encontrado ou não finalizado (404) para UUID {scan_uuid}. Tente aumentar URLSCAN_WAIT_TIME."}
                else:
                    return {'success': False, 'error': f"Erro ao buscar resultado URLScan ({result_response_obj.status_code}): {result_response_obj.text[:200]}"}

            except ValueError:
                return {'success': False, 'error': f"Erro JSON na submissão ao URLScan: {submit_response_obj.text[:200]}"}
            except Exception as e:
                return {'success': False, 'error': f"Erro inesperado no URLScan: {str(e)}"}
        
        elif submit_response_obj.status_code == 400:
            return {'success': False, 'error': f"Requisição inválida para URLScan (400): {submit_response_obj.text[:200]}"}
        elif submit_response_obj.status_code == 401:
            return {'success': False, 'error': "Chave API URLScan.io inválida (401)."}
        elif submit_response_obj.status_code == 429:
            return {'success': False, 'error': "Limite de reqs. URLScan.io (429)."}
        else:
            return {'success': False, 'error': f"Erro ao submeter ao URLScan ({submit_response_obj.status_code}): {submit_response_obj.text[:200]}"}

    def check_phishing_initiative(self, url):
        if not self.phishing_initiative_key:
            print("DEBUG: Chave do Phishing Initiative não configurada")
            return {'success': False, 'error': "Chave de API do Phishing Initiative não configurada. Adicione PHISHING_INITIATIVE_KEY no arquivo .env"}

        api_url = "https://phishing-initiative.eu/api/v1/urls/lookup/"
        headers = {
            "Authorization": f"Token {self.phishing_initiative_key}",
            "Accept": "application/json"
        }
        params = {"url": url}

        print(f"DEBUG: Fazendo requisição para Phishing Initiative: {api_url}")
        response_or_error = self._make_request("GET", api_url, headers=headers, params=params)
        if isinstance(response_or_error, dict) and not response_or_error.get('success', True):
            print(f"DEBUG: Erro na requisição: {response_or_error}")
            return response_or_error

        response = response_or_error
        print(f"DEBUG: Status code da resposta: {response.status_code}")
        print(f"DEBUG: Conteúdo da resposta: {response.text[:200]}")

        if response.status_code == 200:
            try:
                result_list = response.json()
                if not isinstance(result_list, list) or len(result_list) == 0:
                    return {'success': False, 'error': "Resposta inválida do Phishing Initiative: lista vazia ou formato incorreto"}
                
                result = result_list[0]
                tag = result.get('tag')
                tag_label = result.get('tag_label', 'unknown')
                
                # tag: -1 = not submitted, 0 = unknown, 1 = phishing, 2 = clean
                is_safe = tag == 2
                is_phishing = tag == 1
                
                return {
                    'success': True,
                    'is_safe': is_safe,
                    'is_phishing': is_phishing,
                    'tag_label': tag_label,
                    'details': result
                }
            except (ValueError, IndexError) as e:
                print(f"DEBUG: Erro ao processar resposta: {str(e)}")
                return {'success': False, 'error': f"Erro ao processar resposta do Phishing Initiative: {response.text[:200]}"}
        elif response.status_code == 401:
            return {'success': False, 'error': "Chave de API do Phishing Initiative inválida (401). Verifique sua chave."}
        elif response.status_code == 429:
            return {'success': False, 'error': "Limite de requisições excedido no Phishing Initiative (429). Tente novamente mais tarde."}
        else:
            return {
                'success': False,
                'error': f"Erro na API do Phishing Initiative: {response.status_code} - {response.text[:200]}"
            }

    def check_all_apis(self, url):
        results = {
            'url': url,
            'apis': {},
            'is_overall_suspicious': False, 
            'overall_risk_level': 'baixo'
        }
        
        # Google Safe Browse
        google_result = self.check_google_safe_Browse(url) 
        results['apis']['google_safe_Browse'] = google_result
        
        # VirusTotal
        vt_result = self.check_virustotal(url)
        results['apis']['virustotal'] = vt_result

        # URLScan.io
        urlscan_result = self.check_urlscan(url)
        results['apis']['urlscan'] = urlscan_result

        # Phishing Initiative
        phishing_initiative_result = self.check_phishing_initiative(url)
        results['apis']['phishing_initiative'] = phishing_initiative_result

        # Lógica para determinar o resultado e risco geral
        current_risk_priority = 0
        risk_priority_map = {
            'baixo': 0, 'médio': 1, 'medio_suspeito_vt': 2, 'medio_suspeito_urlscan': 2,
            'alto': 3, 'alto_detectado_vt': 4, 'alto_risco_conhecido': 4, 'alto_detectado_urlscan': 4,
            'muito_alto_phishing_confirmado': 5
        }
        
        # Google Safe Browse
        if google_result.get('success') and not google_result.get('is_safe', True):
            results['is_overall_suspicious'] = True
            risk_name = 'alto_risco_conhecido'
            if risk_priority_map.get(risk_name, 0) > current_risk_priority:
                results['overall_risk_level'] = risk_name
                current_risk_priority = risk_priority_map.get(risk_name, 0)
        
        # VirusTotal
        if vt_result.get('success'):
            malicious = vt_result.get('malicious', 0)
            suspicious = vt_result.get('suspicious', 0)
            risk_name = results['overall_risk_level']
            
            if malicious > 0:
                results['is_overall_suspicious'] = True
                risk_name = 'alto_detectado_vt'
                if risk_priority_map.get(risk_name, 0) > current_risk_priority:
                    results['overall_risk_level'] = risk_name
                    current_risk_priority = risk_priority_map.get(risk_name, 0)
            elif suspicious > 0:
                if not results['is_overall_suspicious'] or current_risk_priority < risk_priority_map['medio_suspeito_vt']:
                    results['is_overall_suspicious'] = True
                    risk_name = 'medio_suspeito_vt'
                    if risk_priority_map.get(risk_name, 0) > current_risk_priority:
                        results['overall_risk_level'] = risk_name

        # URLScan.io
        if urlscan_result.get('success'):
            is_malicious_us = urlscan_result.get('malicious_verdict', False)
            is_suspicious_us = urlscan_result.get('suspicious_by_score', False)
            risk_name = results['overall_risk_level']

            if is_malicious_us:
                results['is_overall_suspicious'] = True
                risk_name = 'alto_detectado_urlscan'
                if risk_priority_map.get(risk_name, 0) > current_risk_priority:
                    results['overall_risk_level'] = risk_name
                    current_risk_priority = risk_priority_map.get(risk_name, 0)
            elif is_suspicious_us:
                if not results['is_overall_suspicious'] or current_risk_priority < risk_priority_map['medio_suspeito_urlscan']:
                    results['is_overall_suspicious'] = True
                    risk_name = 'medio_suspeito_urlscan'
                    if risk_priority_map.get(risk_name, 0) > current_risk_priority:
                        results['overall_risk_level'] = risk_name

        # Phishing Initiative
        if phishing_initiative_result.get('success'):
            if phishing_initiative_result.get('is_phishing', False):
                results['is_overall_suspicious'] = True
                risk_name = 'muito_alto_phishing_confirmado'
                if risk_priority_map.get(risk_name, 0) > current_risk_priority:
                    results['overall_risk_level'] = risk_name
                    current_risk_priority = risk_priority_map.get(risk_name, 0)
        
        if results['is_overall_suspicious'] and results['overall_risk_level'] == 'baixo':
            results['overall_risk_level'] = 'médio'
            
        return results

if __name__ == '__main__':

    checker = APIChecker()
    
    test_urls = [
        "http://testphp.vulnweb.com/",
        "https://www.google.com",
    ]

    for u in test_urls:
        print(f"\n--- Verificando URL: {u} ---")
        api_check_results = checker.check_all_apis(u)
        print(f"Resultado Geral Suspeito: {api_check_results.get('is_overall_suspicious')}")
        print(f"Nível de Risco Geral: {api_check_results.get('overall_risk_level')}")

        if 'google_safe_Browse' in api_check_results['apis']:
            print("\nGoogle Safe Browse:")
            gsb_res = api_check_results['apis']['check_google_safe_Browse']
            if gsb_res.get('success'):
                print(f"  É seguro: {gsb_res.get('is_safe')}")
                if not gsb_res.get('is_safe'):
                    print(f"  Tipos de ameaça: {gsb_res.get('threat_types_found')}")
            else:
                print(f"  Erro: {gsb_res.get('error')}")

        if 'virustotal' in api_check_results['apis']:
            print("\nVirusTotal (API v3):")
            vt_res = api_check_results['apis']['virustotal']
            if vt_res['success']:
                if vt_res.get('status_note'):
                    print(f"  Nota: {vt_res.get('status_note')}")
                print(f"  Detecções Maliciosas: {vt_res.get('malicious', 0)}")
                print(f"  Detecções Suspeitas: {vt_res.get('suspicious', 0)}")
                print(f"  Total de Scans Considerados: {vt_res.get('total_scans', 0)}")
            else:
                print(f"  Erro: {vt_res.get('error')}")

        if 'urlscan' in api_check_results['apis']:
            print("\nURLScan.io:")
            us_res = api_check_results['apis']['urlscan']
            if us_res['success']:
                print(f"  Detecções Maliciosas: {us_res.get('malicious', 0)}")
                print(f"  Detecções Suspeitas: {us_res.get('suspicious', 0)}")
                print(f"  Total de Scans Considerados: {us_res.get('total_scans', 0)}")
                print(f"  Link do Scan: {us_res.get('scan_url')}")
            else:
                print(f"  Erro: {us_res.get('error')}")
        print("----------------------------------")