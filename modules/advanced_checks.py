import whois
import ssl
import socket
import requests
from urllib.parse import urlparse, unquote
import re
from datetime import datetime, timezone # Adicionado timezone
from bs4 import BeautifulSoup
import tldextract

DDNS_PROVIDERS = [
    # Serviços gratuitos/populares
    'no-ip.com',
    'duckdns.org',
    'dynu.com',
    'freedns.afraid.org',
    'changeip.com',
    'dynv6.com',
    'tunnelbroker.net',  # Hurricane Electric (IPv6)
    'ipv64.net',
    'now-dns.com',
    'pubyun.com',  # (anteriormente "3322.org")
    'dns.he.net',  # Hurricane Electric DDNS
    'zerigo.com',
    'sitelutions.com',
    'nsupdate.info',
    'twodns.de',
    'dnsomatic.com',
    'loopia.com',  # Apenas para clientes Loopia
    'yi.org',      # Serviço da Yi (câmeras)
    
    # Provedores pagos/empresariais
    'dyn.com',     # Oracle Dyn (pago)
    'easydns.com',
    'zoneedit.com',
    'noip.com',    # Versão paga do No-IP
]

LOGIN_KEYWORDS = [
    'password', 'senha', 'passwd', 'pass', 'secret', 'privatekey',
    'username', 'usuario', 'login', 'email', 'user', 'userid',
    'credit_card', 'cartao_credito', 'cc_number', 'cvv', 'security_code',
    'pin', 'token', 'cpf', 'cnpj', 'cpf_number', 'cnpj_number', 'aluno', 'matricula',
]

# Marcas conhecidas (a mesma lista do basic_checks.py ou uma expandida)
KNOWN_BRAND_KEYWORDS = [
    'google', 'youtube', 'facebook', 'instagram', 'whatsapp', 'twitter', 'x',
    'apple', 'microsoft', 'amazon', 'netflix', 'spotify', 'linkedin', 'tiktok',
    'telegram', 'discord', 'reddit', 'pinterest', 'snapchat', 'zoom', 'skype',
    'ebay', 'aliexpress', 'shopee', 'mercado livre', 'magalu', 'americanas',
    'submarino', 'alibaba', 'walmart', 'target', 'bestbuy', 'rakuten',
    
    # Bancos e Financeiras (globais e brasileiros)
    'paypal', 'visa', 'mastercard', 'amex', 'nubank', 'banco do brasil', 'bradesco',
    'itau', 'caixa', 'santander', 'inter', 'next', 'c6bank', 'picpay', 'pagseguro',
    'mercado pago', 'sicoob', 'sicredi', 'banrisul', 'pan', 'original', 'sofisa',
    'stone', 'banco digital', 'neon', 'will bank', 'btg pactual', 'xp investimentos',
    'rico', 'clear', 'binance', 'coinbase', 'blockchain', 'bitcoin', 'ethereum',
    
    # Varejo e Serviços
    'carrefour', 'casas bahia', 'pontofrio', 'extra', 'havan', 'renner', 'riachuelo',
    'cea', 'marisa', 'lojas americanas', 'fast shop', 'kabum', 'terabyte', 'pichau',
    'dell', 'lenovo', 'samsung', 'lg', 'sony', 'xiaomi', 'motorola', 'asus', 'acer',
    'hp', 'positivo', 'multilaser', 'philco', 'consul', 'braSTEMp', 'electrolux',
    
    # Serviços e Utilitários
    'gmail', 'outlook', 'hotmail', 'yahoo', 'protonmail', 'icloud', 'dropbox',
    'onedrive', 'google drive', 'mega', 'adobe', 'canva', 'wordpress', 'wix',
    'godaddy', 'hostinger', 'uol', 'ig', 'terra', 'globo', 'g1', 'r7', 'uol',
    'oi', 'vivo', 'claro', 'tim', 'nextel', 'algar', 'sercomtel', 'net', 'oi',
    'sky', 'directv', 'oi tv', 'vivo tv', 'claro tv', 'net tv', 'tim tv',
    
    # Automotivo e Transporte
    'uber', '99', 'cabify', 'lyft', 'taxi', 'yellow', 'lime', 'grab', 'didimo',
    'volkswagen', 'fiat', 'chevrolet', 'ford', 'toyota', 'honda', 'hyundai',
    'renault', 'jeep', 'bmw', 'mercedes', 'audi', 'nissan', 'mitsubishi', 'kia',
    'peugeot', 'citroen', 'volvo', 'scania', 'iveco', 'agrale', 'jac', 'caoa',
    'land rover', 'jaguar', 'porsche', 'ferrari', 'lamborghini', 'maserati',
    
    # Governo e Instituições (BR)
    'gov br', 'receita federal', 'inss', 'detran', 'ministerio', 'previdencia',
    'ibge', 'caixa economica', 'correios', 'serpro', 'dataprev', 'sus', 'ans',
    'anatel', 'anvisa', 'bacen', 'bndes', 'pf', 'prf', 'pm', 'pc', 'bombeiros',
    'defensoria', 'mp', 'tj', 'trt', 'tre', 'tse', 'stf', 'stj', 'stm',
    
    # Entretenimento e Cultura
    'disney', 'hbo', 'prime video', 'globoplay', 'disney plus', 'paramount',
    'deezer', 'apple music', 'youtube music', 'twitch', 'crunchyroll', 'funimation',
    'steam', 'epic games', 'origin', 'xbox', 'playstation', 'nintendo', 'riot',
    'ea', 'ubisoft', 'blizzard', 'activision', 'minecraft', 'fortnite', 'league',
    'valorant', 'csgo', 'dota', 'free fire', 'pubg', 'gta', 'fifa', 'pes',
    
    # Viagens e Hospedagem
    'decolar', 'cvc', 'latam', 'gol', 'azul', 'avianca', 'tap', 'emirates',
    'airbnb', 'booking', 'trivago', 'expedia', 'hoteis com', '123milhas',
    'maxmilhas', 'hotelurbano', 'almundo', 'submarino viagens', 'viajanet',
    
    # Saúde e Beleza
    'drogasil', 'droga raia', 'pacheco', 'panvel', 'sao joao', 'drogario',
    'natura', 'avon', 'boticario', 'eudora', 'o boticario', 'souza cruz',
    'johnson', 'roche', 'pfizer', 'astrazeneca', 'janssen', 'butantan',
    'fiocruz', 'fleury', 'hermes pardini', 'delboni', 'santa casa', 'albert',
    'einstein', 'sirio libanes', 'hcor', 'sao luiz', 'porto seguro',
    
    # Educação
    'unesp', 'usp', 'unicamp', 'ufmg', 'ufrj', 'ufrgs', 'ufpr', 'ufscar',
    'puc', 'mackenzie', 'fiap', 'senac', 'senai', 'etec', 'fatec', 'coursera',
    'udemy', 'alura', 'digital house', 'rocketseat', 'trybe', 'kenzie',
    'duolingo', 'khan academy', 'ingles com', 'wizard', 'cellep', 'yazigi',
    'ccaa', 'fisk', 'microlins', 'top gun', 'prepara cursos',
    
    # Outros
    'mcdonalds', 'burger king', 'subway', 'giraffas', 'habibs', 'outback',
    'applebees', 'starbucks', 'coca cola', 'pepsi', 'nestle', 'ambev',
    'heineken', 'skol', 'brahma', 'antarctica', 'itaipava', 'nova schin',
    'petrobras', 'shell', 'ipiranga', 'ale', 'texaco', 'br distribuidora',
    'raizen', 'cosan', 'ioda', 'vale', 'gerdau', 'csn', 'usiminas', 'embraer',
    'suzano', 'fibria', 'brf', 'jbs', 'sadia', 'perdigao', 'seara', 'friboi',
    'cargill', 'bunge', 'amaggi', 'lactalis', 'nestle', 'danone', 'vigor',
    'itambé', 'piá', 'parmalat', 'eletrobras', 'copel', 'cemig', 'sabesp',
    'embasa', 'casan', 'sanepar', 'energisa', 'neoenergia', 'enel', 'light',
    'equatorial', 'elektro', 'cpfl', 'taesa', 'transmissao', 'geracao',
    'distribuicao', 'energetica', 'petroleo', 'gas', 'combustivel', 'energia',
    'mineracao', 'siderurgica', 'metalurgica', 'automotiva', 'farmaceutica',
    'alimentos', 'bebidas', 'varejo', 'varejista', 'atacado', 'atacadista'
]

def extract_main_domain(hostname, use_tldextract=True):
    if not hostname or not isinstance(hostname, str):
        return None
    
    # Remove protocolo e caminhos se presentes
    clean_host = re.sub(r'^https?://|/.*$', '', hostname.split('?')[0].lower())
    
    if use_tldextract:
        try:
            extracted = tldextract.extract(clean_host)
            if not extracted.domain or not extracted.suffix:
                return None
            return f"{extracted.domain}.{extracted.suffix}"
        except Exception:
            pass
    
    parts = [p for p in clean_host.split('.') if p]
    
    if len(parts) < 2:
        return None
    
    CCTLD_SECOND_LEVEL = {
        'uk': ['co', 'gov', 'org', 'ac', 'ltd', 'me', 'net', 'nhs', 'plc', 'sch'],
        'jp': ['co', 'ac', 'go', 'ne', 'or', 'ed', 'gr', 'lg', 'geo'],
        'au': ['com', 'net', 'org', 'edu', 'gov', 'csiro', 'asn', 'id'],
        'br': ['com', 'gov', 'org', 'net', 'edu', 'mil', 'nom'],
        # Adicione outros conforme necessário
    }
    
    tld = parts[-1]
    
    if tld in CCTLD_SECOND_LEVEL and len(parts) >= 3:
        if parts[-2] in CCTLD_SECOND_LEVEL[tld]:
            return ".".join(parts[-3:])
    
    if len(parts) >= 3 and parts[-2] in ['com', 'org', 'net', 'edu', 'gov'] and len(tld) == 2:
        return ".".join(parts[-2:])
    
    return ".".join(parts[-2:]) if len(parts) >= 2 else None

def get_domain_from_url(url):
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url
    try:
        parsed_url = urlparse(url)
        return parsed_url.hostname
    except Exception:
        return None

def analyze_domain_age(url_hostname):
    if not url_hostname:
        return {'success': False, 'error': 'Hostname não fornecido'}
    try:
        domain_info = whois.whois(url_hostname)
        
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            if creation_date.tzinfo is None or creation_date.tzinfo.utcoffset(creation_date) is None:
                now_utc = datetime.now(timezone.utc)
                if creation_date.tzinfo is None:
                    creation_date_utc = creation_date.replace(tzinfo=timezone.utc)
                else:
                    creation_date_utc = creation_date.astimezone(timezone.utc)

                domain_age_days = (now_utc - creation_date_utc).days
            return {
                'success': True,
                'domain_age_days': domain_age_days,
                'creation_date': creation_date.isoformat() if creation_date else None,
                'is_suspicious': domain_age_days < 90
            }
        else:
            return {'success': False, 'error': 'Data de criação não encontrada no WHOIS.'}
    except whois.parser.PywhoisError as e:
        return {'success': False, 'error': f'WHOIS lookup falhou (PywhoisError): Domínio não encontrado ou protegido. Detalhe: {str(e)}'}
    except Exception as e:
        return {'success': False, 'error': f'Erro ao analisar idade do domínio: {str(e)}'}

def check_dynamic_dns(url_hostname):
    if not url_hostname:
        return {'success': False, 'error': 'Hostname não fornecido'}

    try:
        hostname_lower = url_hostname.lower()
        
        is_ddns = any(
            hostname_lower.endswith('.' + provider) or 
            ('.' not in hostname_lower and hostname_lower == provider)
            for provider in DDNS_PROVIDERS
        )

        return {
            'success': True,
            'uses_ddns': is_ddns,
            'is_suspicious': is_ddns
        }

    except Exception as e:
        return {'success': False, 'error': f'Erro ao verificar DDNS: {str(e)}'}

def analyze_ssl_certificate(url_hostname):
    if not url_hostname:
        return {'success': False, 'error': 'Hostname não fornecido'}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((url_hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=url_hostname) as ssock:
                cert = ssock.getpeercert()
        
        if not cert:
            return {'success': True, 'has_ssl': False, 'is_suspicious': True, 'details': 'Nenhum certificado SSL encontrado.'}

        issuer = dict(x[0] for x in cert.get('issuer', []))
        subject = dict(x[0] for x in cert.get('subject', []))
        expires_on_str = cert.get('notAfter')
        
        is_suspicious = False
        suspicion_reasons = []

        if expires_on_str:
            expires_on = datetime.strptime(expires_on_str, '%b %d %H:%M:%S %Y %Z')
            expires_on = expires_on.replace(tzinfo=timezone.utc)
            if expires_on < datetime.now(timezone.utc):
                is_suspicious = True
                suspicion_reasons.append('Certificado SSL expirado.')
            elif (expires_on - datetime.now(timezone.utc)).days < 30:
                is_suspicious = True
                suspicion_reasons.append('Certificado SSL expira em menos de 30 dias.')
        else:
            is_suspicious = True
            suspicion_reasons.append('Data de expiração do SSL não encontrada.')

        subject_alt_names = [name[1] for name in cert.get('subjectAltName', []) if name[0].lower() == 'dns']
        common_name = subject.get('commonName')
        
        valid_for_host = False
        if common_name == url_hostname or f"*.{extract_main_domain(url_hostname)}" == common_name:
            valid_for_host = True
        elif any(sn == url_hostname or (sn.startswith("*.") and url_hostname.endswith(sn[1:])) for sn in subject_alt_names):
            valid_for_host = True
        
        if not valid_for_host:
            is_suspicious = True
            suspicion_reasons.append(f'Certificado SSL não é válido para o hostname "{url_hostname}". Nomes no cert: CN={common_name}, SANs={subject_alt_names}')


        suspicious_issuers_keywords = ['self-signed', 'untrusted', 'example']
        if any(keyword in issuer.get('organizationName', '').lower() for keyword in suspicious_issuers_keywords) or \
           any(keyword in issuer.get('commonName', '').lower() for keyword in suspicious_issuers_keywords):
            is_suspicious = True
            suspicion_reasons.append(f'Emissor do certificado SSL parece suspeito: {issuer.get("commonName", "N/A")}')

        return {
            'success': True,
            'has_ssl': True,
            'issuer': issuer.get('commonName', 'N/A'),
            'organization_issuer': issuer.get('organizationName', 'N/A'),
            'subject_cn': common_name,
            'expires_on': expires_on_str,
            'is_valid_for_host': valid_for_host,
            'is_suspicious': is_suspicious,
            'suspicion_details': suspicion_reasons
        }
    except ssl.SSLCertVerificationError as e:
        return {'success': True, 'has_ssl': True, 'is_suspicious': True, 'error': f'Falha na verificação do certificado SSL: {str(e)}', 'suspicion_details': [str(e)]}
    except socket.timeout:
        return {'success': False, 'error': 'Timeout ao tentar conectar para análise SSL.'}
    except socket.gaierror:
        return {'success': False, 'error': f'Não foi possível resolver o hostname "{url_hostname}" para análise SSL.'}
    except ConnectionRefusedError:
        return {'success': False, 'error': f'Conexão recusada para "{url_hostname}:443" para análise SSL.'}
    except Exception as e:
        return {'success': False, 'error': f'Erro ao analisar certificado SSL: {str(e)}'}

def check_redirects(url, max_redirects=5):
    """Detecta redirecionamentos."""
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url
    
    history = []
    current_url = url
    headers = {'User-Agent': 'PhishingCheckerBot/1.0'}
    
    try:
        for _ in range(max_redirects + 1):
            res = requests.get(current_url, headers=headers, allow_redirects=False, timeout=10, verify=False) # verify=False para pegar certs auto-assinados etc.
            history.append({
                'url': current_url,
                'status_code': res.status_code,
                'headers': dict(res.headers)
            })
            
            if res.status_code in [301, 302, 303, 307, 308] and 'Location' in res.headers:
                current_url = res.headers['Location']
                if not urlparse(current_url).netloc:
                    current_url = urlparse(history[0]['url'])._replace(path=current_url).geturl()
            else:
                break
        
        num_redirects = len(history) - 1
        is_suspicious = num_redirects > 2
        
        return {
            'success': True,
            'redirect_count': num_redirects,
            'final_url': history[-1]['url'] if history else url,
            'history': [{'url': h['url'], 'status': h['status_code']} for h in history],
            'is_suspicious': is_suspicious
        }
    except requests.exceptions.TooManyRedirects:
        return {'success': True, 'redirect_count': max_redirects, 'error': 'Número máximo de redirecionamentos excedido.', 'is_suspicious': True}
    except requests.exceptions.RequestException as e:
        return {'success': False, 'error': f'Erro ao verificar redirecionamentos: {str(e)}'}


def levenshtein_distance_local(s1, s2):
    if len(s1) < len(s2):
        return levenshtein_distance_local(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def check_brand_similarity(url_hostname):
    """Verifica similaridade com domínios de marcas conhecidas."""
    if not url_hostname:
        return {'success': False, 'error': 'Hostname não fornecido'}
    
    main_domain = extract_main_domain(url_hostname)
    if not main_domain:
         return {'success': False, 'error': 'Não foi possível extrair o domínio principal do hostname.'}

    domain_name_only = main_domain.split('.')[0]

    suspicious_matches = []
    min_distance_found = float('inf')
    closest_brand = None

    for brand in KNOWN_BRAND_KEYWORDS:

        dist = levenshtein_distance_local(domain_name_only, brand)
        
        threshold = 1 if len(brand) <= 4 else 2 # Distância menor para palavras curtas
        
        if dist <= threshold and domain_name_only != brand:
            if main_domain != brand + "." + main_domain.split('.')[-1]:
                suspicious_matches.append({'brand': brand, 'checked_domain_part': domain_name_only, 'distance': dist})
                if dist < min_distance_found:
                    min_distance_found = dist
                    closest_brand = brand
    
    is_suspicious = len(suspicious_matches) > 0
    
    return {
        'success': True,
        'is_suspicious': is_suspicious,
        'closest_brand_match': closest_brand if is_suspicious else None,
        'details': suspicious_matches if is_suspicious else f"Nenhuma similaridade suspeita com marcas conhecidas encontrada para '{domain_name_only}'."
    }

def analyze_page_content(url):
    """Analisa o conteúdo da página para detectar formulários de login e palavras-chave sensíveis."""
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url
    
    headers = {'User-Agent': 'PhishingCheckerBot/1.0 (Page Content Analyzer)'}
    try:
        response = requests.get(url, headers=headers, timeout=15, verify=False, allow_redirects=True)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        forms = soup.find_all('form')
        login_form_found = False
        sensitive_fields_in_form = []

        for form in forms:
            inputs = form.find_all('input')
            has_password_field = any(inp.get('type') == 'password' for inp in inputs)
            
            current_form_sensitive_fields = []
            for inp in inputs:
                for attr in ['name', 'id', 'placeholder', 'aria-label']:
                    attr_val = inp.get(attr, '').lower()
                    if any(keyword in attr_val for keyword in LOGIN_KEYWORDS):
                        current_form_sensitive_fields.append(attr_val)
                        break
            
            if has_password_field or any(keyword in str(form).lower() for keyword in ['login', 'signin', 'acesso', 'entrar']):
                login_form_found = True
                sensitive_fields_in_form.extend(list(set(current_form_sensitive_fields))) # Adiciona campos únicos

        page_text = soup.get_text().lower()
        sensitive_keywords_on_page = [kw for kw in LOGIN_KEYWORDS if kw in page_text]

        is_suspicious = login_form_found and len(sensitive_fields_in_form) > 0
        
        # Detalhes para o resultado
        details = []
        if login_form_found:
            details.append(f"Formulário de login detectado. Campos sensíveis potenciais: {', '.join(list(set(sensitive_fields_in_form)))}")
        if sensitive_keywords_on_page:
            details.append(f"Palavras-chave sensíveis encontradas no texto da página: {', '.join(list(set(sensitive_keywords_on_page)))}")
        if not details:
            details.append("Nenhum formulário de login óbvio ou palavras-chave sensíveis proeminentes detectadas.")

        return {
            'success': True,
            'login_form_detected': login_form_found,
            'sensitive_keywords_found': list(set(sensitive_keywords_on_page)),
            'sensitive_fields_in_form': list(set(sensitive_fields_in_form)),
            'is_suspicious': is_suspicious,
            'details': details
        }
    except requests.exceptions.HTTPError as e:
        return {'success': False, 'error': f'Erro HTTP ao buscar conteúdo da página: {str(e)}'}
    except requests.exceptions.RequestException as e:
        return {'success': False, 'error': f'Erro de requisição ao buscar conteúdo da página: {str(e)}'}
    except Exception as e:
        return {'success': False, 'error': f'Erro ao analisar conteúdo da página: {str(e)}'}