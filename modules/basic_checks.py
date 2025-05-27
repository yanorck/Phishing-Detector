import re
from urllib.parse import urlparse, unquote


def get_domain_parts(url):
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url
    
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    if hostname:
        return hostname.lower()
    return None

def contains_number_letter_substitution(url_hostname):
    if not url_hostname:
        return False

    substitutions = {
        '0': ['o'],
        '1': ['l', 'i'],
        '3': ['e'],
        '4': ['a'],
        '5': ['s'],
        '6': ['g', 'b'],
        '8': ['b'],
        '9': ['g', 'q']
    }
    

    known_brand_keywords = [
    # Tecnologia e Internet
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


    domain_parts = url_hostname.split('.')
    main_domain_part = ""
    if len(domain_parts) > 1:
        potential_main = domain_parts[-2] if len(domain_parts) > 2 and domain_parts[-1] in ['uk', 'au', 'jp', 'br'] else domain_parts[-2]
        if len(domain_parts) > 2 and domain_parts[-2] in ['com', 'net', 'org', 'gov', 'edu']:
             potential_main = domain_parts[-3] if len(domain_parts) > 2 else domain_parts[0]
        main_domain_part = potential_main


    for brand_keyword in known_brand_keywords:
        temp_brand = brand_keyword
        test_hostname = url_hostname

        for num, chars_replaced in substitutions.items():
            for char_replaced in chars_replaced:
                if char_replaced in brand_keyword and num in test_hostname:
                    phishy_brand_variant = brand_keyword.replace(char_replaced, num)
                    if phishy_brand_variant in test_hostname and brand_keyword not in test_hostname:
                        if levenshtein_distance(phishy_brand_variant, main_domain_part) < 3 :
                            return True
    

    for i, char_host in enumerate(url_hostname):
        if char_host.isdigit():
            for digit, possible_letters in substitutions.items():
                if char_host == digit:
                    if i > 0 and url_hostname[i-1].isalpha() and url_hostname[i-1] in "abcdefghijklmnopqrstuvwxyz":
                        return True
                    if i < len(url_hostname) -1 and url_hostname[i+1].isalpha() and url_hostname[i+1] in "abcdefghijklmnopqrstuvwxyz":
                        return True
    return False

def levenshtein_distance(s1, s2):
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
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


def has_excessive_subdomains(url_hostname, max_subdomains=3):
    if not url_hostname:
        return False
    
    parts = url_hostname.split('.')
    subdomain_count = url_hostname.count('.')
    
    tld_like_parts = 0
    if len(parts) > 1 and parts[-1] in ['com', 'org', 'net', 'gov', 'edu', 'io', 'app', 'dev']:
        tld_like_parts = 1
        if len(parts) > 2 and parts[-2] in ['co', 'com', 'net', 'org', 'gov', 'ac', 'biz', 'info']:
             tld_like_parts = 2
             if len(parts) > 3 and parts[-3] in ['com', 'net']:
                 tld_like_parts = 3


    num_actual_subdomains = len(parts) - tld_like_parts -1
    
    return num_actual_subdomains > max_subdomains

def has_suspicious_special_chars(url, url_hostname):
    if not url_hostname:
        return True

    suspicious_in_hostname = ['@', '_']
    for char in suspicious_in_hostname:
        if char in url_hostname:
            return True
            
    if "--" in url_hostname or url_hostname.startswith('-') or url_hostname.endswith('-'):
        return True
    for part in url_hostname.split('.'):
        if part.startswith('-') or part.endswith('-'):
            return True

    if url.count('%') > 10:
        try:
            decoded_url = unquote(url)
            if any(susp_char in decoded_url for susp_char in ['<', '>', '"', "'", '{', '}']):
                return True
        except Exception:
            pass


    path_and_query = url.replace(f"https://{url_hostname}", "").replace(f"http://{url_hostname}", "")
    uncommon_in_path_query = ['*', '^']
    for char in uncommon_in_path_query:
        if char in path_and_query:
            return True
            
    return False

KNOWN_PHISHING_DOMAINS_CACHE = {
    "www.phishingsite1.com", 
    "malicious-login.net",
    "secure-update-totally-real.org"
}

def check_against_known_phishing_lists(url_hostname):
    """
    Verifica se o hostname (ou partes dele) está em listas conhecidas de phishing.
    Esta é uma SIMULAÇÃO. Em um sistema real, você usaria APIs (Google Safe Browse)
    ou manteria um banco de dados atualizado.
    """
    if not url_hostname:
        return False
    
    if url_hostname in KNOWN_PHISHING_DOMAINS_CACHE:
        return True
    
    parts = url_hostname.split('.')
    for i in range(len(parts) -1):
        sub_domain_to_check = ".".join(parts[i:])
        if sub_domain_to_check in KNOWN_PHISHING_DOMAINS_CACHE:
            return True
            
    return False

# --- Função Principal Refinada ---

def check_url(url):
    """
    Realiza verificações em uma URL para identificar possíveis sinais de phishing.
    """
    original_url = url
    url_hostname = get_domain_parts(url)

    results = {
        'url': original_url,
        'normalized_hostname': url_hostname,
        'is_suspicious': False,
        'risk_score': 0, # Usaremos um score para calcular o risco
        'risk_level': 'baixo', # baixo, médio, alto, muito_alto/phishing_conhecido
        'checks': {
            'phishing_list_match': False,
            'numeros_substituindo_letras': False,
            'excesso_subdominio': False,
            'caracteres_especiais_suspeitos': False,
            'idade_dominio_suspeita': None, # bool ou string
            'ssl_invalido_suspeito': None, # bool
            'similaridade_levenshtein_alta': None, # bool
        },
        'details': []
    }

    if not url_hostname:
        results['is_suspicious'] = True
        results['risk_level'] = 'alto'
        results['details'].append("URL malformada ou sem hostname identificável.")
        return results

    # 1. Verificação em listas de phishing conhecidas
    if check_against_known_phishing_lists(url_hostname):
        results['checks']['phishing_list_match'] = True
        results['details'].append(f"ALERTA: Hostname '{url_hostname}' encontrado em lista de phishing conhecida (simulação).")
        results['risk_score'] += 50
        results['is_suspicious'] = True
    
    # 2. Verificar números substituindo letras
    if contains_number_letter_substitution(url_hostname):
        results['checks']['numeros_substituindo_letras'] = True
        results['details'].append(f"Hostname '{url_hostname}' parece usar números para substituir letras de forma suspeita.")
        results['risk_score'] += 15
    
    # 3. Verificar excesso de subdomínios (ex: mais de 2 subdomínios além do principal.com)
    if has_excessive_subdomains(url_hostname, max_subdomains=2):
        results['checks']['excesso_subdominio'] = True
        results['details'].append(f"Hostname '{url_hostname}' parece ter um número excessivo de subdomínios.")
        results['risk_score'] += 10
    
    # 4. Verificar caracteres especiais suspeitos
    if has_suspicious_special_chars(original_url, url_hostname):
        results['checks']['caracteres_especiais_suspeitos'] = True
        results['details'].append(f"URL ou hostname '{url_hostname}' contém caracteres especiais de forma suspeita.")
        results['risk_score'] += 10

    # Determinar nível de risco com base no score
    if results['risk_score'] > 0:
        results['is_suspicious'] = True
        if results['checks']['phishing_list_match'] or results['risk_score'] >= 50:
            results['risk_level'] = 'PHISHING CONHECIDO' if results['checks']['phishing_list_match'] else 'MUITO ALTO'
        elif results['risk_score'] >= 30:
            results['risk_level'] = 'alto'
        elif results['risk_score'] >= 15:
            results['risk_level'] = 'médio'
        else:
            results['risk_level'] = 'baixo' # Mesmo com score > 0, pode ser só um aviso leve
    
    if not results['is_suspicious']:
         results['details'].append(f"Nenhum sinal óbvio de phishing detectado para '{url_hostname}'.")


    return results

# --- Exemplos de Uso ---
if __name__ == '__main__':
    urls_to_test = [
        "www.g00gle-imitation.com/login",
        "secure-login-banco-brasil.com.br.xyz.com/acesso",
        "amazon.com.co.uk.secure-payment-info.net/update",
        "http://example.com",
        "itaupersonnalite.com",
        "banco123seguro.com",
        "meusite.com/path@caracter",
        "user@phishingsite1.com/login.html",
        "www.phishingsite1.com/seguranca",
        "https---malicious.com",
        "xn--ggle-0nda.com",
        "https://www.mylegitbusiness.com/index.html",
        "http://123.45.67.89/admin"
    ]
    
    print("--- Iniciando Testes de URLs ---")
    for test_url in urls_to_test:
        result = check_url(test_url)
        print(f"\nURL: {result['url']}")
        print(f"  Hostname Normalizado: {result['normalized_hostname']}")
        print(f"  É Suspeita: {result['is_suspicious']}")
        print(f"  Nível de Risco: {result['risk_level']} (Score: {result['risk_score']})")
        print(f"  Detalhes:")
        for detail in result['details']:
            print(f"    - {detail}")
        # print(f"  Checks: {result['checks']}")