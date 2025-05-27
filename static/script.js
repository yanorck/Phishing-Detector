function showAPIDetails(checkIdentifier, resultObject) {
    let modal = document.getElementById('api-details-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'api-details-modal';
        modal.className = 'modal';
        // O conteúdo do modal (título, pre) será definido abaixo ou já existe
        document.body.appendChild(modal);

        modal.onclick = function(event) { // Fechar ao clicar fora
            if (event.target == modal) {
                modal.style.display = 'none';
            }
        };
    }

    // Limpar e recriar conteúdo interno para título dinâmico
    modal.innerHTML = `
        <div class="modal-content">
            <span class="close" id="api-details-modal-close">&times;</span>
            <h2>Detalhes: ${checkIdentifier.replace('api-', '').replace('advanced-', '').replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}</h2>
            <pre id="api-details-content"></pre>
        </div>
    `;
    
    modal.querySelector('#api-details-modal-close').onclick = function() {
        modal.style.display = 'none';
    };

    const content = modal.querySelector('#api-details-content');
    try {
        content.textContent = JSON.stringify(resultObject, null, 2);
    } catch (e) {
        content.textContent = "Erro ao serializar detalhes. Dados podem estar incompletos ou malformados.";
        console.error("Erro ao serializar para showAPIDetails:", e, resultObject);
    }
    modal.style.display = 'block';
}


document.addEventListener('DOMContentLoaded', function() {
    const urlForm = document.getElementById('url-form');
    const urlInput = document.getElementById('url-input');
    const resultContainer = document.getElementById('result-container');
    const statusIcon = document.getElementById('status-icon');
    const statusText = document.getElementById('status-text');
    const detailsBody = document.getElementById('details-body');
    const warningsContainer = document.getElementById('warnings-container');
    const warningsList = document.getElementById('warnings-list');
    const loadingElement = document.getElementById('loading');

    let pendingChecks = 0;
    let currentBasicDataGlobal = null; // Para armazenar resultados básicos para status geral

    function decrementPendingChecksAndFinalize() {
        pendingChecks--;
        if (pendingChecks <= 0) {
            loadingElement.classList.add('hidden');
            statusIcon.classList.remove('checking-animation'); // Parar animação de "verificando" global
            console.log("Todas as verificações concluídas.");
            updateOverallStatus(); // Chamada final para garantir que o status reflita tudo
        }
         console.log("Checks pendentes:", pendingChecks);
    }

    urlForm.addEventListener('submit', function(e) {
        e.preventDefault();
        const url = urlInput.value.trim();
        if (!url) {
            alert('Por favor, insira uma URL válida');
            return;
        }
        checkUrl(url);
    });

    function checkUrl(url) {
        loadingElement.classList.remove('hidden');
        resultContainer.classList.add('hidden');
        detailsBody.innerHTML = '';
        warningsList.innerHTML = '';
        warningsContainer.classList.add('hidden');
        currentBasicDataGlobal = null; // Reseta dados básicos globais

        statusIcon.innerHTML = '⏳';
        statusIcon.classList.remove('blink');
        statusIcon.classList.add('checking-animation');
        statusText.innerHTML = `<h3>Verificando URL...</h3><p>Analisando múltiplos vetores de segurança...</p>`;
        resultContainer.querySelector('.result-box').className = 'result-box checking';
        resultContainer.classList.remove('hidden');

        const allChecks = createInitialStatusRows(); // Retorna o número total de checks iniciados
        pendingChecks = allChecks.total;
        console.log("Total de verificações iniciadas:", pendingChecks);


        const originalUrl = url; // URL fornecida pelo usuário
        let preliminaryHostname;
        try {
            const parsedUrl = new URL(originalUrl.startsWith('http') ? originalUrl : `http://${originalUrl}`);
            preliminaryHostname = parsedUrl.hostname;
        } catch (e) {
            console.error("URL inválida para extração de hostname no frontend:", originalUrl, e);
            statusText.innerHTML = `<h3>Erro</h3><p>URL fornecida (${originalUrl}) é inválida.</p>`;
            resultContainer.querySelector('.result-box').className = 'result-box error';
            loadingElement.classList.add('hidden');
            pendingChecks = 0; // Zera para não travar
            return;
        }

        // 1. Verificações básicas
        checkBasicVerifications(originalUrl)
            .then(data => {
                currentBasicDataGlobal = data; // Armazena para uso no status geral
                updateBasicChecks(data);
                const normalizedHostname = data.normalized_hostname || preliminaryHostname;
                triggerAdvancedAndApiChecks(originalUrl, normalizedHostname, allChecks.advancedIds, allChecks.apiIds);
            })
            .catch(error => {
                console.error('Erro crítico nas verificações básicas:', error);
                updateBasicChecksError();
                currentBasicDataGlobal = { success: false, error: 'Falha nas verificações básicas', is_suspicious: true, risk_level: 'alto' };
                // Mesmo com erro, tenta as outras, usando o hostname preliminar
                triggerAdvancedAndApiChecks(originalUrl, preliminaryHostname, allChecks.advancedIds, allChecks.apiIds);
            })
            .finally(() => {
                // As verificações básicas (grupo) contam como uma unidade para o decremento inicial.
                // O decremento individual será feito pelas sub-funções de advanced/api.
                // DecrementPendingChecks não é chamado aqui diretamente, pois as sub-chamadas farão.
                // Se as básicas fossem o único grupo, aqui seria o local.
            });
    }

    function triggerAdvancedAndApiChecks(originalUrl, hostnameToUse, advancedCheckIds, apiCheckIds) {
        // 2. Verificações Avançadas (granulares)
        advancedCheckIds.forEach(id => {
            switch(id) {
                case 'domain_age': fetchDomainAge(originalUrl); break; // WHOIS geralmente usa o domínio raiz, backend trata
                case 'dynamic_dns': fetchDynamicDns(hostnameToUse); break;
                case 'ssl_certificate': fetchSslCertificate(hostnameToUse); break;
                case 'redirects': fetchRedirects(originalUrl); break;
                case 'brand_similarity': fetchBrandSimilarity(hostnameToUse); break;
                case 'page_content': fetchPageContent(originalUrl); break;
            }
        });

        // 3. Verificações de API
        apiCheckIds.forEach(id => {
             switch(id) {
                case 'google': checkGoogleSafeBrowse(originalUrl); break;
                case 'virustotal': checkVirusTotal(originalUrl); break;
                case 'urlscan': checkURLScan(originalUrl); break;
                case 'phishing_initiative': checkPhishingInitiative(originalUrl); break;
            }
        });
    }

    async function checkBasicVerifications(url) {
        const response = await fetch('/check_basic', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || `Erro HTTP ${response.status} nas verificações básicas`);
        }
        return response.json();
    }

    // --- Funções para chamar endpoints avançados granulares ---
    function fetchDomainAge(url) {
        const endpoint = '/advanced/domain_age';
        const checkId = 'domain_age';
        makeGenericCheckRequest(endpoint, { url: url }, 'advanced', checkId, (res) =>
            res.success ?
            `<span class="check-icon">${res.is_suspicious ? '⚠️' : '✅'}</span> Idade: ${res.domain_age_days !== undefined ? res.domain_age_days + ' dias' : 'N/A'}. ${res.is_suspicious ? 'Recente!' : 'OK.'} (Criado: ${res.creation_date ? new Date(res.creation_date).toLocaleDateString() : 'N/A'})` :
            `<span class="check-icon">❌</span> Erro: ${res.error}`
        );
    }

    function fetchDynamicDns(hostname) {
        const endpoint = '/advanced/dynamic_dns';
        const checkId = 'dynamic_dns';
        makeGenericCheckRequest(endpoint, { url: hostname }, 'advanced', checkId, (res) =>
            res.success ?
            `<span class="check-icon">${res.is_suspicious ? '⚠️' : '✅'}</span> ${res.uses_ddns ? 'Detectado DDNS' : 'Não usa DDNS'}` :
            `<span class="check-icon">❌</span> Erro: ${res.error}`
        );
    }

    function fetchSslCertificate(hostname) {
        const endpoint = '/advanced/ssl_certificate';
        const checkId = 'ssl_certificate';
        makeGenericCheckRequest(endpoint, { url: hostname }, 'advanced', checkId, (res) => {
            if (!res.success) return `<span class="check-icon">❌</span> Erro: ${res.error || 'Desconhecido'}`;
            if (res.error && (res.error.includes("Não foi possível resolver o hostname") || res.error.includes("Connection refused") || res.error.includes("Timeout ao tentar conectar"))) {
                 return `<span class="check-icon">❓</span> SSL: ${res.error}`;
            }
            if (!res.has_ssl && !res.error) return `<span class="check-icon">⚠️</span> Sem SSL.`;
            if (!res.has_ssl && res.error) return `<span class="check-icon">❌</span> SSL Erro: ${res.error}`;

            let details = `Emitido por: ${res.organization_issuer || res.issuer}. Válido p/ host: ${res.is_valid_for_host ? 'Sim' : 'Não!'}.`;
            if (res.suspicion_details && res.suspicion_details.length > 0) {
                details += ` Alertas SSL: ${res.suspicion_details.join('; ')}`;
            }
            return `<span class="check-icon">${res.is_suspicious ? '⚠️' : '✅'}</span> ${details.substring(0, 150)}${details.length > 150 ? '...' : ''}`;
        });
    }

    function fetchRedirects(url) {
        const endpoint = '/advanced/redirects';
        const checkId = 'redirects';
        makeGenericCheckRequest(endpoint, { url: url }, 'advanced', checkId, (res) =>
            res.success ?
            `<span class="check-icon">${res.is_suspicious ? '⚠️' : '✅'}</span> ${res.redirect_count} redirecionamentos. URL Final: ${res.final_url ? res.final_url.substring(0,50) : 'N/A'}...` :
            `<span class="check-icon">❌</span> Erro: ${res.error}`
        );
    }

    function fetchBrandSimilarity(hostname) {
        const endpoint = '/advanced/brand_similarity';
        const checkId = 'brand_similarity';
        makeGenericCheckRequest(endpoint, { url: hostname }, 'advanced', checkId, (res) =>
            res.success ?
            `<span class="check-icon">${res.is_suspicious ? '⚠️' : '✅'}</span> ${res.is_suspicious ? 'Similaridade com: ' + res.closest_brand_match : 'Nenhuma similaridade óbvia.'}` :
            `<span class="check-icon">❌</span> Erro: ${res.error}`
        );
    }

    function fetchPageContent(url) {
        const endpoint = '/advanced/page_content';
        const checkId = 'page_content';
        makeGenericCheckRequest(endpoint, { url: url }, 'advanced', checkId, (res) =>
            res.success ?
            `<span class="check-icon">${res.is_suspicious ? '⚠️' : '✅'}</span> ${res.login_form_detected ? 'Form. login detectado.' : 'Form. login não óbvio.'} ${res.details ? res.details.join(' ').substring(0,100) : ''}...` :
            `<span class="check-icon">❌</span> Erro: ${res.error}`
        );
    }

    // --- Funções para chamar APIs Externas (já existentes, adaptadas para makeGenericCheckRequest) ---
    function checkGoogleSafeBrowse(url) {
        makeGenericCheckRequest('/check/google', { url: url }, 'api', 'google', (result) => 
            result.success ?
            `<span class="check-icon">${!result.is_safe ? '❌' : '✅'}</span> ${!result.is_safe ? `Ameaças: ${result.threat_types_found.join(', ')}` : 'URL segura'}` :
            `<span class="check-icon">⚠️</span> Erro: ${result.error}`
        , 10000); // 10s timeout
    }

    function checkVirusTotal(url) {
        makeGenericCheckRequest('/check/virustotal', { url: url }, 'api', 'virustotal', (result) =>
            result.success ?
            `<span class="check-icon">${result.malicious > 0 ? '❌' : result.suspicious > 0 ? '⚠️' : '✅'}</span> ${result.malicious > 0 ? `${result.malicious} maliciosas` : result.suspicious > 0 ? `${result.suspicious} suspeitas` : 'Nenhuma ameaça'} (${result.total_scans || 0} scans). ${result.status_note || ''}`:
            `<span class="check-icon">⚠️</span> Erro: ${result.error}`
        , 20000); // 20s timeout
    }

    function checkURLScan(url) {
        makeGenericCheckRequest('/check/urlscan', { url: url }, 'api', 'urlscan', (result) => {
            if (!result.success) return `<span class="check-icon">⚠️</span> Erro: ${result.error}`;
            let scanLink = result.details && result.details.task && result.details.task.reportURL ?
                           `<br><a href="${result.details.task.reportURL}" target="_blank" class="scan-link">Ver relatório URLScan.io</a>` : '';
            if (result.error && result.error.includes("não finalizado")) { // Erro de scan não pronto
                scanLink = `<br><span class="scan-link">Scan não completou a tempo.</span>`;
            }
            return `<span class="check-icon">${result.malicious_verdict ? '❌' : result.suspicious_by_score ? '⚠️' : '✅'}</span> ${result.malicious_verdict ? 'Malicioso (URLScan)' : result.suspicious_by_score ? 'Suspeito (URLScan)' : 'OK (URLScan)'}. Score: ${result.score || 0}${scanLink}`;
        }, 130000); // 130s timeout (URLScan pode demorar ~120s no backend + folga)
    }
    
    function checkPhishingInitiative(url) {
        makeGenericCheckRequest('/check/phishing_initiative', { url: url }, 'api', 'phishing_initiative', (result) =>
            result.success ?
            `<span class="check-icon">${result.is_phishing ? '❌' : result.is_safe ? '✅' : '❓'}</span> ${result.is_phishing ? 'Phishing confirmado' : result.is_safe ? 'Seguro' : result.tag_label || 'Desconhecido'}`:
            `<span class="check-icon">⚠️</span> Erro: ${result.error}`
        , 15000); // 15s timeout
    }
    

    // Função auxiliar genérica para fazer requisições e atualizar UI
    function makeGenericCheckRequest(endpoint, bodyPayload, type, checkId, formatResultCallback, timeoutMs = 30000) {
        const fullCheckId = `${type}-${checkId}`; // ex: 'api-google' ou 'advanced-domain_age'

        const timeoutPromise = new Promise((_, reject) =>
            setTimeout(() => reject(new Error(`Timeout (${timeoutMs/1000}s) para ${checkId}`)), timeoutMs)
        );

        Promise.race([
            fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(bodyPayload)
            }).then(response => {
                if (!response.ok) {
                    return response.json()
                        .then(errData => { throw new Error(errData.error || `Erro HTTP ${response.status} em ${checkId}`); })
                        .catch(() => { throw new Error(`Erro HTTP ${response.status} em ${checkId} (sem JSON)`); });
                }
                return response.json();
            }),
            timeoutPromise
        ])
        .then(result => {
            updateCheckUIRow(fullCheckId, result, formatResultCallback);
        })
        .catch(error => {
            console.error(`Erro em ${fullCheckId}:`, error);
            updateCheckUIError(fullCheckId, error);
        })
        .finally(() => {
            decrementPendingChecksAndFinalize();
            updateOverallStatus(); // Atualiza status geral após cada check
        });
    }

    function updateCheckUIRow(fullCheckId, resultData, formatResultCallback) {
        const row = document.getElementById(fullCheckId);
        if (row) {
            const resultCell = row.querySelector('.check-result');
            resultCell.innerHTML = formatResultCallback(resultData);

            if (resultData.success !== false || (resultData.success === false && resultData.details)) { // Adiciona detalhes mesmo para alguns erros se houver 'details'
                const detailsButton = document.createElement('button');
                detailsButton.className = 'details-btn';
                detailsButton.textContent = 'Detalhes';
                detailsButton.onclick = () => showAPIDetails(fullCheckId, resultData.details || resultData); // Passa sub-objeto 'details' se existir
                
                if (!resultCell.querySelector('.details-btn')) {
                    resultCell.appendChild(detailsButton);
                }
            }
        }
    }

    function updateCheckUIError(fullCheckId, error) {
        const row = document.getElementById(fullCheckId);
        if (row) {
            const resultCell = row.querySelector('.check-result');
            resultCell.innerHTML = `<span class="check-icon">❌</span> Falha: ${error.message || 'Erro desconhecido'}`;
        }
    }
    
    function updateBasicChecks(data) {
        currentBasicDataGlobal = data; // Atualiza o global
        if (data && data.success === false && data.error) {
            console.error("Erro retornado pelo backend para verificações básicas:", data.error);
            updateBasicChecksError(data.error);
            return;
        }
        if (data && data.checks) {
            const basicCheckMapping = {
                'numeros_substituindo_letras': 'basic-numeros_substituindo_letras',
                'excesso_subdominio': 'basic-excesso_subdominio',
                'caracteres_especiais_suspeitos': 'basic-caracteres_especiais_suspeitos',
                // Adicione outros se basic_checks.py retornar mais, e crie as linhas em createInitialStatusRows
            };
            for (const checkKey in basicCheckMapping) {
                const rowId = basicCheckMapping[checkKey];
                const rowElement = document.getElementById(rowId);
                const result = data.checks[checkKey];
                if (rowElement) {
                    const resultCell = rowElement.querySelector('.check-result');
                    if (resultCell) {
                         resultCell.innerHTML = `
                            <span class="check-icon">${result === true ? '⚠️' : result === false ? '✅' : '❓'}</span>
                            ${result === true ? 'Detectado' : result === false ? 'Não detectado' : 'N/A'}
                        `;
                    }
                }
            }
        }
        warningsList.innerHTML = '';
        if (data && data.details && data.details.length > 0) {
            warningsContainer.classList.remove('hidden');
            data.details.forEach(detail => {
                const li = document.createElement('li');
                li.textContent = detail;
                warningsList.appendChild(li);
            });
        } else {
            warningsContainer.classList.add('hidden');
        }
    }

    function updateBasicChecksError(errorMessage = "Falha na verificação") {
        const basicCheckIds = ['basic-numeros_substituindo_letras', 'basic-excesso_subdominio', 'basic-caracteres_especiais_suspeitos'];
        basicCheckIds.forEach(rowId => {
            const row = document.getElementById(rowId);
            if (row) {
                const resultCell = row.querySelector('.check-result');
                resultCell.innerHTML = `<span class="check-icon">❌</span> ${errorMessage}`;
            }
        });
    }

    
    function createInitialStatusRows() {
        let count = 0;
        const basicChecks = [
            { id: 'numeros_substituindo_letras', name: 'Substituição Letra/Número' },
            { id: 'excesso_subdominio', name: 'Excesso de Subdomínios' },
            { id: 'caracteres_especiais_suspeitos', name: 'Caracteres Suspeitos' }
        ];
        basicChecks.forEach(check => {
            const row = document.createElement('tr');
            row.id = `basic-${check.id}`;
            row.innerHTML = `
                <td>${check.name}</td>
                <td class="check-result"><span class="check-icon">⏳</span> Aguardando...</td>`;
            detailsBody.appendChild(row);
            // Não incrementa pendingChecks aqui, pois a chamada básica é uma só.
        });

        const advancedChecks = [
            { id: 'domain_age', name: 'Idade do Domínio' }, { id: 'dynamic_dns', name: 'DNS Dinâmico' },
            { id: 'ssl_certificate', name: 'Certificado SSL' }, { id: 'redirects', name: 'Redirecionamentos' },
            { id: 'brand_similarity', name: 'Similaridade c/ Marcas' }, { id: 'page_content', name: 'Conteúdo da Página' }
        ];
        advancedChecks.forEach(check => {
            const row = document.createElement('tr');
            row.id = `advanced-${check.id}`;
            row.innerHTML = `
                <td>${check.name}</td>
                <td class="check-result"><span class="check-icon">⏳</span> Verificando...</td>`;
            detailsBody.appendChild(row);
            count++;
        });

        const apis = [
            { id: 'google', name: 'Google Safe Browse' }, { id: 'virustotal', name: 'VirusTotal' },
            { id: 'urlscan', name: 'URLScan.io' }, { id: 'phishing_initiative', name: 'Phishing Initiative' }
        ];
        apis.forEach(api => {
            const row = document.createElement('tr');
            row.id = `api-${api.id}`;
            row.innerHTML = `
                <td>${api.name}</td>
                <td class="check-result"><span class="check-icon">⏳</span> Verificando...</td>`;
            detailsBody.appendChild(row);
            count++;
        });
        return {total: count + 1, advancedIds: advancedChecks.map(c=>c.id), apiIds: apis.map(a=>a.id) }; // +1 para o bloco de basic checks
    }

    function getCheckOutcome(rowId) {
        const row = document.getElementById(rowId);
        if (!row) return { success: false, is_safe: false, malicious: 0, suspicious: 0, error: 'Row not found' };
        const iconEl = row.querySelector('.check-icon');
        if (!iconEl) return { success: false, is_safe: false, malicious: 0, suspicious: 0, error: 'Icon not found' };
    
        const icon = iconEl.textContent;
        const text = row.querySelector('.check-result').textContent.toLowerCase();
        
        let is_safe = icon === '✅';
        // Para Phishing Initiative especificamente, só é malicioso se o texto confirmar.
        let malicious = 0;
        if (rowId === 'api-phishing_initiative') {
            malicious = (icon === '❌' && (text.includes('phishing confirmado') || text.includes('phishing detectado'))) ? 1 : 0;
        } else { // Lógica para outras APIs e checks
            malicious = (icon === '❌' || text.includes('malicioso') || text.includes('maliciosa')) ? 1 : 0;
        }
    
        // Um '❓' no Phishing Initiative (ou outros checks que podem ser inconclusivos) não deve contar como suspeito por si só.
        // Apenas '⚠️' ou texto explícito de suspeita.
        let suspicious = 0;
        if (icon === '⚠️' || text.includes('suspeit')) { // ex: "X suspeitas", "Recente!" (idade), "Sem SSL", "Detectado DDNS"
            suspicious = 1;
        }
        // Para verificações básicas, se o ícone for '⚠️' (que usamos para "Detectado"), consideramos suspeito.
        if (rowId.startsWith('basic-') && icon === '⚠️') {
            suspicious = 1;
        }
        // Se for SSL não resolvido, não é suspeito, é inconclusivo
        if (rowId === 'advanced-ssl_certificate' && icon === '❓' && text.includes('domínio não resolvido')) {
            suspicious = 0; // Não é suspeito, apenas não pôde ser verificado.
        }
    
    
        if (icon === '❌' && (text.includes('erro:') || text.includes('falha:'))) {
            // Erro na execução do check. Não é 'malicious', mas pode ser 'suspicious' se quisermos penalizar falhas.
            // Por ora, vamos tratar como falha e não 'suspicious' diretamente aqui, a menos que a lógica de score penalize.
            return { success: false, is_safe: false, malicious: 0, suspicious: 0, error: 'Falha na verificação' };
        }
        
        if (malicious) { is_safe = false; suspicious = 0; }
        else if (suspicious) { is_safe = false; }
        else if (is_safe) { malicious = 0; suspicious = 0; }
        // Se não for seguro, nem malicioso, nem suspeito (ex: Phishing Initiative '❓'),
        // is_safe será false, malicious 0, suspicious 0. Isso é inconclusivo.
    
        return { success: true, is_safe, malicious, suspicious };
    }

    function updateOverallStatus() {
        if (pendingChecks > 0 && loadingElement.classList.contains('hidden')) {
            // Se o loader principal já sumiu mas ainda há checks, pode ser um estado intermediário
            // Vamos aguardar o pendingChecks chegar a zero para a avaliação final.
            // No entanto, podemos atualizar o status com o que temos.
        }

        let overallRiskLevel = 'baixo';
        let isOverallSuspicious = false; // Indica se *qualquer* coisa suspeita foi encontrada
        let isConfirmedMalicious = false; // Indica se *qualquer* check confirmou malícia/phishing
        let riskScore = 0;
        const reasons = [];

        // 1. Verificações Básicas (usando currentBasicDataGlobal)
        if (currentBasicDataGlobal) {
            if (currentBasicDataGlobal.is_suspicious) {
                isOverallSuspicious = true;
                // Adiciona o score diretamente se ele existir, senão uma pontuação padrão para suspeita básica
                riskScore += currentBasicDataGlobal.risk_score || 5; // Um valor padrão se risk_score não estiver lá
                reasons.push(`Básico: ${currentBasicDataGlobal.risk_level || 'suspeito'} (${currentBasicDataGlobal.risk_score || 5} pts)`);
            }
            if (currentBasicDataGlobal.checks && currentBasicDataGlobal.checks.phishing_list_match) {
                isConfirmedMalicious = true; // Se estiver na lista de phishing simulada
                reasons.push("Básico: Encontrado em lista de phishing conhecida!");
                riskScore += 100; // Pontuação alta para phishing conhecido
            }
        } else {
            riskScore += 10;
            isOverallSuspicious = true;
            reasons.push("Básico: Falha crítica (10 pts)");
        }
        
        const weights = {
            advanced: { malicious: 30, suspicious: 10, error: 3 }, // Ajuste os pesos
            api:      { malicious: 40, suspicious: 15, error: 5 }  // Phishing Initiative malicioso terá peso de API
        };

        const checkCategories = {
            advanced: ['domain_age', 'dynamic_dns', 'ssl_certificate', 'redirects', 'brand_similarity', 'page_content'],
            api: ['google', 'virustotal', 'urlscan', 'phishing_initiative']
        };

        for (const type in checkCategories) {
            checkCategories[type].forEach(id => {
                const res = getCheckOutcome(`${type}-${id}`);
                if (!res.success && res.error !== 'Row not found') {
                    riskScore += weights[type].error;
                    isOverallSuspicious = true; // Considera erro como um ponto de atenção
                    reasons.push(`${type}(${id}): Falha (${weights[type].error} pts)`);
                } else if (res.success) {
                    if (res.malicious) {
                        riskScore += weights[type].malicious;
                        isOverallSuspicious = true;
                        isConfirmedMalicious = true; // Se qualquer check avançado/API confirmar malícia
                        reasons.push(`${type}(${id}): Malicioso (${weights[type].malicious} pts)`);
                    } else if (res.suspicious) {
                        // Para Phishing Initiative, 'suspicious' não deve ser setado se for inconclusivo.
                        // getCheckOutcome já deve estar tratando isso.
                        // Só adiciona score se realmente for marcado como suspeito (e não apenas inconclusivo).
                        if (!(type === 'api' && id === 'phishing_initiative' && !res.malicious && !res.is_safe)) {
                            riskScore += weights[type].suspicious;
                            isOverallSuspicious = true;
                            reasons.push(`${type}(${id}): Suspeito (${weights[type].suspicious} pts)`);
                        }
                    }
                }
            });
        }
        
        // Definir nível de risco com base no score e flags
        if (isConfirmedMalicious || riskScore >= 100) { // Phishing conhecido das básicas ou score muito alto de APIs/avançadas
            overallRiskLevel = 'PHISHING CONFIRMADO';
        } else if (riskScore >= 60) { // Limiares ajustados
            overallRiskLevel = 'MUITO ALTO';
        } else if (riskScore >= 35) {
            overallRiskLevel = 'ALTO';
        } else if (riskScore >= 15) {
            overallRiskLevel = 'MÉDIO';
        } else if (isOverallSuspicious && riskScore > 0) { // Se qualquer coisa foi suspeita mas o score é baixo
            overallRiskLevel = 'BAIXO (COM ALERTAS)';
        } else {
            overallRiskLevel = 'BAIXO';
        }

        // Atualizar UI
        const resultBox = resultContainer.querySelector('.result-box');
        statusIcon.classList.remove('checking-animation', 'blink');

        let statusTitle = "";
        let statusDescription = "";
        let riskClass = "safe"; // Classe CSS para a caixa de resultado geral

        switch(overallRiskLevel) {
            case 'PHISHING CONFIRMADO':
                statusIcon.innerHTML = '🚨';
                statusTitle = "ALERTA DE PHISHING!";
                statusDescription = `Esta URL foi identificada como PHISHING. NÃO ACESSE!`;
                riskClass = "error risk-phishing_confirmado"; // Mais enfático
                // Esconder os alertas de baixo quando for phishing confirmado
                warningsContainer.classList.add('hidden');
                warningsList.innerHTML = '';
                break;
            case 'MUITO ALTO':
                statusIcon.innerHTML = '🚨';
                statusTitle = "URL EXTREMAMENTE PERIGOSA!";
                riskClass = "error risk-muito_alto";
                break;
            case 'ALTO':
                statusIcon.innerHTML = '高'; // Caractere japonês para "alto/caro", apenas um exemplo de ícone diferente. Poderia ser ❗
                statusTitle = "URL ALTAMENTE SUSPEITA!";
                riskClass = "error risk-alto"; // 'error' para vermelho, 'suspicious' para laranja/amarelo
                break;
            case 'MÉDIO':
                statusIcon.innerHTML = '⚠️';
                statusTitle = "URL Suspeita";
                riskClass = "suspicious risk-medio";
                break;
            case 'BAIXO (COM ALERTAS)':
                statusIcon.innerHTML = '✅'; // Ou talvez 'ⓘ' para "informação"
                statusTitle = "URL Parece Segura, Mas Com Alertas";
                riskClass = "safe risk-baixo_alertas"; // Um verde um pouco diferente, ou manter 'safe'
                break;
            case 'BAIXO':
            default:
                statusIcon.innerHTML = '✅';
                statusTitle = "URL Parece Segura";
                riskClass = "safe risk-baixo";
                break;
        }
        
        if (!statusDescription) { // Descrição padrão se não definida pelo nível de risco
            if (reasons.length > 0) {
                statusDescription = `Nível de risco: <strong>${overallRiskLevel.toUpperCase()}</strong>. Pontos de atenção: ${reasons.slice(0,2).join('; ')}.`;
            } else if (overallRiskLevel === 'BAIXO') {
                statusDescription = `Nível de risco: <strong>BAIXO</strong>. Nenhuma ameaça crítica detectada.`;
            } else {
                 statusDescription = `Nível de risco: <strong>${overallRiskLevel.toUpperCase()}</strong>. Analise os detalhes abaixo.`;
            }
        }

        statusText.innerHTML = `<h3>${statusTitle}</h3><p>${statusDescription}</p>`;
        resultBox.className = `result-box ${riskClass}`;
    }

}); // Fim do DOMContentLoaded