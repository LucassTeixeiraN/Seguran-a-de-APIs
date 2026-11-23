/**
 * Segurança de APIs — Apresentação Didática & Laboratório Interativo
 * Script principal:
 * - Exemplo #1: Comparador Web Tradicional vs API
 * - Explorador OWASP API Top 10 (Código Vulnerável vs Seguro)
 * - Linha do Tempo Histórica Interativa
 * - Exemplo #2: Inspetor JWT e Pipeline de Defesa
 * - Casos Notáveis com Filtro
 * - Exemplo #3: Laboratório Prático de Ataque e Defesa ao Vivo
 * - Checklist de Maturidade & Cópia de Referências ABNT
 * - Modo Apresentação (Slides por Teclado ← →)
 */

document.addEventListener('DOMContentLoaded', () => {
  initReadingProgress();
  initAnatomyToggle();
  initOwaspExplorer();
  initTimeline();
  initJwtInspector();
  initPipelineDiagram();
  initCases();
  initInteractiveLab();
  initChecklist();
  initReferencesCopy();
  initSlideMode();
});

/* ==========================================================================
   1. BARRA DE PROGRESSO DE LEITURA E NAVEGAÇÃO ATIVA
   ========================================================================== */
function initReadingProgress() {
  const progressBar = document.getElementById('readingProgress');
  window.addEventListener('scroll', () => {
    const scrollTop = window.scrollY;
    const docHeight = document.documentElement.scrollHeight - window.innerHeight;
    const pct = docHeight > 0 ? (scrollTop / docHeight) * 100 : 0;
    progressBar.style.width = `${pct}%`;
  });
}

/* ==========================================================================
   2. EXEMPLO PRÁTICO #1: WEB TRADICIONAL VS ARQUITETURA DE API
   ========================================================================== */
function initAnatomyToggle() {
  const buttons = document.querySelectorAll('[data-anatomy]');
  const viewTrad = document.getElementById('view-traditional');
  const viewApi = document.getElementById('view-api');

  buttons.forEach(btn => {
    btn.addEventListener('click', () => {
      buttons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const mode = btn.getAttribute('data-anatomy');
      if (mode === 'traditional') {
        viewTrad.classList.remove('hidden');
        viewApi.classList.add('hidden');
      } else {
        viewTrad.classList.add('hidden');
        viewApi.classList.remove('hidden');
      }
    });
  });
}

/* ==========================================================================
   3. EXPLORADOR OWASP API SECURITY TOP 10 (2023)
   ========================================================================== */
const OWASP_DATA = {
  bola: {
    title: 'API1:2023 — Broken Object Level Authorization (BOLA / IDOR)',
    desc: 'A falha mais comum e crítica em APIs. Ocorre quando o endpoint recebe o ID de um objeto na URL ou payload e retorna os dados sem verificar se o usuário autenticado realmente é o dono daquele registro.',
    vulnCode: `// ❌ CÓDIGO VULNERÁVEL (Node.js / Express)
app.get('/api/v1/faturas/:faturaId', autenticarJWT, async (req, res) => {
  // Busca a fatura apenas pelo ID enviado na URL!
  // Qualquer usuário logado pode trocar :faturaId para ver faturas alheias
  const fatura = await db.Faturas.findById(req.params.faturaId);
  return res.json(fatura);
});`,
    secureCode: `// ✅ CÓDIGO SEGURO (Validação de Propriedade + UUID)
app.get('/api/v1/faturas/:faturaUuid', autenticarJWT, async (req, res) => {
  // Filtra pelo ID do recurso E pelo ID do usuário extraído do token JWT
  const fatura = await db.Faturas.findOne({
    uuid: req.params.faturaUuid,
    ownerUserId: req.user.id
  });
  if (!fatura) return res.status(403).json({ erro: 'Acesso negado ao recurso.' });
  return res.json(fatura);
});`
  },
  auth: {
    title: 'API2:2023 — Broken Authentication (Falhas em Tokens e Sessão)',
    desc: 'Implementação incorreta de mecanismos de autenticação, permitindo que atacantes forjem tokens JWT (ex: aceitando algoritmo "none" ou segredos fracos), roubem sessões ou façam credential stuffing.',
    vulnCode: `// ❌ CÓDIGO VULNERÁVEL
// 1. Segredo fraco hardcoded e sem restrição de algoritmo
const decoded = jwt.decode(token); // decode() NÃO verifica assinatura criptográfica!
req.user = decoded;
next();`,
    secureCode: `// ✅ CÓDIGO SEGURO
// 1. Verifica assinatura com chave pública/secreta forte e fixa o algoritmo
const decoded = jwt.verify(token, process.env.JWT_PUBLIC_KEY, {
  algorithms: ['RS256'],
  issuer: 'https://auth.suaempresa.com.br',
  maxAge: '15m'
});
req.user = decoded;`
  },
  bopla: {
    title: 'API3:2023 — Broken Object Property Level Authorization (Mass Assignment)',
    desc: 'Combina Exposição Excessiva de Dados e Atribuição em Massa (Mass Assignment). Ocorre quando a API salva diretamente todo o corpo JSON enviado pelo cliente no banco, permitindo alterar propriedades internas como "role" ou "saldo".',
    vulnCode: `// ❌ CÓDIGO VULNERÁVEL (Mass Assignment)
app.put('/api/v1/perfil', autenticarJWT, async (req, res) => {
  // Se o atacante enviar {"nome": "Ana", "isAdmin": true, "creditos": 99999}
  // o ORM atualiza todas as colunas diretamente!
  const user = await db.Users.update(req.user.id, req.body);
  return res.json(user); // Ainda retorna password_hash no objeto!
});`,
    secureCode: `// ✅ CÓDIGO SEGURO (Allowlist / DTO Estrito)
app.put('/api/v1/perfil', autenticarJWT, async (req, res) => {
  // Extrai explicitamente APENAS os campos permitidos para edição pelo usuário
  const { nome, telefone } = req.body;
  await db.Users.update(req.user.id, { nome, telefone });
  return res.json({ id: req.user.id, nome, telefone });
});`
  },
  ratelimit: {
    title: 'API4:2023 — Unrestricted Resource Consumption (Falta de Rate Limit)',
    desc: 'APIs que não limitam a frequência de requisições, tamanho de paginação ou upload de arquivos ficam vulneráveis a Negação de Serviço (DoS), força bruta de OTP/senhas e custos financeiros explosivos em nuvem.',
    vulnCode: `// ❌ CÓDIGO VULNERÁVEL
app.get('/api/v1/relatorios', async (req, res) => {
  // O cliente pode pedir ?limit=10000000 e travar o banco de dados
  const limit = parseInt(req.query.limit);
  const dados = await db.Logs.find().limit(limit);
  res.json(dados);
});`,
    secureCode: `// ✅ CÓDIGO SEGURO (Rate Limiter + Teto de Paginação)
app.get('/api/v1/relatorios', rateLimiter({ max: 60, windowMs: 60000 }), async (req, res) => {
  // Impõe teto máximo de 100 registros por página
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);
  const dados = await db.Logs.find().limit(limit);
  res.json(dados);
});`
  },
  ssrf: {
    title: 'API7:2023 — Server-Side Request Forgery (SSRF)',
    desc: 'Ocorre quando uma API busca um recurso remoto (ex: webhook, avatar por URL, importação de PDF) sem validar o endereço de destino. O atacante força o servidor a acessar a rede interna ou metadados da nuvem (169.254.169.254).',
    vulnCode: `// ❌ CÓDIGO VULNERÁVEL
app.post('/api/v1/webhook-test', async (req, res) => {
  // Atacante envia: {"url": "http://169.254.169.254/latest/meta-data/iam/"}
  const resp = await fetch(req.body.url);
  const texto = await resp.text();
  res.send(texto); // Vazamento das credenciais AWS do servidor!
});`,
    secureCode: `// ✅ CÓDIGO SEGURO (Allowlist de Domínios e Bloqueio de IP Privado)
app.post('/api/v1/webhook-test', async (req, res) => {
  const parsed = new URL(req.body.url);
  if (!DOMINIOS_PERMITIDOS.includes(parsed.hostname) || isPrivateIP(parsed.hostname)) {
    return res.status(400).json({ erro: 'Host de destino bloqueado por política SSRF.' });
  }
  const resp = await fetch(parsed.toString());
  res.json({ status: resp.status });
});`
  }
};

function initOwaspExplorer() {
  const container = document.getElementById('owaspContent');
  const tabs = document.querySelectorAll('.owasp-tab');

  function renderOwasp(key) {
    const item = OWASP_DATA[key];
    container.innerHTML = `
      <div class="owasp-detail-header">
        <h4>${item.title}</h4>
        <p class="text-muted">${item.desc}</p>
      </div>
      <div class="code-comparison">
        <div class="code-pane vuln">
          <div class="pane-title">
            <span>🔓 Implementação Vulnerável</span>
            <span>Risco Alto</span>
          </div>
          <pre><code>${escapeHtml(item.vulnCode)}</code></pre>
        </div>
        <div class="code-pane secure">
          <div class="pane-title">
            <span>🛡️ Implementação Segura (Mitigada)</span>
            <span>Recomendado</span>
          </div>
          <pre><code>${escapeHtml(item.secureCode)}</code></pre>
        </div>
      </div>
    `;
  }

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      renderOwasp(tab.getAttribute('data-vuln'));
    });
  });

  renderOwasp('bola');
}

/* ==========================================================================
   4. LINHA DO TEMPO HISTÓRICA (2.2 HISTÓRICO)
   ========================================================================== */
const TIMELINE_DATA = {
  '2000': {
    period: '2000 – 2005 · A Era SOA, XML-RPC e SOAP',
    summary: 'As integrações corporativas nasceram baseadas em XML e no protocolo SOAP. A segurança dependia do padrão WS-Security (assinatura e criptografia XML pesada) e conexões ponto a ponto entre empresas.',
    threats: 'Principais Ameaças: XML External Entity (XXE), XML Bomb (Billion Laughs DoS) e complexidade excessiva de configuração.',
    codeExample: `<!-- Envelope SOAP Clássico com WS-Security -->
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Header>
    <wsse:Security>
      <wsse:UsernameToken>...</wsse:UsernameToken>
    </wsse:Security>
  </soap:Header>
  <soap:Body>
    <GetAccountBalance><AccountId>1042</AccountId></GetAccountBalance>
  </soap:Body>
</soap:Envelope>`
  },
  '2006': {
    period: '2006 – 2013 · A Revolução REST, JSON e Smartphones',
    summary: 'A tese de Roy Fielding (REST) e o lançamento do iPhone/Android popularizaram APIs leves em JSON sobre HTTP. Surgem as primeiras versões do OAuth (1.0 e 2.0 em 2012) para delegar acesso sem compartilhar senhas.',
    threats: 'Principais Ameaças: API Keys enviadas em texto claro, falta de HTTPS em redes móveis e ausência de controles de sessão stateless.',
    codeExample: `// Transição para REST + JSON + OAuth 2.0 Bearer Token
GET /v1/timeline.json HTTP/1.1
Host: api.rede-social.com
Authorization: Bearer 8x92kLp0192mN...`
  },
  '2014': {
    period: '2014 – 2018 · Microsserviços, SPAs (React/Angular) e GraphQL',
    summary: 'Monolitos foram quebrados em dezenas de microsserviços. A comunicação Leste-Oeste (serviço a serviço) explodiu. O Facebook lançou o GraphQL (2015), permitindo queries flexíveis em um único endpoint.',
    threats: 'Principais Ameaças: Introspecção GraphQL exposta, queries profundamente aninhadas (DoS), BOLA entre microsserviços e vazamento em repositórios públicos.',
    codeExample: `# Ataque de Query Aninhada em GraphQL sem limite de profundidade:
query AtaqueDoS {
  usuario(id: 1) {
    amigos { amigos { amigos { amigos { nome } } } }
  }
}`
  },
  '2019': {
    period: '2019 – 2023 · Nascimento do OWASP API Top 10 e Zero Trust',
    summary: 'Em 2019, a OWASP reconheceu que o Top 10 Web tradicional não cobria as falhas lógicas de APIs e lançou o primeiro OWASP API Security Top 10 (atualizado em 2023). Surge a arquitetura Zero Trust com mTLS e Service Mesh.',
    threats: 'Principais Ameaças: BOLA/IDOR massivo, Shadow/Zombie APIs durante a pandemia e ataques automatizados de bots contra fluxos de negócio.',
    codeExample: `// Política Zero Trust: Nenhum pacote é confiável apenas por estar na rede interna
// Exige mTLS (Certificado do Serviço) + JWT (Identidade do Usuário Final)`
  },
  '2024': {
    period: '2024 – Hoje · APIs de Inteligência Artificial (LLMs) e Open Finance',
    summary: 'Agentes de IA autônomos consomem APIs diretamente (Function Calling / MCP). No Brasil, o Open Finance consolida um dos ecossistemas de APIs mais avançados do mundo com FAPI e mTLS ICP-Brasil.',
    threats: 'Principais Ameaças: Prompt Injection acionando APIs internas, Denial of Wallet (exaustão financeira de tokens de IA) e vazamento de chaves de LLMs.',
    codeExample: `// Proteção Moderna em Gateways de IA & Open Finance:
// 1. Certificado mTLS válido + DPoP (Demonstrating Proof-of-Possession)
// 2. Rate Limit por Custo de Tokens + Guardrails de saída`
  }
};

function initTimeline() {
  const nodes = document.querySelectorAll('.timeline-node');
  const detail = document.getElementById('timelineDetail');

  function renderEra(era) {
    const data = TIMELINE_DATA[era];
    detail.innerHTML = `
      <div class="timeline-detail-grid">
        <div>
          <span class="concept-badge">${data.period}</span>
          <h3 style="margin-bottom: 0.6rem;">Marco Histórico & Arquitetural</h3>
          <p style="color: var(--text-secondary); margin-bottom: 0.9rem;">${data.summary}</p>
          <div class="terminal-note warning-note" style="margin-bottom:0;">
            <strong>⚠️ ${data.threats}</strong>
          </div>
        </div>
        <div>
          <pre class="code-block"><code>${escapeHtml(data.codeExample)}</code></pre>
        </div>
      </div>
    `;
  }

  nodes.forEach(node => {
    node.addEventListener('click', () => {
      nodes.forEach(n => n.classList.remove('active'));
      node.classList.add('active');
      renderEra(node.getAttribute('data-era'));
    });
  });

  renderEra('2000');
}

/* ==========================================================================
   5. EXEMPLO PRÁTICO #2: INSPETOR JWT & PIPELINE DE DEFESA
   ========================================================================== */
const JWT_MODES = {
  secure: {
    rawHeader: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9',
    rawPayload: 'eyJzdWIiOiJ1c3JfMTA0MiIsInJvbGUiOiJjdXN0b21lciIsInNjb3BlIjoicmVhZDpvcmRlcnMiLCJleHAiOjE3OTUzODAwMDB9',
    rawSig: 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    header: { alg: 'RS256', typ: 'JWT', kid: 'key-2026-prod' },
    payload: { sub: 'usr_1042', role: 'customer', scope: 'read:orders', exp: 1795380000 },
    statusClass: 'ok',
    statusMsg: '✅ Assinatura RSA-256 Válida! O servidor confia nas claims e sabe que o usuário é "usr_1042" com perfil "customer".'
  },
  algnone: {
    rawHeader: 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0',
    rawPayload: 'eyJzdWIiOiJ1c3JfMTA0MiIsInJvbGUiOiJhZG1pbiIsInNjb3BlIjoiallifQ',
    rawSig: '',
    header: { alg: 'none', typ: 'JWT' },
    payload: { sub: 'usr_1042', role: 'admin', scope: 'all' },
    statusClass: 'err',
    statusMsg: '🚨 ATAQUE "alg: none": O atacante removeu a assinatura e trocou o algoritmo para "none". Bibliotecas mal configuradas aceitam o token como administrador!'
  },
  tampered: {
    rawHeader: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9',
    rawPayload: 'eyJzdWIiOiJ1c3JfMTA0MiIsInJvbGUiOiJzdXBlcmFkbWluIiwiZXhwIjoxOTk5OTk5OTk5fQ',
    rawSig: 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    header: { alg: 'RS256', typ: 'JWT' },
    payload: { sub: 'usr_1042', role: 'superadmin', exp: 1999999999 },
    statusClass: 'err',
    statusMsg: '🛡️ BLOQUEADO PELA ASSINATURA: O atacante decodificou o Base64 e alterou "role" para "superadmin", mas como não possui a chave privada do servidor, a verificação criptográfica da assinatura falha!'
  }
};

function initJwtInspector() {
  const btns = document.querySelectorAll('[data-jwt-mode]');
  const rawH = document.getElementById('jwtRawHeader');
  const rawP = document.getElementById('jwtRawPayload');
  const rawS = document.getElementById('jwtRawSig');
  const decH = document.getElementById('jwtDecodedHeader');
  const decP = document.getElementById('jwtDecodedPayload');
  const banner = document.getElementById('jwtStatusBanner');

  function renderJwt(modeKey) {
    const d = JWT_MODES[modeKey];
    rawH.textContent = d.rawHeader;
    rawP.textContent = d.rawPayload;
    rawS.textContent = d.rawSig || '(assinatura_removida)';
    decH.textContent = JSON.stringify(d.header, null, 2);
    decP.textContent = JSON.stringify(d.payload, null, 2);
    banner.className = `jwt-status-banner ${d.statusClass}`;
    banner.textContent = d.statusMsg;
  }

  btns.forEach(btn => {
    btn.addEventListener('click', () => {
      btns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      renderJwt(btn.getAttribute('data-jwt-mode'));
    });
  });

  renderJwt('secure');
}

const PIPELINE_DATA = {
  waf: {
    title: 'Camada 1: CDN, Anti-DDoS & WAAP (Web Application and API Protection)',
    desc: 'Termina conexões TLS 1.3 na borda, absorve ataques volumétricos DDoS, bloqueia bots conhecidos de credential stuffing e filtra payloads malformados ou SQL Injection/XSS antes de chegarem à infraestrutura.'
  },
  gateway: {
    title: 'Camada 2: API Gateway (Kong, Apigee, AWS API Gateway)',
    desc: 'Ponto único de entrada: valida certificados mTLS, verifica assinatura e expiração do token JWT (OAuth 2.0), aplica Rate Limiting por cliente/IP e roteia apenas endpoints documentados (bloqueando Shadow APIs).'
  },
  authz: {
    title: 'Camada 3: Microsserviço & Lógica de Negócios (Autorização BOLA/BFLA)',
    desc: 'Onde o Gateway não enxerga: o código do serviço valida se o "user_id" do token tem permissão sobre o registro solicitado no banco de dados (prevenindo BOLA) e aplica DTOs para evitar Mass Assignment.'
  },
  runtime: {
    title: 'Camada 4: Monitoramento Contínuo, Logs de Auditoria & Detecção de Anomalias',
    desc: 'Analisa o comportamento em tempo real: se um usuário autenticado começa a consultar 300 IDs diferentes por minuto, o motor de segurança identifica a enumeração e revoga o token automaticamente.'
  }
};

function initPipelineDiagram() {
  const steps = document.querySelectorAll('.pipeline-step');
  const detail = document.getElementById('pipelineDetail');

  function renderPipe(key) {
    const item = PIPELINE_DATA[key];
    detail.innerHTML = `
      <h4 style="color: var(--accent-primary); margin-bottom: 0.35rem;">${item.title}</h4>
      <p style="color: var(--text-secondary);">${item.desc}</p>
    `;
  }

  steps.forEach(step => {
    step.addEventListener('click', () => {
      steps.forEach(s => s.classList.remove('active'));
      step.classList.add('active');
      renderPipe(step.getAttribute('data-pipe'));
    });
  });

  renderPipe('waf');
}

/* ==========================================================================
   6. CASOS NOTÁVEIS REAIS (2.5 CASOS)
   ========================================================================== */
const CASES_DATA = [
  {
    id: 'optus',
    year: '2022',
    company: 'Optus Telecom (Austrália)',
    category: 'bola',
    vulnTag: 'API1: BOLA + Shadow API Sem Auth',
    impact: '9,8 milhões de clientes expostos (passaportes, CNH, CPF australiano) e prejuízo estimado em US$ 140 milhões.',
    desc: 'Um subdomínio de API de homologação/legado foi deixado acessível na internet pública sem exigir token de autenticação e com identificadores sequenciais de clientes.',
    techSnippet: `GET https://api.optus.com.au/customers/1004921\n// Retornava 200 OK com PII completo sem cabeçalho Authorization!`,
    lesson: 'Lição: Manter inventário rigoroso de subdomínios, bloquear APIs de teste na borda e exigir autenticação padrão em todas as rotas.'
  },
  {
    id: 'peloton',
    year: '2021',
    company: 'Peloton Interactive',
    category: 'bola',
    vulnTag: 'API1: BOLA / IDOR',
    impact: 'Qualquer usuário podia consultar dados privados (idade, localização, peso, estatísticas) de mais de 3 milhões de contas, inclusive perfis marcados como privados.',
    desc: 'O endpoint da API autenticava o usuário, mas não verificava se o solicitante tinha permissão para visualizar perfis privados quando consultados diretamente pelo user_id.',
    techSnippet: `GET /api/user/f8291a0c-912b\n// Ignorava a flag "is_profile_private: true" no nível da API`,
    lesson: 'Lição: Regras de privacidade não podem existir apenas na interface do aplicativo (UI); devem ser impostas no backend da API.'
  },
  {
    id: 'twitter',
    year: '2022',
    company: 'Twitter (X)',
    category: 'scraping',
    vulnTag: 'API4 + Lógica de Negócio',
    impact: 'Mais de 5,4 milhões de contas tiveram telefone e e-mail vinculados aos seus @handles e vendidos em fóruns de hackers.',
    desc: 'Uma falha no endpoint de sincronização de contatos do Android permitia enviar qualquer e-mail ou telefone e a API respondia qual conta correspondia a ele, sem Rate Limit adequado.',
    techSnippet: `POST /i/api/1.1/users/email_phone_info.json\n{"email": "alvo@empresa.com"} -> Retornava {"user_id": "882192"}`,
    lesson: 'Lição: Endpoints de busca/descoberta devem possuir Rate Limiting agressivo, detecção de bots e respostas genéricas.'
  },
  {
    id: 'tmobile',
    year: '2023',
    company: 'T-Mobile (EUA)',
    category: 'scraping',
    vulnTag: 'API1: BOLA + API4: Sem Rate Limit',
    impact: '37 milhões de registros de clientes extraídos ao longo de mais de 40 dias sem detecção inicial.',
    desc: 'Atacantes exploraram uma API vulnerável a BOLA e realizaram milhões de requisições automatizadas para coletar nome, endereço de cobrança, e-mail e dados do plano.',
    techSnippet: `// Enumeração contínua durante semanas sem alerta de anomalia comportamental`,
    lesson: 'Lição: Monitoramento comportamental de APIs é indispensável para detectar extração lenta e contínua de dados.'
  },
  {
    id: 'parler',
    year: '2021',
    company: 'Parler Social Network',
    category: 'auth',
    vulnTag: 'IDs Sequenciais + Falha de Auth',
    impact: '70 Terabytes de posts, vídeos com metadados GPS EXIF e até postagens deletadas foram baixados integralmente.',
    desc: 'APIs públicas com IDs numéricos sequenciais (1, 2, 3...), sem controle de taxa e que apenas marcavam posts como "deleted: true" no JSON em vez de ocultá-los.',
    techSnippet: `GET /v1/post/100001 -> GET /v1/post/100002\n// Retornava o vídeo original mesmo quando deletado pelo usuário`,
    lesson: 'Lição: Usar UUIDs não sequenciais, aplicar Rate Limit global e nunca retornar registros excluídos no payload da API.'
  }
];

function initCases() {
  const grid = document.getElementById('casesGrid');
  const filterBtns = document.querySelectorAll('[data-case-filter]');

  function renderCases(filter) {
    const list = filter === 'all' ? CASES_DATA : CASES_DATA.filter(c => c.category === filter);
    grid.innerHTML = list.map(c => `
      <article class="case-card">
        <div>
          <div class="case-top">
            <span class="case-year">📅 ${c.year}</span>
            <span class="case-vuln-tag">${c.vulnTag}</span>
          </div>
          <h3>${c.company}</h3>
          <p class="case-desc" style="margin: 0.5rem 0;"><strong>Impacto:</strong> ${c.impact}</p>
          <p class="case-desc">${c.desc}</p>
        </div>
        <div>
          <pre class="case-tech-box" style="margin-bottom: 0.7rem;"><code>${escapeHtml(c.techSnippet)}</code></pre>
          <div class="case-lesson">💡 <strong>${c.lesson}</strong></div>
        </div>
      </article>
    `).join('');
  }

  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      filterBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      renderCases(btn.getAttribute('data-case-filter'));
    });
  });

  renderCases('all');
}

/* ==========================================================================
   7. EXEMPLO PRÁTICO #3: LABORATÓRIO INTERATIVO DE ATAQUE E DEFESA
   ========================================================================== */
function initInteractiveLab() {
  let currentScenario = 'bola';
  let isProtected = false;
  let rateLimitCounter = 0;

  const scenarioBtns = document.querySelectorAll('[data-scenario]');
  const defenseSwitch = document.getElementById('defenseSwitch');
  const defenseStatusText = document.getElementById('defenseStatusText');
  const labInstruction = document.getElementById('labInstruction');
  const labMethod = document.getElementById('labMethod');
  const labUrl = document.getElementById('labUrl');
  const labPayload = document.getElementById('labPayload');
  const labPresets = document.getElementById('labPresets');
  const sendBtn = document.getElementById('sendRequestBtn');
  const statusPill = document.getElementById('labStatusPill');
  const responseCode = document.getElementById('labResponseCode');
  const explanation = document.getElementById('labExplanation');

  const SCENARIOS = {
    bola: {
      method: 'GET',
      url: '/api/v1/contas/1043/extrato',
      instruction: 'Você está autenticado como Maria (user_id: 1042). Tente acessar o extrato da sua própria conta (1042) ou altere a URL para invadir a conta 1043 (João).',
      payload: `Authorization: Bearer eyJhbGciOiJSUzI1Ni... (user_id: 1042)\nAccept: application/json`,
      presets: [
        { label: '👤 Consultar Minha Conta (1042)', url: '/api/v1/contas/1042/extrato' },
        { label: '🏴‍☠️ Atacar Conta Alheia (1043 - BOLA)', url: '/api/v1/contas/1043/extrato' },
        { label: '🏴‍☠️ Atacar Conta VIP (1001 - BOLA)', url: '/api/v1/contas/1001/extrato' }
      ]
    },
    mass: {
      method: 'PUT',
      url: '/api/v1/usuarios/1042/perfil',
      instruction: 'Envie uma atualização de perfil JSON. No ataque de Mass Assignment, injetamos os campos "role": "admin" e "limite_pix": 500000 no corpo da requisição.',
      payload: `{\n  "nome": "Maria Silva",\n  "telefone": "(11) 99999-0000",\n  "role": "admin",\n  "limite_pix": 500000\n}`,
      presets: [
        {
          label: '✅ Payload Normal',
          body: `{\n  "nome": "Maria Silva",\n  "telefone": "(11) 98888-1111"\n}`
        },
        {
          label: '🏴‍☠️ Injetar "role": "admin" (Mass Assignment)',
          body: `{\n  "nome": "Maria Silva",\n  "telefone": "(11) 98888-1111",\n  "role": "admin",\n  "limite_pix": 500000\n}`
        }
      ]
    },
    ratelimit: {
      method: 'POST',
      url: '/api/v1/auth/verificar-otp',
      instruction: 'Clique várias vezes seguidas em "Enviar Requisição" para simular um ataque de força bruta contra um código SMS/OTP de 4 dígitos.',
      payload: `{\n  "cpf": "123.456.789-00",\n  "codigo_otp": "4829"\n}`,
      presets: [
        { label: '🔁 Testar PIN #1 (4829)', body: `{\n  "cpf": "123.456.789-00",\n  "codigo_otp": "4829"\n}` },
        { label: '🔁 Testar PIN #2 (9104)', body: `{\n  "cpf": "123.456.789-00",\n  "codigo_otp": "9104"\n}` }
      ]
    }
  };

  function loadScenario(key) {
    currentScenario = key;
    rateLimitCounter = 0;
    const sc = SCENARIOS[key];
    labMethod.textContent = sc.method;
    labUrl.value = sc.url;
    labInstruction.textContent = sc.instruction;
    labPayload.value = sc.payload;

    labPresets.innerHTML = sc.presets.map((p, idx) =>
      `<button type="button" class="btn-sm" data-preset-idx="${idx}">${p.label}</button>`
    ).join('');

    labPresets.querySelectorAll('[data-preset-idx]').forEach(btn => {
      btn.addEventListener('click', () => {
        const preset = sc.presets[parseInt(btn.getAttribute('data-preset-idx'), 10)];
        if (preset.url) labUrl.value = preset.url;
        if (preset.body) labPayload.value = preset.body;
        executeSimulation();
      });
    });

    executeSimulation();
  }

  function executeSimulation() {
    const url = labUrl.value.trim();
    const rawBody = labPayload.value;

    if (currentScenario === 'bola') {
      const match = url.match(/\/contas\/(\d+)/);
      const requestedId = match ? match[1] : '1042';

      if (requestedId === '1042') {
        statusPill.className = 'status-pill status-200';
        statusPill.textContent = 'HTTP 200 OK (Acesso Legítimo)';
        responseCode.textContent = JSON.stringify({
          conta_id: 1042,
          titular: 'Maria Silva (Você)',
          saldo: 'R$ 3.420,00',
          ultimas_transacoes: ['PIX Recebido R$ 500,00', 'Padaria Central R$ 28,90']
        }, null, 2);
        explanation.innerHTML = '✅ <strong>Requisição Legítima:</strong> O ID da conta na URL (1042) pertence à própria usuária autenticada no token JWT (1042).';
      } else if (!isProtected) {
        statusPill.className = 'status-pill status-danger';
        statusPill.textContent = '⚠️ HTTP 200 OK (VAZAMENTO BOLA!)';
        responseCode.textContent = JSON.stringify({
          conta_id: parseInt(requestedId, 10),
          titular: requestedId === '1001' ? 'Diretoria Financeira S/A' : 'João Souza (Outro Cliente!)',
          cpf: '987.654.321-11',
          saldo: requestedId === '1001' ? 'R$ 1.480.900,00' : 'R$ 42.810,55',
          chave_pix_secreta: 'joao.souza@email.com'
        }, null, 2);
        explanation.innerHTML = '🚨 <strong>Vulnerabilidade Explorada (API1:2023 - BOLA):</strong> O servidor validou que seu token JWT era válido, mas NÃO conferiu se a conta <code>' + requestedId + '</code> pertencia ao <code>user_id: 1042</code>! Clique em "API VULNERÁVEL" no topo para ativar a correção.';
      } else {
        statusPill.className = 'status-pill status-blocked';
        statusPill.textContent = '🛡️ HTTP 403 Forbidden (Bloqueado)';
        responseCode.textContent = JSON.stringify({
          status: 403,
          error: 'Forbidden - Broken Object Level Authorization Prevention',
          message: `O usuário autenticado (1042) não possui permissão de propriedade sobre o objeto conta (${requestedId}).`,
          audit_log_id: 'sec_evt_99481a'
        }, null, 2);
        explanation.innerHTML = '🛡️ <strong>Ataque Mitigado com Sucesso!</strong> No Modo Seguro, a query do banco exige <code>WHERE conta_id = :id AND owner_id = req.user.id</code>. A tentativa foi bloqueada com HTTP 403 e registrada no SIEM.';
      }
    } else if (currentScenario === 'mass') {
      let parsed = {};
      try {
        parsed = JSON.parse(rawBody);
      } catch {
        statusPill.className = 'status-pill status-danger';
        statusPill.textContent = 'HTTP 400 Bad Request (JSON Inválido)';
        responseCode.textContent = '// Erro de sintaxe no JSON enviado.';
        return;
      }

      const hasAttack = parsed.role === 'admin' || parsed.limite_pix !== undefined;

      if (!isProtected && hasAttack) {
        statusPill.className = 'status-pill status-danger';
        statusPill.textContent = '⚠️ HTTP 200 OK (ESCALAÇÃO DE PRIVILÉGIO!)';
        responseCode.textContent = JSON.stringify({
          id: 1042,
          nome: parsed.nome || 'Maria Silva',
          telefone: parsed.telefone || '(11) 99999-0000',
          role: parsed.role || 'customer',
          limite_pix: parsed.limite_pix || 5000,
          status: 'Perfil atualizado via db.update(req.body)'
        }, null, 2);
        explanation.innerHTML = '🚨 <strong>Vulnerabilidade Explorada (API3:2023 - Mass Assignment):</strong> A API salvou todo o objeto <code>req.body</code> diretamente no banco. A usuária comum transformou sua conta em <code>"role": "admin"</code>!';
      } else {
        statusPill.className = 'status-pill status-blocked';
        statusPill.textContent = isProtected && hasAttack ? '🛡️ HTTP 200 OK (Campos Extras Ignorados pelo DTO)' : 'HTTP 200 OK';
        responseCode.textContent = JSON.stringify({
          id: 1042,
          nome: parsed.nome || 'Maria Silva',
          telefone: parsed.telefone || '(11) 99999-0000',
          role: 'customer (protegido - somente leitura)',
          limite_pix: 5000
        }, null, 2);
        explanation.innerHTML = '🛡️ <strong>Protegido por Schema / DTO Allowlist:</strong> O servidor aplica desestruturação estrita <code>const { nome, telefone } = req.body</code>, ignorando ou rejeitando propriedades sensíveis como <code>role</code> e <code>limite_pix</code>.';
      }
    } else if (currentScenario === 'ratelimit') {
      rateLimitCounter++;
      if (!isProtected) {
        statusPill.className = 'status-pill status-danger';
        statusPill.textContent = `⚠️ HTTP 200 / 401 (Tentativa #${rateLimitCounter} Permitida Sem Limite)`;
        responseCode.textContent = JSON.stringify({
          tentativa_numero: rateLimitCounter,
          resultado: 'Código OTP incorreto, tente novamente.',
          rate_limit_ativo: false,
          aviso: 'Um script automatizado pode testar todos os 10.000 códigos possíveis em segundos!'
        }, null, 2);
        explanation.innerHTML = `🚨 <strong>Vulnerabilidade Explorada (API4:2023 - Sem Rate Limit):</strong> Já foram enviadas <strong>${rateLimitCounter} requisições</strong> consecutivas sem nenhum bloqueio ou atraso.`;
      } else {
        if (rateLimitCounter <= 2) {
          statusPill.className = 'status-pill status-200';
          statusPill.textContent = `HTTP 401 (Tentativa ${rateLimitCounter}/2 — Restam ${2 - rateLimitCounter})`;
          responseCode.textContent = JSON.stringify({
            tentativa: rateLimitCounter,
            headers: {
              'X-RateLimit-Limit': 2,
              'X-RateLimit-Remaining': 2 - rateLimitCounter
            },
            mensagem: 'Código OTP inválido. Clique novamente em Enviar Requisição para disparar o Rate Limiter.'
          }, null, 2);
          explanation.innerHTML = 'ℹ️ <strong>Rate Limiter Monitorando:</strong> O API Gateway permite no máximo 2 tentativas por janela. Clique em <strong>Enviar Requisição</strong> mais uma vez para ver o bloqueio HTTP 429.';
        } else {
          statusPill.className = 'status-pill status-blocked';
          statusPill.textContent = '🛡️ HTTP 429 Too Many Requests (Bloqueado)';
          responseCode.textContent = JSON.stringify({
            status: 429,
            error: 'Too Many Requests',
            retry_after_seconds: 300,
            message: 'Limite de tentativas de OTP excedido. IP e conta bloqueados temporariamente por 5 minutos.'
          }, null, 2);
          explanation.innerHTML = '🛡️ <strong>Ataque de Força Bruta Neutralizado!</strong> O API Gateway retornou <code>HTTP 429 Too Many Requests</code> com cabeçalho <code>Retry-After: 300</code>, impedindo a enumeração do código OTP.';
        }
      }
    }
  }

  scenarioBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      scenarioBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      loadScenario(btn.getAttribute('data-scenario'));
    });
  });

  defenseSwitch.addEventListener('click', () => {
    isProtected = !isProtected;
    rateLimitCounter = 0;
    if (isProtected) {
      defenseSwitch.className = 'defense-switch protected';
      defenseSwitch.querySelector('.switch-indicator').textContent = '🛡️';
      defenseStatusText.textContent = 'API PROTEGIDA (CORRIGIDA)';
    } else {
      defenseSwitch.className = 'defense-switch vulnerable';
      defenseSwitch.querySelector('.switch-indicator').textContent = '🔓';
      defenseStatusText.textContent = 'API VULNERÁVEL';
    }
    executeSimulation();
  });

  sendBtn.addEventListener('click', executeSimulation);

  loadScenario('bola');
}

/* ==========================================================================
   8. CHECKLIST INTERATIVO DE CONCLUSÃO & CÓPIA DE REFERÊNCIAS
   ========================================================================== */
function initChecklist() {
  const checks = document.querySelectorAll('.sec-check');
  const scoreBadge = document.getElementById('checklistScore');
  const barFill = document.getElementById('maturityBarFill');
  const feedback = document.getElementById('maturityFeedback');

  function updateChecklist() {
    let count = 0;
    checks.forEach(c => { if (c.checked) count++; });
    const total = checks.length;
    const pct = Math.round((count / total) * 100);

    scoreBadge.textContent = `${count} / ${total} concluídos (${pct}%)`;
    barFill.style.width = `${pct}%`;

    if (count === 0) {
      feedback.textContent = '⚠️ Nível Crítico: API exposta a ataques triviais de enumeração e BOLA.';
    } else if (count <= 3) {
      feedback.textContent = '🔶 Nível Intermediário: Controles básicos ativos, mas ainda há lacunas na lógica de negócios.';
    } else if (count < total) {
      feedback.textContent = '🔷 Nível Avançado: Boa cobertura de defesa em profundidade.';
    } else {
      feedback.textContent = '🛡️ Nível Excelente (DevSecOps Zero Trust): API pronta para produção crítica!';
    }
  }

  checks.forEach(c => c.addEventListener('change', updateChecklist));
}

function initReferencesCopy() {
  const btn = document.getElementById('copyRefsBtn');
  btn.addEventListener('click', () => {
    const refs = [
      'OWASP FOUNDATION. OWASP API Security Top 10 – 2023. Open Worldwide Application Security Project, 2023. Disponível em: https://owasp.org/API-Security/.',
      'NIST. NIST Special Publication 800-204A: Building Secure Microservices-based Applications Using Service-Mesh Architecture. Gaithersburg, MD, 2020.',
      'HARDT, D. (Ed.). The OAuth 2.0 Authorization Framework (RFC 6749) & JSON Web Token Best Current Practices (RFC 8725). IETF, 2020.',
      'MADDEN, Neil. API Security in Action. Shelter Island, NY: Manning Publications, 2020.',
      'BALL, Corey J. Hacking APIs: Breaking Web Application Programming Interfaces. San Francisco: No Starch Press, 2022.',
      'SALT SECURITY. State of API Security Report. Palo Alto, CA: Salt Labs, 2024.',
      'BRASIL. Lei nº 13.709/2018 (Lei Geral de Proteção de Dados Pessoais - LGPD) & Padrões Open Finance Brasil (Banco Central).'
    ].join('\n\n');

    navigator.clipboard.writeText(refs).then(() => {
      const orig = btn.textContent;
      btn.textContent = '✅ Referências Copiadas!';
      setTimeout(() => { btn.textContent = orig; }, 2200);
    });
  });
}

/* ==========================================================================
   9. MODO SLIDE (APRESENTAÇÃO EM TELA CHEIA COM TECLAS ← →)
   ========================================================================== */
function initSlideMode() {
  const presentBtn = document.getElementById('presentModeBtn');
  const exitBtn = document.getElementById('exitSlideBtn');
  const prevBtn = document.getElementById('prevSlideBtn');
  const nextBtn = document.getElementById('nextSlideBtn');
  const indicator = document.getElementById('slideIndicator');
  const slides = Array.from(document.querySelectorAll('.slide-section'));

  let currentSlide = 0;

  function updateSlideView() {
    slides.forEach((s, i) => {
      s.classList.toggle('active-slide', i === currentSlide);
    });
    const title = slides[currentSlide].getAttribute('data-slide-title') || `Slide ${currentSlide + 1}`;
    indicator.textContent = `${currentSlide + 1} / ${slides.length} · ${title}`;
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function enterSlideMode() {
    document.body.classList.add('slide-mode');
    currentSlide = 0;
    updateSlideView();
  }

  function exitSlideMode() {
    document.body.classList.remove('slide-mode');
    slides.forEach(s => s.classList.remove('active-slide'));
  }

  presentBtn.addEventListener('click', () => {
    if (document.body.classList.contains('slide-mode')) {
      exitSlideMode();
    } else {
      enterSlideMode();
    }
  });

  exitBtn.addEventListener('click', exitSlideMode);

  prevBtn.addEventListener('click', () => {
    if (currentSlide > 0) {
      currentSlide--;
      updateSlideView();
    }
  });

  nextBtn.addEventListener('click', () => {
    if (currentSlide < slides.length - 1) {
      currentSlide++;
      updateSlideView();
    }
  });

  window.addEventListener('keydown', e => {
    if (!document.body.classList.contains('slide-mode')) return;
    if (['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName)) return;

    if (e.key === 'ArrowRight' || e.key === 'PageDown') {
      if (currentSlide < slides.length - 1) {
        currentSlide++;
        updateSlideView();
      }
    } else if (e.key === 'ArrowLeft' || e.key === 'PageUp') {
      if (currentSlide > 0) {
        currentSlide--;
        updateSlideView();
      }
    } else if (e.key === 'Escape') {
      exitSlideMode();
    }
  });
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}
