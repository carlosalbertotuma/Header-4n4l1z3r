#!/bin/bash

banner()
{

    echo '                      _             _  _         _  _   _ _     _____      '
    echo '  /\  /\___  __ _  __| | ___ _ __  | || |  _ __ | || | | / |___|___ / _ __ '
    echo ' / /_/ / _ \/ _` |/ _` |/ _ \  __| | || |_|  _ \| || |_| | |_  / |_ \|  __|'
    echo '/ __  /  __/ (_| | (_| |  __/ |    |__   _| | | |__   _| | |/ / ___) | |   '
    echo '\/ /_/ \___|\__,_|\__,_|\___|_|       |_| |_| |_|  |_| |_|_/___|____/|_|   '
    echo '                                                                           '    
    echo "Desenvolvido por Carlos Tuma - Bl4dsc4n - Version 0.1"
    echo
    
}

modouso()
{
    echo -e "\e[31m[ERRO] Uso: $0 <URL>\e[0m"
}

# Verifica se a URL foi passada como argumento
if [ -z "$1" ]; then
    banner
    modouso
    exit 1
fi

URL="$1"

# Lista de headers de segurança recomendados
HEADERS_RECOMENDADOS=(
    "Content-Security-Policy"
    "X-Frame-Options"
    "X-XSS-Protection"
    "X-Content-Type-Options"
    "Strict-Transport-Security"
    "Referrer-Policy"
    "Permissions-Policy"
    "Expect-CT"
)

# Função para descrever o propósito de cada header
declare -A HEADER_DESCRICAO
HEADER_DESCRICAO=(
    ["Content-Security-Policy"]="Define as fontes permitidas para conteúdo como scripts e imagens, prevenindo injeções de código."
    ["X-Frame-Options"]="Impedir que o conteúdo seja exibido dentro de frames ou iframes, mitigando ataques clickjacking."
    ["X-XSS-Protection"]="Ativa proteção contra ataques de cross-site scripting (XSS)."
    ["X-Content-Type-Options"]="Evita que o navegador tente adivinhar o tipo de conteúdo, ajudando a prevenir ataques de MIME sniffing."
    ["Strict-Transport-Security"]="Força a comunicação segura via HTTPS, prevenindo ataques man-in-the-middle."
    ["Referrer-Policy"]="Controla as informações do referenciador enviadas nas requisições HTTP, protegendo a privacidade."
    ["Permissions-Policy"]="Controla o acesso a recursos específicos do navegador, como geolocalização ou câmera."
    ["Expect-CT"]="Força a verificação de certificados de segurança em relação ao site."
)

# Captura headers da resposta HTTP
RESPONSE_HEADERS=$(curl -s -I --http2 --max-time 10 "$URL")

# Verifica se a URL está acessível
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$URL")
if [ "$HTTP_STATUS" -ge 400 ]; then
    echo -e "\e[31m[ERRO] O site retornou um código HTTP $HTTP_STATUS. Verifique a URL.\e[0m"
    exit 1
fi

# Exibir headers obtidos
banner
echo -e "\n🔎 \e[34mAnalisando headers de resposta para:\e[0m $URL\n"
echo -e "📜 \e[34mHeaders encontrados:\e[0m\n$RESPONSE_HEADERS"

# Verificar headers presentes
echo -e "\n✅ \e[32mHeaders presentes:\e[0m\n"
for HEADER in "${HEADERS_RECOMENDADOS[@]}"; do
    if echo "$RESPONSE_HEADERS" | grep -i -q "^$HEADER:"; then
        echo -e "✅ \e[32m$HEADER:\e[0m ${HEADER_DESCRICAO[$HEADER]}"
    fi
done

# Verificar headers ausentes
echo -e "\n⚠️ \e[32m**Vulnerabilidade detectada**: (CWE: 693) CVSS3 Score: 3.1 LOW\e[0m"
echo -e "\n🚨 \e[31mHeaders de segurança ausentes:\e[0m\n"
MISSING_HEADERS=0
for HEADER in "${HEADERS_RECOMENDADOS[@]}"; do
    if ! echo "$RESPONSE_HEADERS" | grep -i -q "^$HEADER:"; then
        echo -e "❌ \e[31m$HEADER (Faltando)\e[0m"
        ((MISSING_HEADERS++))
    fi
done

if [ "$MISSING_HEADERS" -eq 0 ]; then
    echo -e "✅ \e[32mTodos os headers de segurança essenciais estão presentes!\e[0m"
fi

# Sugestões para headers ausentes
echo -e "\n💡 \e[33mSugestões de melhorias:\e[0m\n"

declare -A SUGESTOES=(
    ["X-Frame-Options"]="Impedir que o conteúdo do seu site seja carregado em um frame ou iframe em sites de terceiros, protegendo contra ataques de clickjacking (onde o usuário é enganado a clicar em elementos ocultos ou maliciosos)."
    
    ["Referrer-Policy"]="Controla a quantidade de informações de referenciador enviadas em requisições HTTP, protegendo a privacidade do usuário e evitando a exposição de informações sensíveis, como a URL original de onde a requisição foi feita."
    
    ["Permissions-Policy"]="Define as permissões de acesso a recursos sensíveis do navegador, como geolocalização, câmera e microfone, impedindo que sites maliciosos acessem essas funcionalidades sem o consentimento do usuário."
    
    ["Expect-CT"]="Força a verificação de certificados TLS e garante que os certificados utilizados pelo site estejam listados em um log de certificação pública (CT), prevenindo ataques como ataques de certificação falsificada."
    
    ["Cross-Origin-Embedder-Policy"]="Reforça segurança contra embeddings não confiáveis, controlando o carregamento de recursos de diferentes origens."
    
    ["Cross-Origin-Opener-Policy"]="Reforça isolamento de contexto entre origens, garantindo que scripts não possam acessar dados de outras origens."
    
    ["Cross-Origin-Resource-Policy"]="Restringe quais sites podem carregar seus recursos, evitando o carregamento indesejado por sites não confiáveis."
    
    ["CORS"]="Define políticas de compartilhamento de recursos entre origens diferentes, controlando quais sites podem acessar os recursos da sua aplicação."
)

declare -A POLITICAS=(
    ["X-Frame-Options"]="DENY"
    ["Referrer-Policy"]="no-referrer"
    ["Permissions-Policy"]="geolocation=(), microphone=(), camera=()"
    ["Expect-CT"]="max-age=86400, enforce"
    ["Cross-Origin-Embedder-Policy"]="require-corp"
    ["Cross-Origin-Opener-Policy"]="same-origin"
    ["Cross-Origin-Resource-Policy"]="same-origin"
    ["CORS"]="https://exemplo.com"
)

for header in "${!SUGESTOES[@]}"; do
    # Primeira linha amarela com o nome do header
    echo -e "⚠️ Adicione \033[33m$header\033[0m para melhorar a segurança:"
    
    # Descrição do header
    echo -e "${SUGESTOES[$header]}"
    
    # Linha "Para definir o header" em amarelo com o valor real do header
    echo -e "\033[32mPara definir o header:\033[0m \033[33m$header: ${POLITICAS[$header]}\033[0m"
    echo
done





#for HEADER in "${HEADERS_RECOMENDADOS[@]}"; do
#    if ! echo "$RESPONSE_HEADERS" | grep -i -q "^$HEADER:"; then
 #       echo -e "⚠️ \e[33mAdicione $HEADER para melhorar a segurança:\e[0m"
#        echo "   $HEADER: ${SUGESTOES[$HEADER]}"
#    fi
#done

# Analisando Políticas de Cross-Origin

# Cross-Origin Embedder Policy (COEP)
if echo "$RESPONSE_HEADERS" | grep -qi "Cross-Origin-Embedder-Policy"; then
    echo -e "✅ \e[32mCross-Origin-Embedder-Policy está presente.\e[0m Protege contra ataques de injeção de recursos."
else
    echo -e "⚠️ \e[33mAdicione Cross-Origin-Embedder-Policy para reforçar segurança contra embeddings não confiáveis:\e[0m"
    echo "   Cross-Origin-Embedder-Policy: require-corp"
fi

# Cross-Origin Opener Policy (COOP)
if echo "$RESPONSE_HEADERS" | grep -qi "Cross-Origin-Opener-Policy"; then
    echo -e "✅ \e[32mCross-Origin-Opener-Policy está presente.\e[0m Protege contra ataques de cross-origin."
else
    echo -e "⚠️ \e[33mAdicione Cross-Origin-Opener-Policy para reforçar isolamento de contexto:\e[0m"
    echo "   Cross-Origin-Opener-Policy: same-origin"
fi

# Cross-Origin Resource Policy (CORP)
if echo "$RESPONSE_HEADERS" | grep -qi "Cross-Origin-Resource-Policy"; then
    echo -e "✅ \e[32mCross-Origin-Resource-Policy está presente.\e[0m Protege contra acesso indevido a recursos."
else
    echo -e "⚠️ \e[33mAdicione Cross-Origin-Resource-Policy para restringir quais sites podem carregar seus recursos:\e[0m"
    echo "   Cross-Origin-Resource-Policy: same-origin"
fi

# Cross-Origin Resource Sharing (CORS)
if echo "$RESPONSE_HEADERS" | grep -qi "Access-Control-Allow-Origin"; then
    echo -e "✅ \e[32mCORS (Access-Control-Allow-Origin) está presente.\e[0m Controla acesso de outras origens."
else
    echo -e "⚠️ \e[33mAdicione CORS para definir políticas de compartilhamento de recursos entre origens diferentes:\e[0m"
    echo "   Access-Control-Allow-Origin: https://exemplo.com"
fi

# Cross-Origin Read Blocking (CORB) (não é um header, mas pode ser mitigado)
echo -e "\n🔍 \e[34mCORB (Cross-Origin Read Blocking) é implementado automaticamente pelo Chrome para evitar leitura de conteúdo sensível de outras origens.\e[0m"
echo "   Para mitigação extra, use Content-Type apropriado para arquivos sensiveis."


# Adicionar referência a OWASP e SecurityHeaders
echo -e "\n📚 \e[34mReferências para mais informações:\e[0m"
echo "   🔗 https://owasp.org/www-project-secure-headers/"
echo "   🔗 https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers"
echo "   🔗 https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy"
echo "   🔗 https://securityheaders.com/"

echo -e "\n🔚 \e[34mAnálise concluída!\e[0m 🚀\n"
