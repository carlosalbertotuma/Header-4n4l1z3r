#!/bin/bash
URL="${1}"

# Função para exibir o banner
banner()
{
    echo '                      _             _  _         _  _   _ _     _____      '
    echo '  /\  /\___  __ _  __| | ___ _ __  | || |  _ __ | || | | / |___|___ / _ __ '
    echo ' / /_/ / _ \/ _` |/ _` |/ _ \  __| | || |_|  _ \| || |_| | |_  / |_ \|  __|'
    echo '/ __  /  __/ (_| | (_| |  __/ |    |__   _| | | |__   _| | |/ / ___) | |   '
    echo '\/ /_/ \___|\__,_|\__,_|\___|_|       |_| |_| |_|  |_| |_|_/___|____/|_|   '
    echo '                                                                           '    
    echo "Desenvolvido por Carlos Tuma - Bl4dsc4n - Version 1.0"
    echo
    
}

# Função para exibir o modo de uso
modouso() {
    echo -e "\e[31m[ERRO] Uso: $0 <URL>\e[0m"
}

# Função para exibir mensagens coloridas
color_output() {
  case $1 in
    "INFO") echo -e "\e[34m[INFO]\e[0m $2" ;;   # Azul
    "WARNING") echo -e "\e[33m[WARNING]\e[0m $2" ;;  # Amarelo
    "ALERT") echo -e "\e[31m[ALERT]\e[0m $2" ;;  # Vermelho
    *) echo "$2" ;;
  esac
}

# Verifica se a URL foi passada como argumento
if [ -z "${1}" ]; then
    banner
    modouso
    exit 1
elif [[ ! "${1}" =~ ^http:// && ! "${1}" =~ ^https:// ]]; then
  color_output "ALERT" "URL inválida: $URL"
  exit 1

fi



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
    "Cross-Origin-Embedder-Policy"
    "Cross-Origin-Opener-Policy"
    "Cross-Origin-Resource-Policy"
    "Access-Control-Allow-Origin"
)

# Descrição e políticas recomendadas para cada header
declare -A HEADER_DESCRICAO
HEADER_DESCRICAO=(
    ["Content-Security-Policy"]="Define as fontes permitidas para conteúdo como scripts e imagens, prevenindo injeções de código malicioso."
    ["X-Frame-Options"]="Impedir que o conteúdo seja exibido dentro de frames ou iframes, mitigando ataques de clickjacking."
    ["X-XSS-Protection"]="Ativa proteção contra ataques de cross-site scripting (XSS), bloqueando a execução de scripts maliciosos."
    ["X-Content-Type-Options"]="Evita que o navegador tente adivinhar o tipo de conteúdo, ajudando a prevenir ataques de MIME sniffing."
    ["Strict-Transport-Security"]="Força a comunicação segura via HTTPS, prevenindo ataques man-in-the-middle e garantindo a integridade dos dados."
    ["Referrer-Policy"]="Controla as informações do referenciador enviadas nas requisições HTTP, protegendo a privacidade do usuário."
    ["Permissions-Policy"]="Controla o acesso a recursos específicos do navegador, como geolocalização ou câmera, aumentando a privacidade do usuário."
    ["Expect-CT"]="Força a verificação de certificados de segurança em relação ao site, prevenindo o uso de certificados inválidos."
    ["Cross-Origin-Embedder-Policy"]="Reforça a segurança contra embeddings não confiáveis, controlando o carregamento de recursos de diferentes origens."
    ["Cross-Origin-Opener-Policy"]="Reforça o isolamento de contexto entre origens, garantindo que scripts não possam acessar dados de outras origens."
    ["Cross-Origin-Resource-Policy"]="Restringe quais sites podem carregar seus recursos, evitando o carregamento indesejado por sites não confiáveis."
    ["Access-Control-Allow-Origin"]="Define políticas de compartilhamento de recursos entre origens diferentes, controlando quais sites podem acessar os recursos da sua aplicação."
)

declare -A POLITICAS_RECOMENDADAS
POLITICAS_RECOMENDADAS=(
    ["Content-Security-Policy"]="default-src 'self';"
    ["X-Frame-Options"]="DENY"
    ["X-XSS-Protection"]="1; mode=block"
    ["X-Content-Type-Options"]="nosniff"
    ["Strict-Transport-Security"]="max-age=31536000; includeSubDomains"
    ["Referrer-Policy"]="no-referrer"
    ["Permissions-Policy"]="geolocation=(), microphone=(), camera=()"
    ["Expect-CT"]="max-age=86400, enforce"
    ["Cross-Origin-Embedder-Policy"]="require-corp"
    ["Cross-Origin-Opener-Policy"]="same-origin"
    ["Cross-Origin-Resource-Policy"]="same-origin"
    ["Access-Control-Allow-Origin"]="https://exemplo.com"
)

# Função para seguir redirecionamentos e capturar headers
seguir_redirecionamento() {
    local url="$1"
    local depth="$2"
    local response=$(curl -s -I --http2 --max-time 10 -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3" "$url")
    local status_code=$(echo "$response" | grep -i "HTTP/" | awk '{print $2}')
    local location=$(echo "$response" | grep -i "Location:" | awk '{print $2}' | tr -d '\r')
    
   
    echo -e "\n🔎 \e[34mAnalisando headers de resposta para (Redirecionamento $depth):\e[0m $url\n"
    echo -e "📜 \e[34mHeaders encontrados:\e[0m\n$response"

    # Verificar headers presentes e suas configurações
    echo -e "\n✅ \e[32mHeaders presentes:\e[0m\n"
    for HEADER in "${HEADERS_RECOMENDADOS[@]}"; do
        if echo "$response" | grep -i -q "^$HEADER:"; then
            HEADER_VALUE=$(echo "$response" | grep -i "^$HEADER:" | cut -d' ' -f2-)
            
            if [[ "$HEADER" == "X-XSS-Protection" || "$HEADER" == "X-Content-Type-Options" ]]; then
                # Normalizar o valor e o valor recomendado
                normalized_value=$(echo "$HEADER_VALUE" | tr '[:upper:]' '[:lower:]' | sed 's/ //g')
                normalized_recommended_value=$(echo "${POLITICAS_RECOMENDADAS[$HEADER]}" | tr '[:upper:]' '[:lower:]' | sed 's/ //g')

                if [[ "$normalized_value" == "$normalized_recommended_value" ]]; then
                    echo -e "✅ \e[32m$HEADER:\e[0m ${HEADER_DESCRICAO[$HEADER]}"
                    echo -e "   \e[32mConfiguração atual: Ótima!\e[0m $HEADER: $HEADER_VALUE"
                else
                    echo -e "✅ \e[32m$HEADER:\e[0m ${HEADER_DESCRICAO[$HEADER]}"
                    echo -e "   \e[34mConfiguração atual:\e[0m $HEADER: $HEADER_VALUE"
                    echo -e "   \e[33mSugestão de melhoria:\e[0m $HEADER: ${POLITICAS_RECOMENDADAS[$HEADER]}"
                fi
            else
                echo -e "✅ \e[32m$HEADER:\e[0m ${HEADER_DESCRICAO[$HEADER]}"
                echo -e "   \e[34mConfiguração atual:\e[0m $HEADER: $HEADER_VALUE"
                if [ "$HEADER_VALUE" != "${POLITICAS_RECOMENDADAS[$HEADER]}" ]; then
                    echo -e "   \e[33mSugestão de melhoria:\e[0m $HEADER: ${POLITICAS_RECOMENDADAS[$HEADER]}"
                fi
            fi
        fi
    done

    # Verificar headers ausentes
    echo -e "\n⚠️ \e[32m**Vulnerabilidade detectada**: (CWE: 693) CVSS3 Score: 3.1 LOW\e[0m"
    echo -e "\n🚨 \e[31mHeaders de segurança ausentes:\e[0m\n"
    MISSING_HEADERS=0
    for HEADER in "${HEADERS_RECOMENDADOS[@]}"; do
        if ! echo "$response" | grep -i -q "^$HEADER:"; then
            echo -e "❌ \e[31m$HEADER (Faltando)\e[0m"
            echo -e "   \e[34mDescrição:\e[0m ${HEADER_DESCRICAO[$HEADER]}"
            echo -e "   \e[33mSugestão de melhoria:\e[0m $HEADER: ${POLITICAS_RECOMENDADAS[$HEADER]}"
            ((MISSING_HEADERS++))
        fi
    done

    if [ "$MISSING_HEADERS" -eq 0 ]; then
        echo -e "✅ \e[32mTodos os headers de segurança essenciais estão presentes!\e[0m"
    fi

    if [[ "$status_code" == "301" || "$status_code" == "302" ]]; then
        echo -e "\e[33m[INFO] Redirecionando para $location\e[0m"
        # Fazer nova requisição para o local redirecionado
        if [[ "$location" != http* ]]; then
            # Se o location não for uma URL completa, adicionar o domínio original
            local base_url=$(echo "$url" | grep -oP 'https?://[^/]+')
            location="$base_url$location"
        fi
        seguir_redirecionamento "$location" $((depth + 1))
    fi
   
}

# Iniciar análise com a URL fornecida
seguir_redirecionamento "$URL" 1

echo -e "\n"
color_output "INFO" "Verificando misconfiguration"
echo -e "\n"
# Obtém os headers da resposta
HEADERS=$(curl -s -I "$URL" | tr -d '\r')  

# Função para verificar e alertar sobre headers específicos
check_header() {
  HEADER_NAME=$1
  RECOMMENDATION=$2
  HEADER_VALUE=$(echo "$HEADERS" | grep -iE "^$HEADER_NAME:" | cut -d ':' -f2- | sed 's/^ *//g')

  if [[ -n "$HEADER_VALUE" ]]; then
    color_output "WARNING" "Possível misconfiguration encontrada: $HEADER_NAME"
    echo -e "  \e[32mValor:\e[0m $HEADER_VALUE"
    echo -e "  \e[36mRecomendações:\e[0m $RECOMMENDATION"
    echo "----------------------------------------"
  fi
}

# Lista de headers a verificar
check_header "Server" "Evite expor informações sobre o servidor."
check_header "X-Powered-By" "Evite expor a tecnologia usada."
check_header "X-AspNet-Version" "Evite expor a versão do ASP.NET."
check_header "X-AspNetMvc-Version" "Evite expor a versão do ASP.NET MVC."
check_header "X-Powered-By-Plesk" "Evite expor o uso do painel de controle Plesk."
check_header "X-Drupal-Cache" "Evite expor informações sobre a configuração do cache do Drupal."
check_header "X-Generator" "Evite expor a ferramenta ou framework usado para gerar a página."

# Headers que podem conter informações sensíveis
check_header "Authorization" "Evite expor tokens de acesso ou chaves API."
check_header "Set-Cookie" "Certifique-se de usar flags de segurança como HttpOnly, Secure e SameSite."
check_header "Proxy-Authorization" "Evite expor tokens ou chaves para autenticação com um servidor proxy."
check_header "X-Api-Key" "Evite expor chaves de API."
check_header "X-Amz-Security-Token" "Evite expor tokens de segurança temporários da AWS."
check_header "X-Auth-Token" "Evite expor tokens de autenticação."

color_output "INFO" "Verificação concluída."
