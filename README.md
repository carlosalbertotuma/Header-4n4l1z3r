# Header-4n4l1z3r

![image](https://github.com/user-attachments/assets/53a8f4bd-9b95-4965-a6f1-500261ec19cd)


Header-4n4l1z3r é uma ferramenta desenvolvida para verificar os cabeçalhos de segurança presentes em um site, destacando os cabeçalhos recomendados e oferecendo sugestões de melhorias para aumentar a segurança da aplicação. Esta ferramenta ajuda a detectar vulnerabilidades relacionadas à ausência de cabeçalhos essenciais de segurança e oferece orientações claras sobre como corrigi-los.

# 🚀 Visão Geral
Essa ferramenta analisa os cabeçalhos de resposta HTTP de um site, verifica a presença de cabeçalhos de segurança essenciais e sugere ações para melhorar a segurança do site. Ela foi desenvolvida com o intuito de ajudar profissionais de segurança, administradores de sistemas e desenvolvedores a implementarem boas práticas de segurança em seus servidores web.

# 🛠️ Funcionalidade
- [ ] Análise dos Cabeçalhos de Segurança:
A ferramenta verifica se os cabeçalhos de segurança recomendados estão presentes na resposta HTTP de um site.

# Sugestões de Melhoria:
Caso algum cabeçalho de segurança esteja ausente, a ferramenta oferece sugestões de como adicioná-lo e quais os benefícios disso.

# Verificação de Políticas de Cross-Origin:
A ferramenta também analisa as políticas de segurança relacionadas ao Cross-Origin (COEP, COOP, CORS) para proteger contra ataques de injeção de recursos e vazamento de dados.

# Sugestões de Headers Faltantes:
Fornece recomendações de como configurar cabeçalhos faltantes, como o X-Frame-Options, Referrer-Policy, Permissions-Policy e outros, para melhorar a segurança da aplicação.

Exibição de Detalhes:
Exibe de forma clara os cabeçalhos encontrados, cabeçalhos ausentes e sugestões de políticas de segurança para os desenvolvedores implementarem.

#📋 Como Usar

- Pré-requisitos

Certifique-se de que você tenha o curl instalado no seu sistema para fazer as requisições HTTP.
A ferramenta foi projetada para rodar em sistemas Unix-like (Linux/macOS).

- Uso Básico
Execute o script passando a URL do site que você deseja analisar.

./head_analyzer.sh <URL>

Caso não forneça uma URL, a ferramenta mostrará uma mensagem de erro com a sintaxe correta.

# ⚙️ Detalhes da Ferramenta

- A ferramenta irá realizar as seguintes ações:

- [ ] Exibir a lista de cabeçalhos presentes na resposta HTTP.
- [ ] Detectar cabeçalhos de segurança ausentes e sugerir melhorias.
- [ ] Mostrar as políticas de segurança recomendadas e como implementá-las.
- [ ] Exibir informações sobre os riscos relacionados à ausência de determinados cabeçalhos.
- [ ] Fornecer links úteis para mais informações sobre segurança de cabeçalhos e políticas de segurança.


# Screenshot

![image](https://github.com/user-attachments/assets/5a0d2167-0bcc-433a-a577-5682994aeb29)

![image](https://github.com/user-attachments/assets/d927b5cb-9bde-46fa-a751-1f60ff0fd6bc)


# 🚨 Exemplo de Saída

![image](https://github.com/user-attachments/assets/ac709234-296d-4a0f-a1a5-691fabf847fe)


# 📝 Notas Importantes
A ferramenta é um protótipo na versão 0.1.
Está em constante atualização para adicionar mais recursos e verificações.
Fique atento às mensagens de erro para uma utilização mais eficiente.


# 📚 Referências
- [ ] 🔗 https://owasp.org/www-project-secure-headers/"
- [ ] 🔗 https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers"
- [ ] 🔗 https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy"
- [ ] 🔗 https://securityheaders.com/"


# 📝 Licença

Esse projeto está sob é de livre uso e modificação, favor manter os créditos em comentário.
 
Ps. não utilize para crimes ciberneticos, não tenho responsábilidade do mau uso da ferramenta.

# Desenvolvido

Desenvolvido por Carlos Tuma - Bl4dsc4n
