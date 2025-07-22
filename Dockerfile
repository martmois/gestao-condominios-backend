# Usar uma imagem oficial do Node.js
FROM node:18-slim

# Definir o diretório de trabalho dentro do container
WORKDIR /usr/src/app

# Copiar os arquivos de manifesto do projeto
COPY package*.json ./

# Instalar as dependências da aplicação
RUN npm install --omit=dev

# Copiar o resto do código-fonte da aplicação
COPY . .

# Expor a porta que o Cloud Run usará
EXPOSE 8080

# Comando para iniciar a aplicação
CMD [ "node", "index.js" ]