# Dockerfile
FROM node:22-alpine

# Diretório de trabalho dentro do container
WORKDIR /usr/src/app

# Copia apenas package.json e package-lock.json para acelerar o cache
COPY package*.json ./

# Instala só dependências de produção
RUN npm ci --omit=dev

# Copia o restante do código
COPY . .

# Expõe a porta que o Express vai usar
ENV PORT=8080

# Comando padrão para iniciar
CMD ["node", "index.js"]
