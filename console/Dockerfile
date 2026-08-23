# syntax=docker/dockerfile:1
FROM node:26.7.0-alpine AS build
WORKDIR /src
COPY package.json package-lock.json* ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginx:1.31.4-alpine
LABEL org.opencontainers.image.title="OhMyRasp Sentinel Console" \
      org.opencontainers.image.description="Application-centric RASP control console"
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html
RUN find /usr/share/nginx/html -type d -exec chmod 755 {} \; \
    && find /usr/share/nginx/html -type f -exec chmod 644 {} \;
EXPOSE 8080
