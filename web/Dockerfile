FROM node:24-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.29-alpine
ARG VERSION=dev
ARG REVISION=unknown
ARG SOURCE=https://github.com/ohmyrasp/oh-my-rasp
LABEL org.opencontainers.image.title="OhMyRasp Control Web" \
	org.opencontainers.image.description="Self-hosted OhMyRasp control plane web console" \
	org.opencontainers.image.version="${VERSION}" \
	org.opencontainers.image.revision="${REVISION}" \
	org.opencontainers.image.source="${SOURCE}"
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html
RUN chmod 644 /etc/nginx/conf.d/default.conf \
	&& find /usr/share/nginx/html -type d -exec chmod 755 {} \; \
	&& find /usr/share/nginx/html -type f -exec chmod 644 {} \;
EXPOSE 8080
