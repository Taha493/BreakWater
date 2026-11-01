# The dashboard: built with Node, served as static files by nginx running as a non-root
# user. The gateway URL is baked in at build time (VITE_GATEWAY_URL) and the server's CSP
# only lets the page call that origin (GATEWAY_ORIGIN at run time).
FROM node:24.22.2-alpine@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85 AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
ARG VITE_GATEWAY_URL=http://localhost:8000
ENV VITE_GATEWAY_URL=${VITE_GATEWAY_URL}
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.30.6-alpine@sha256:f5116ed4606f3eb015dd4a8e28cb9b351476dc0ad4bc6e9f93b19cec130cdf03
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /app/dist /usr/share/nginx/html
ENV GATEWAY_ORIGIN=http://localhost:8000
EXPOSE 8080
