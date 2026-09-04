# ACT frontend — nginx serving the static dashboard + proxying /api to the backend.
#
#   docker build -t act-frontend frontend/
#   docker run --rm -p 8080:80 -e ACT_BACKEND_URL=http://host.docker.internal:8000 act-frontend
#
# Normally started via docker-compose.yml at the repo root.

FROM nginx:1.27-alpine

ENV ACT_BACKEND_URL=http://act-backend:8000

# nginx:alpine ships envsubst (gettext) and templating: files in
# /etc/nginx/templates/*.template are rendered to /etc/nginx/conf.d/ on start,
# substituting ${ACT_BACKEND_URL}.
COPY frontend/nginx.conf /etc/nginx/templates/default.conf.template
COPY frontend/index.html frontend/login.html /usr/share/nginx/html/

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1/healthz >/dev/null 2>&1 || exit 1

EXPOSE 80
