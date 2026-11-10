#!/usr/bin/env bash
set -euo pipefail

# Запускає OWASP ZAP API Scan для всіх шести цілей за специфікацією
# openapi.yaml. Для кожної цілі підставляє правильний порт у "servers:"
# і зберігає HTML- та JSON-звіти в цю ж папку, з якої потім parse_zap.py
# будує зведений CSV (results/dast-zap/zap_summary.csv).
#
# Передумови:
#   - Docker запущений (образ zaproxy/zap-stable тягнеться автоматично
#     при першому запуску)
#   - усі 6 застосунків підняті: docker compose up -d (з кореня репозиторію)
#   - openapi.yaml лежить у цій самій папці
#
# Запуск (з кореня репозиторію): ./results/dast-zap/run_scan.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f "openapi.yaml" ]; then
  echo "Не знайдено openapi.yaml у $SCRIPT_DIR" >&2
  exit 1
fi

declare -A PORTS=(
  [flask-v]=5001   [flask-p]=5101
  [django-v]=5002  [django-p]=5102
  [fastapi-v]=5003 [fastapi-p]=5103
)

for name in "${!PORTS[@]}"; do
  port="${PORTS[$name]}"
  echo "=== Сканую $name (http://host.docker.internal:$port) ==="

  # Підставляємо порт цілі в тимчасову копію специфікації
  sed "s#http://host.docker.internal:[0-9]*#http://host.docker.internal:${port}#" \
    openapi.yaml > "openapi-${name}.yaml"

  docker run --rm -v "$SCRIPT_DIR:/zap/wrk:rw" \
    -t zaproxy/zap-stable zap-api-scan.py \
    -t "/zap/wrk/openapi-${name}.yaml" -f openapi \
    -r "${name}-report.html" -J "${name}-api.json" \
    -I

  rm -f "openapi-${name}.yaml"
done

echo ""
echo "Готово. Звіти (*-report.html, *-api.json) — у $SCRIPT_DIR"
echo "Наступний крок: python parse_zap.py"
