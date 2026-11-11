#!/usr/bin/env bash
set -euo pipefail

# Навантажувальне тестування: 12 комбінацій (6 цілей × 2 ендпоінти),
# по 10 прогонів кожна (перший — прогрів, відкидається при аналізі).
# Паралельно зі старту k6 знімає CPU/пам'ять контейнера кожні 2с.
#
# Орієнтовний час: ~70-90 хвилин на повний прогін.
# Запуск (з кореня репозиторію): ./perf/run_all.sh

REPS=10

mkdir -p results/load-testing/k6 results/load-testing/stats

declare -A PORTS=(
  [flask-v]=5001 [flask-p]=5101
  [django-v]=5002 [django-p]=5102
  [fastapi-v]=5003 [fastapi-p]=5103
)

for name in "${!PORTS[@]}"; do
  port="${PORTS[$name]}"
  base_url="http://localhost:${port}"
  container_id=$(docker compose ps -q "$name")

  if [ -z "$container_id" ]; then
    echo "!! контейнер для $name не знайдено, пропускаю" >&2
    continue
  fi

  for endpoint in search greet; do
    echo "=== $name / $endpoint ==="
    for run in $(seq 1 "$REPS"); do
      echo "-- прогін $run/$REPS --"
      stats_file="results/load-testing/stats/${name}-${endpoint}-run${run}.csv"
      echo "timestamp,cpu_perc,mem_usage" > "$stats_file"

      # Фонове знімання CPU/пам'яті, поки виконується k6.
      # & запускає підпроцес у фоні; його PID зберігаємо, щоб коректно
      # зупинити одразу після завершення k6, а не покладатися на час.
      (
        while true; do
          ts=$(date +%s)
          stat_line=$(docker stats "$container_id" --no-stream --format "{{.CPUPerc}},{{.MemUsage}}" 2>/dev/null)
          if [ -n "$stat_line" ]; then
            echo "${ts},${stat_line}" >> "$stats_file"
          fi
          sleep 2
        done
      ) &
      stats_pid=$!

      k6 run --env BASE_URL="$base_url" \
        --summary-export="results/load-testing/k6/${name}-${endpoint}-run${run}.json" \
        "perf/${endpoint}.js" || true

      kill "$stats_pid" 2>/dev/null || true
      wait "$stats_pid" 2>/dev/null || true

      # Перевірка одразу: якщо stats-файл лишився лише з заголовком,
      # попереджаємо негайно, а не постфактум при аналізі.
      lines=$(wc -l < "$stats_file")
      if [ "$lines" -le 1 ]; then
        echo "  !! УВАГА: $stats_file не містить точок CPU/пам'яті (docker stats не спрацював)" >&2
      fi
    done
  done
done

echo ""
echo "Готово. Результати в results/load-testing/k6 і results/load-testing/stats"
echo "Наступний крок: python perf/parse_performance.py"
