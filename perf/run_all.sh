set -euo pipefail

mkdir -p results/day7/k6 results/day7/stats

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
    echo "!! контейнер для $name не знайдено, пропускаю"
    continue
  fi

  for endpoint in search greet; do
    echo "=== $name / $endpoint ==="
    for run in 1 2 3 4 5; do
      echo "-- прогін $run --"
      stats_file="results/day7/stats/${name}-${endpoint}-run${run}.csv"
      echo "timestamp,cpu_perc,mem_usage" > "$stats_file"

      # фонове знімання CPU/пам'яті кожні 2с, поки k6 виконується
      (
        while true; do
          ts=$(date +%s)
          line=$(docker stats "$container_id" --no-stream --format "{{.CPUPerc}},{{.MemUsage}}")
          echo "${ts},${line}" >> "$stats_file"
          sleep 2
        done
      ) &
      stats_pid=$!

      k6 run --env BASE_URL="$base_url" \
        --summary-export="results/day7/k6/${name}-${endpoint}-run${run}.json" \
        "perf/${endpoint}.js" || true

      kill "$stats_pid" 2>/dev/null || true
      wait "$stats_pid" 2>/dev/null || true
    done
  done
done

echo "Готово. Результати в results/day7/k6 і results/day7/stats"