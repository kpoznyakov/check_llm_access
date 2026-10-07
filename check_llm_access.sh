#!/usr/bin/env bash
#
# check_llm_access.sh — проверка доступности API LLM-провайдеров с текущего сервера.
#
# Запросы идут БЕЗ API-ключей. Если сервер ответил 401/403 "нужен ключ" — значит,
# сеть и регион в порядке. Гео-блокировки определяются по коду/тексту ответа
# (например, Gemini: "User location is not supported", OpenAI:
# "unsupported_country_region_territory", Anthropic: 403 "Request not allowed").
#
# Использование:
#   ./check_llm_access.sh [-t TIMEOUT] [-j JOBS] [-p PROXY] [-v] [-n] [-h]
#
#   -t SEC    таймаут на один запрос (по умолчанию 10)
#   -j N      число параллельных проверок (по умолчанию 8)
#   -p URL    прокси (http://host:port или socks5h://host:port)
#   -v        показывать фрагмент тела ответа
#   -n        не определять внешний IP/страну (не обращаться к ipinfo.io)
#   -h        помощь
#
# Коды возврата: 0 — всё доступно, 1 — есть недоступные/заблокированные, 2 — ошибка запуска.

set -u

TIMEOUT=10
JOBS=8
PROXY=""
VERBOSE=0
SHOW_IP=1

while getopts "t:j:p:vnh" opt; do
  case "$opt" in
    t) TIMEOUT="$OPTARG" ;;
    j) JOBS="$OPTARG" ;;
    p) PROXY="$OPTARG" ;;
    v) VERBOSE=1 ;;
    n) SHOW_IP=0 ;;
    h) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) exit 2 ;;
  esac
done

command -v curl >/dev/null 2>&1 || { echo "Ошибка: нужен curl" >&2; exit 2; }

# Цвета только если вывод в терминал
if [ -t 1 ]; then
  G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; B=$'\033[1m'; N=$'\033[0m'
else
  G=""; R=""; Y=""; B=""; N=""
fi

# Формат: Название|URL
# URL выбраны так, чтобы без ключа вернуть 401/403/404, а не требовать тело запроса.
ENDPOINTS=(
  "OpenAI|https://api.openai.com/v1/models"
  "Anthropic (Claude)|https://api.anthropic.com/v1/models"
  "Google Gemini (AI Studio)|https://generativelanguage.googleapis.com/v1beta/models"
  "Google Vertex AI|https://aiplatform.googleapis.com/"
  "AWS Bedrock (us-east-1)|https://bedrock-runtime.us-east-1.amazonaws.com/"
  "Mistral|https://api.mistral.ai/v1/models"
  "Cohere|https://api.cohere.com/v1/models"
  "xAI (Grok)|https://api.x.ai/v1/models"
  "DeepSeek|https://api.deepseek.com/models"
  "Groq|https://api.groq.com/openai/v1/models"
  "Together AI|https://api.together.xyz/v1/models"
  "Fireworks AI|https://api.fireworks.ai/inference/v1/models"
  "OpenRouter|https://openrouter.ai/api/v1/models"
  "Perplexity|https://api.perplexity.ai/"
  "Cerebras|https://api.cerebras.ai/v1/models"
  "SambaNova|https://api.sambanova.ai/v1/models"
  "NVIDIA NIM|https://integrate.api.nvidia.com/v1/models"
  "Hugging Face Router|https://router.huggingface.co/v1/models"
  "Replicate|https://api.replicate.com/v1/models"
  "AI21|https://api.ai21.com/studio/v1/models"
  "Moonshot (Kimi)|https://api.moonshot.ai/v1/models"
  "Alibaba Qwen (DashScope intl)|https://dashscope-intl.aliyuncs.com/compatible-mode/v1/models"
  "Zhipu (GLM)|https://open.bigmodel.cn/api/paas/v4/models"
  "MiniMax|https://api.minimax.io/v1/models"
  "Yandex Foundation Models|https://llm.api.cloud.yandex.net/"
)

# Паттерны гео/региональной блокировки в теле ответа
GEO_RE='location is not supported|unsupported_country|country, region, or territory|not available in your (country|region)|not supported in your (country|region)|region is not supported|access denied.*(country|region)|blocked.*(country|region)'
# Паттерны "нужна авторизация" — т.е. сервер нас пустил
AUTH_RE='api[ _-]?key|unauthori[sz]ed|authenticat|authorization|credentials|unregistered callers|missing.*(token|key)|invalid.*(token|key)|permission_denied|x-api-key|bearer'

check_one() {
  local name="$1" url="$2"
  local body_file; body_file="$(mktemp)"
  local args=(-sS -o "$body_file" -m "$TIMEOUT" --connect-timeout "$TIMEOUT"
              -A "llm-access-check/1.0"
              -w '%{http_code}|%{time_connect}|%{time_appconnect}|%{time_total}')
  [ -n "$PROXY" ] && args+=(-x "$PROXY")

  local out rc err_file; err_file="$(mktemp)"
  out="$(curl "${args[@]}" "$url" 2>"$err_file")"
  rc=$?
  local err; err="$(tr '\n' ' ' <"$err_file")"

  local code time_total status detail
  code="${out%%|*}"
  time_total="${out##*|}"
  local body; body="$(head -c 600 "$body_file" | tr '\n\r' '  ')"
  rm -f "$body_file" "$err_file"

  if [ $rc -ne 0 ]; then
    case $rc in
      6)  status="FAIL";  detail="DNS не резолвится (curl 6)" ;;
      7)  status="FAIL";  detail="Не удалось подключиться (curl 7): порт закрыт/блокировка" ;;
      28) status="FAIL";  detail="Таймаут (curl 28): вероятно, фильтрация пакетов" ;;
      35|51|58|60|77) status="FAIL"; detail="Ошибка TLS (curl $rc): возможен MITM/DPI" ;;
      56) status="FAIL";  detail="Соединение сброшено (curl 56): вероятно, DPI/блокировка" ;;
      *)  status="FAIL";  detail="curl error $rc: ${err:0:120}" ;;
    esac
    code="---"
  else
    local lower; lower="$(printf '%s' "$body" | tr '[:upper:]' '[:lower:]')"
    case "$code" in
      451)
        status="GEO"; detail="HTTP 451 — недоступно по юридическим причинам" ;;
      000)
        status="FAIL"; detail="Нет HTTP-ответа" ;;
      2*|3*)
        status="OK"; detail="Доступно" ;;
      401|404|405|400|415|422|429)
        if printf '%s' "$lower" | grep -Eq "$GEO_RE"; then
          status="GEO"; detail="Гео-блокировка (HTTP $code)"
        else
          status="OK"; detail="Доступно (HTTP $code — ответ без ключа ожидаем)"
        fi ;;
      403)
        if printf '%s' "$lower" | grep -Eq "$GEO_RE"; then
          status="GEO"; detail="Гео-блокировка (HTTP 403)"
        elif printf '%s' "$lower" | grep -Eq "$AUTH_RE"; then
          status="OK"; detail="Доступно (HTTP 403 — требуется ключ)"
        else
          status="BLOCK"; detail="HTTP 403 без признаков авторизации — похоже на блокировку по IP/региону"
        fi ;;
      5*)
        status="WARN"; detail="Сервер ответил HTTP $code (проблема на стороне провайдера?)" ;;
      *)
        status="WARN"; detail="Неожиданный HTTP $code" ;;
    esac
  fi

  # Одна строка результата: STATUS|name|code|time|detail|body
  printf '%s|%s|%s|%.2fs|%s|%s\n' "$status" "$name" "$code" "${time_total:-0}" "$detail" "$body"
}

# --- Информация о сервере ---
echo "${B}Проверка доступа к LLM API${N}  ($(date '+%Y-%m-%d %H:%M:%S %Z'))"
if [ $SHOW_IP -eq 1 ]; then
  ipargs=(-sS -m 5)
  [ -n "$PROXY" ] && ipargs+=(-x "$PROXY")
  info="$(curl "${ipargs[@]}" https://ipinfo.io/json 2>/dev/null | tr -d '\n')"
  if [ -n "$info" ]; then
    ip="$(printf '%s' "$info" | sed -n 's/.*"ip": *"\([^"]*\)".*/\1/p')"
    country="$(printf '%s' "$info" | sed -n 's/.*"country": *"\([^"]*\)".*/\1/p')"
    org="$(printf '%s' "$info" | sed -n 's/.*"org": *"\([^"]*\)".*/\1/p')"
    echo "Внешний IP: ${ip:-?}  страна: ${country:-?}  провайдер: ${org:-?}"
  else
    echo "Внешний IP: не удалось определить"
  fi
fi
[ -n "$PROXY" ] && echo "Прокси: $PROXY"
echo

# --- Параллельный запуск ---
TMPDIR_RES="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_RES"' EXIT

i=0
running=0
for entry in "${ENDPOINTS[@]}"; do
  name="${entry%%|*}"
  url="${entry#*|}"
  i=$((i+1))
  ( check_one "$name" "$url" > "$TMPDIR_RES/$(printf '%03d' "$i")" ) &
  running=$((running+1))
  if [ "$running" -ge "$JOBS" ]; then
    wait -n 2>/dev/null || wait
    running=$((running-1))
  fi
done
wait

# --- Вывод ---
ok=0; bad=0; warn=0
printf '%-32s %-7s %-5s %-8s %s\n' "ПРОВАЙДЕР" "СТАТУС" "HTTP" "ВРЕМЯ" "ДЕТАЛИ"
printf '%s\n' "------------------------------------------------------------------------------------------"
for f in "$TMPDIR_RES"/*; do
  IFS='|' read -r status name code t detail body < "$f"
  case "$status" in
    OK)    color="$G"; ok=$((ok+1)) ;;
    WARN)  color="$Y"; warn=$((warn+1)) ;;
    *)     color="$R"; bad=$((bad+1)) ;;
  esac
  printf '%-32s %s%-7s%s %-5s %-8s %s\n' "$name" "$color" "$status" "$N" "$code" "$t" "$detail"
  if [ $VERBOSE -eq 1 ] && [ -n "${body:-}" ]; then
    printf '    ↳ %s\n' "${body:0:200}"
  fi
done

echo
echo "${B}Итого:${N} ${G}доступно: $ok${N}, ${Y}предупреждения: $warn${N}, ${R}недоступно/заблокировано: $bad${N}"
echo "Статусы: OK — доступно; GEO — гео-блокировка; BLOCK — похоже на блокировку; FAIL — сетевая ошибка; WARN — нестандартный ответ."

[ "$bad" -eq 0 ] && exit 0 || exit 1
