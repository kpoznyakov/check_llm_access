#!/usr/bin/env bash
#
# check_llm_access.sh — проверка доступности API LLM-провайдеров с текущего сервера.
#
# Без ключей: если сервер ответил 401/403 "нужен ключ" — сеть в порядке. Но часть
# провайдеров (например, Gemini) проверяет страну только ПОСЛЕ ключа, поэтому
# без ключа такую блокировку не видно. Для них страна сервера сверяется со
# списком UNSUPPORTED (статус GEO?), а если задан ключ в переменной окружения
# (OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY и др.) — делается настоящий
# минимальный запрос, и его результат окончательный.
#
# Использование:
#   ./check_llm_access.sh [-t TIMEOUT] [-j JOBS] [-p PROXY] [-c CC] [-v] [-n] [-h]
#
#   -t SEC    таймаут на один запрос (по умолчанию 10)
#   -j N      число параллельных проверок (по умолчанию 8)
#   -p URL    прокси (http://host:port или socks5h://host:port)
#   -c CC     код страны для сверки со списком (по умолчанию — из ipinfo.io)
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
COUNTRY=""

while getopts "t:j:p:c:vnh" opt; do
  case "$opt" in
    t) TIMEOUT="$OPTARG" ;;
    j) JOBS="$OPTARG" ;;
    p) PROXY="$OPTARG" ;;
    c) COUNTRY="$(printf '%s' "$OPTARG" | tr '[:lower:]' '[:upper:]')" ;;
    v) VERBOSE=1 ;;
    n) SHOW_IP=0 ;;
    h) sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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

# Формат: Название|URL|id
# URL выбраны так, чтобы без ключа вернуть 401/403/404, а не требовать тело запроса.
# id (необязателен) связывает строку с проверкой по ключу (key_probe) и списком UNSUPPORTED.
ENDPOINTS=(
  "OpenAI|https://api.openai.com/v1/models|openai"
  "Anthropic (Claude)|https://api.anthropic.com/v1/models|anthropic"
  "Google Gemini (AI Studio)|https://generativelanguage.googleapis.com/v1beta/models|gemini"
  "Google Vertex AI|https://aiplatform.googleapis.com/"
  "AWS Bedrock (us-east-1)|https://bedrock-runtime.us-east-1.amazonaws.com/"
  "Mistral|https://api.mistral.ai/v1/models|mistral"
  "Cohere|https://api.cohere.com/v1/models|cohere"
  "xAI (Grok)|https://api.x.ai/v1/models|xai"
  "DeepSeek|https://api.deepseek.com/models|deepseek"
  "Groq|https://api.groq.com/openai/v1/models|groq"
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

# Страны (ISO 3166-1 alpha-2), из которых провайдер не обслуживает API.
# Используется, только когда ключа нет: сервер ответил, но страна в списке → GEO?.
# Списки неполные — сверяйте с официальными страницами поддерживаемых регионов.
UNSUPPORTED=(
  "openai|RU BY CN HK MO IR KP SY CU"
  "anthropic|RU BY CN HK MO IR KP SY CU"
  "gemini|RU BY CN HK MO IR KP SY CU"
)

# Модель для проверки Gemini по ключу (нужен настоящий generateContent: /models гео не проверяет)
GEMINI_MODEL="${GEMINI_MODEL:-gemini-flash-latest}"

# Паттерны гео/региональной блокировки в теле ответа
GEO_RE='location is not supported|unsupported_country|country, region, or territory|not available in your (country|region)|not supported in your (country|region)|region is not supported|access denied.*(country|region)|blocked.*(country|region)'
# Паттерны "нужна авторизация" — т.е. сервер нас пустил
AUTH_RE='api[ _-]?key|unauthori[sz]ed|authenticat|authorization|credentials|unregistered callers|missing.*(token|key)|invalid.*(token|key)|permission_denied|x-api-key|bearer'

# Готовит запрос с ключом для провайдера $1. Задаёт P_KEYVAR (имя переменной с ключом)
# всегда, а P_URL, P_CFG (заголовки в формате curl -K) и P_BODY — только если ключ задан.
# Возвращает 1, если для провайдера нет проверки по ключу или ключ не задан.
key_probe() {
  local id="$1" key
  P_KEYVAR=""; P_URL=""; P_CFG=""; P_BODY=""
  case "$id" in
    openai)    P_KEYVAR=OPENAI_API_KEY;    P_URL="https://api.openai.com/v1/models" ;;
    anthropic) P_KEYVAR=ANTHROPIC_API_KEY; P_URL="https://api.anthropic.com/v1/models" ;;
    gemini)    P_KEYVAR=GEMINI_API_KEY
               P_URL="https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent"
               P_BODY='{"contents":[{"parts":[{"text":"hi"}]}],"generationConfig":{"maxOutputTokens":1}}' ;;
    mistral)   P_KEYVAR=MISTRAL_API_KEY;   P_URL="https://api.mistral.ai/v1/models" ;;
    cohere)    P_KEYVAR=COHERE_API_KEY;    P_URL="https://api.cohere.com/v1/models" ;;
    xai)       P_KEYVAR=XAI_API_KEY;       P_URL="https://api.x.ai/v1/models" ;;
    deepseek)  P_KEYVAR=DEEPSEEK_API_KEY;  P_URL="https://api.deepseek.com/models" ;;
    groq)      P_KEYVAR=GROQ_API_KEY;      P_URL="https://api.groq.com/openai/v1/models" ;;
    *) return 1 ;;
  esac
  key="${!P_KEYVAR:-}"
  if [ "$id" = gemini ] && [ -z "$key" ]; then key="${GOOGLE_API_KEY:-}"; fi
  [ -z "$key" ] && return 1
  # Ключ передаётся через конфиг на stdin, чтобы не светиться в списке процессов
  case "$id" in
    anthropic) P_CFG="header = \"x-api-key: $key\""$'\n'"header = \"anthropic-version: 2023-06-01\"" ;;
    gemini)    P_CFG="header = \"x-goog-api-key: $key\""$'\n'"header = \"Content-Type: application/json\"" ;;
    *)         P_CFG="header = \"Authorization: Bearer $key\"" ;;
  esac
  return 0
}

# 0, если страна $2 есть в списке UNSUPPORTED для провайдера $1
in_unsupported() {
  local id="$1" cc="$2" entry
  [ -z "$id" ] || [ -z "$cc" ] && return 1
  for entry in "${UNSUPPORTED[@]}"; do
    [ "${entry%%|*}" = "$id" ] || continue
    case " ${entry#*|} " in *" $cc "*) return 0 ;; esac
  done
  return 1
}

check_one() {
  local name="$1" url="$2" id="$3"
  local with_key=0
  key_probe "$id" && { with_key=1; url="$P_URL"; }

  local body_file; body_file="$(mktemp)"
  local args=(-sS -o "$body_file" -m "$TIMEOUT" --connect-timeout "$TIMEOUT"
              -A "llm-access-check/1.0"
              -w '%{http_code}|%{time_connect}|%{time_appconnect}|%{time_total}')
  [ -n "$PROXY" ] && args+=(-x "$PROXY")
  [ -n "$P_BODY" ] && args+=(--data-binary "$P_BODY")

  local out rc err_file; err_file="$(mktemp)"
  if [ $with_key -eq 1 ]; then
    out="$(printf '%s\n' "$P_CFG" | curl -K - "${args[@]}" "$url" 2>"$err_file")"
  else
    out="$(curl "${args[@]}" "$url" 2>"$err_file")"
  fi
  rc=$?
  local err; err="$(tr '\n' ' ' <"$err_file")"

  local code time_total status detail
  code="${out%%|*}"
  time_total="${out##*|}"
  local body; body="$(head -c 600 "$body_file" | tr '\n\r' '  ')"
  rm -f "$body_file" "$err_file"
  local lower; lower="$(printf '%s' "$body" | tr '[:upper:]' '[:lower:]')"
  is_geo()  { printf '%s' "$lower" | grep -Eq "$GEO_RE"; }
  is_auth() { printf '%s' "$lower" | grep -Eq "$AUTH_RE"; }

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
  elif [ $with_key -eq 1 ]; then
    # Настоящий запрос с ключом: ответ провайдера окончательный
    if [ "$code" = 451 ] || is_geo; then
      status="GEO"; detail="Гео-блокировка (HTTP $code, проверено с ключом)"
    else
      case "$code" in
        2*)  status="OK"; detail="Доступно (проверено с ключом)" ;;
        429) status="OK"; detail="Доступно, но упёрлись в лимит (HTTP 429, проверено с ключом)" ;;
        400|401|403)
          if is_auth; then
            status="WARN"; detail="Ключ $P_KEYVAR отклонён (HTTP $code) — страна не проверена"
          elif [ "$code" = 403 ]; then
            status="BLOCK"; detail="HTTP 403 с ключом без признаков авторизации — похоже на блокировку по IP/региону"
          else
            status="WARN"; detail="Неожиданный HTTP $code с ключом"
          fi ;;
        404) status="WARN"; detail="HTTP 404 с ключом: эндпоинт или модель не найдены" ;;
        5*)  status="WARN"; detail="Сервер ответил HTTP $code (проблема на стороне провайдера?)" ;;
        *)   status="WARN"; detail="Неожиданный HTTP $code с ключом" ;;
      esac
    fi
  else
    case "$code" in
      451)
        status="GEO"; detail="HTTP 451 — недоступно по юридическим причинам" ;;
      000)
        status="FAIL"; detail="Нет HTTP-ответа" ;;
      2*|3*)
        status="OK"; detail="Доступно" ;;
      401|404|405|400|415|422|429)
        if is_geo; then
          status="GEO"; detail="Гео-блокировка (HTTP $code)"
        else
          status="OK"; detail="Доступно (HTTP $code — ответ без ключа ожидаем)"
        fi ;;
      403)
        if is_geo; then
          status="GEO"; detail="Гео-блокировка (HTTP 403)"
        elif is_auth; then
          status="OK"; detail="Доступно (HTTP 403 — требуется ключ)"
        else
          status="BLOCK"; detail="HTTP 403 без признаков авторизации — похоже на блокировку по IP/региону"
        fi ;;
      5*)
        status="WARN"; detail="Сервер ответил HTTP $code (проблема на стороне провайдера?)" ;;
      *)
        status="WARN"; detail="Неожиданный HTTP $code" ;;
    esac
    # Сервер пустил без ключа, но страна в списке неподдерживаемых: блокировка
    # вероятно сработает только на запросе с ключом
    if [ "$status" = OK ] && in_unsupported "$id" "$COUNTRY"; then
      status="GEO?"
      detail="Сервер отвечает, но $COUNTRY нет среди поддерживаемых стран; для точной проверки задайте $P_KEYVAR"
    fi
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
    [ -z "$COUNTRY" ] && COUNTRY="$country"
  else
    echo "Внешний IP: не удалось определить"
  fi
fi
[ -n "$PROXY" ] && echo "Прокси: $PROXY"
if [ -n "$COUNTRY" ]; then
  echo "Страна для сверки со списками провайдеров: $COUNTRY"
else
  echo "Страна неизвестна — сверка со списками провайдеров отключена (задайте -c CC)"
fi
keys=""
for entry in "${ENDPOINTS[@]}"; do
  IFS='|' read -r name url id <<<"$entry"
  key_probe "${id:-}" && keys="$keys $name,"
done
[ -n "$keys" ] && echo "Проверка с ключом:${keys%,}"
echo

# --- Параллельный запуск ---
TMPDIR_RES="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_RES"' EXIT

i=0
running=0
for entry in "${ENDPOINTS[@]}"; do
  IFS='|' read -r name url id <<<"$entry"
  i=$((i+1))
  ( check_one "$name" "$url" "${id:-}" > "$TMPDIR_RES/$(printf '%03d' "$i")" ) &
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
echo "Статусы: OK — доступно; GEO — гео-блокировка; GEO? — страна не поддерживается (без ключа не подтвердить); BLOCK — похоже на блокировку; FAIL — сетевая ошибка; WARN — нестандартный ответ."

[ "$bad" -eq 0 ] && exit 0 || exit 1
