# 📡 SNI Probe — Подробная документация

## 🎯 Что это и зачем нужно

**SNI Probe** — инструмент для исследования блокировок по SNI (Server Name Indication) у интернет-провайдеров в контексте использования протокола **VLESS + TCP + REALITY**.

### Проблема, которую решает

Когда вы настраиваете VPN с протоколом REALITY:
- Клиент подключается к **вашему серверу** (например, `111.111.111.111:8080`)
- Но внутри TLS-рукопожатия указывает **чужой домен** как SNI (например, `catalog.api.2gis.com`)
- Провайдер видит этот SNI и может **заблокировать соединение**, если домен в чёрном списке
- Ваш REALITY-сервер получает рукопожатие и решает, пускать ли клиента

**Задача**: найти домены, которые НЕ блокируются провайдером и подходят для маскировки.

---

## 🔬 Как работает программа

### Два типа проверок

#### 1️⃣ **Control Check** (контрольная проверка)
Прямое подключение к реальному домену:
```
Ваш компьютер → catalog.api.2gis.com:443
```

**Цель**: понять, доступен ли сам домен с вашего IP/провайдера.

**Результаты**:
- `ok:TLSv1.3:45ms` — домен доступен, TLS работает, задержка 45 мс
- `fail:timeout:6000ms` — домен недоступен (может быть заблокирован или офлайн)

#### 2️⃣ **Probe Check** (тестовая проверка)
Подключение к **вашему серверу**, но с SNI чужого домена:
```
Ваш компьютер → ВАШ_СЕРВЕР_IP:8080
                 (но в TLS ClientHello пишем SNI: catalog.api.2gis.com)
```

**Цель**: проверить, блокирует ли провайдер соединение по SNI.

**Результаты**:
- `ok` — соединение прошло, SNI не заблокирован ✅
- `fail` — провайдер сбросил соединение (reset/timeout) ❌

---

## 📊 Интерпретация результатов

### Идеальный сценарий
```
Control: ok:TLSv1.3:45ms
Probe:   ok (latency: 120ms)
```
✅ **Домен подходит для REALITY** — и сам доступен, и SNI не блокируется.

### Домен офлайн/заблокирован, но SNI проходит
```
Control: fail:timeout:6000ms
Probe:   ok (latency: 110ms)
```
✅ **Можно использовать** — провайдер не блокирует SNI этого домена, даже если сам домен недоступен.

### SNI заблокирован провайдером
```
Control: ok:TLSv1.3:50ms
Probe:   fail (connection reset by peer, latency: 15ms)
```
❌ **Нельзя использовать** — провайдер режет соединения с этим SNI. Быстрая блокировка (15ms) = локальный DPI.

### Ошибка REALITY-сервера
```
Control: ok:TLSv1.3:60ms
Probe:   ok (WRONG_VERSION_NUMBER, latency: 130ms)
```
✅ **Отлично!** — соединение дошло до сервера, но REALITY отверг его (нормально, т.к. мы не делаем полную аутентификацию). SNI прошёл фильтр провайдера.

---

## ⚙️ Параметры командной строки

### Обязательные
```bash
--server-ip 111.111.111.111   # IP вашего REALITY-сервера
--domains whitelist.txt        # Файл со списком доменов (по одному на строку)
```

### Основные
```bash
--server-port 8080             # Порт сервера (по умолчанию 443)
--out results.csv              # Имя выходного файла
--isp "Rostelecom"                # Название провайдера (для аналитики)
--where "Moscow"               # Локация (город/регион)
```

### Контроль поведения
```bash
--no-control                   # Не делать control checks (быстрее, но меньше данных)
--timeout 8.0                  # Таймаут для каждого соединения в секундах
--workers 10                   # Количество параллельных потоков (1-50)
--quiet                        # Не показывать прогресс (для cron-задач)
```

### Классификация ошибок (важно для REALITY!)
```bash
--ok-on-wrong-version          # Считать "WRONG_VERSION_NUMBER" успешным
--ok-on-alert                  # Считать TLS alerts успешными
```

**Когда использовать**:
- `--ok-on-wrong-version` — **всегда** для REALITY (это нормальная реакция сервера)
- `--ok-on-alert` — если видите много false negatives (домены, которые должны работать, но помечены как fail)

---

## 🚀 Примеры использования

### Базовый тест с одним провайдером
```bash
python sni_probe.py \
  --server-ip 111.111.111.111 \
  --server-port 8080 \
  --domains whitelist.txt \
  --out rostelecom_moscow.csv \
  --isp "Rostelecom" \
  --where "Moscow" \
  --ok-on-wrong-version \
  --ok-on-alert
```

### Быстрое тестирование (много потоков)
```bash
python sni_probe.py \
  --server-ip 111.111.111.111 \
  --server-port 8080 \
  --domains large_list.txt \
  --out quick_test.csv \
  --workers 30 \
  --timeout 5.0 \
  --no-control \
  --ok-on-wrong-version \
  --quiet
```

### Аккуратное тестирование (низкая нагрузка)
```bash
python sni_probe.py \
  --server-ip 111.111.111.111 \
  --server-port 8080 \
  --domains sensitive_list.txt \
  --out careful_test.csv \
  --workers 3 \
  --timeout 10.0 \
  --isp "Rostelecom" \
  --ok-on-wrong-version
```

### Ночной мониторинг (cron-задача)
```bash
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M)
python sni_probe.py \
  --server-ip 111.111.111.111 \
  --server-port 8080 \
  --domains daily_check.txt \
  --out "results/rostelecom_${DATE}.csv" \
  --isp "Rostelecom" \
  --where "Moscow" \
  --quiet \
  --ok-on-wrong-version \
  --ok-on-alert
```

---

## 📁 Формат выходного CSV

Колонки в файле `results.csv`:

| Колонка | Пример | Описание |
|---------|--------|----------|
| `timestamp` | `2024-10-24T15:30:45Z` | Время проверки (UTC) |
| `isp_name` | `Rostelecom` | Название провайдера |
| `probe_location` | `Moscow` | Город/регион |
| `server_ip` | `111.111.111.111` | IP вашего сервера |
| `server_port` | `8080` | Порт сервера |
| `domain` | `catalog.api.2gis.com` | Проверяемый домен |
| `sni` | `catalog.api.2gis.com` | SNI (обычно = domain) |
| `control_tcp_443` | `ok:45ms` | Результат TCP-подключения к домену |
| `control_tls_handshake` | `ok:TLSv1.3:50ms` | Результат TLS к домену |
| `probe_tls_to_server_with_sni` | `ok` / `fail` | **Главный результат** — прошёл ли SNI |
| `probe_error` | `connection reset by peer` | Текст ошибки (если fail) |
| `notes` | `proto=TLSv1.3,lat=120ms` | Дополнительная информация |

---

## 🧮 Анализ данных

### Быстрая статистика через командную строку
```bash
# Процент успешных SNI
awk -F';' 'NR>1 && $10=="ok" {ok++} NR>1 {total++} END {print ok/total*100"%"}' results.csv

# Топ-10 самых быстрых доменов
awk -F';' 'NR>1 && $10=="ok" {print $6, $12}' results.csv | sort -k2 -n | head -10

# Типы ошибок блокировок
awk -F';' 'NR>1 && $10=="fail" {print $11}' results.csv | sort | uniq -c | sort -rn
```

### Python-анализ
```python
import pandas as pd

df = pd.read_csv("results.csv", delimiter=";")

# Процент успеха по провайдерам
success_rate = df.groupby("isp_name")["probe_tls_to_server_with_sni"].apply(
    lambda x: (x == "ok").sum() / len(x) * 100
)
print("Success rate by ISP:")
print(success_rate)

# Домены с самой низкой задержкой
df_ok = df[df["probe_tls_to_server_with_sni"] == "ok"].copy()
df_ok["latency"] = df_ok["notes"].str.extract(r'lat=(\d+)ms').astype(float)
top_fast = df_ok.nsmallest(20, "latency")[["domain", "latency"]]
print("\nFastest domains:")
print(top_fast)

# Паттерны блокировок
df_fail = df[df["probe_tls_to_server_with_sni"] == "fail"]
print("\nBlocking patterns:")
print(df_fail["probe_error"].value_counts())
```

---

## 🎨 Визуализация результатов

```python
import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("results.csv", delimiter=";")

# График 1: Успешность по провайдерам
success = df.groupby("isp_name")["probe_tls_to_server_with_sni"].apply(
    lambda x: (x == "ok").sum() / len(x) * 100
)
success.plot(kind="bar", title="SNI Success Rate by ISP", ylabel="%")
plt.tight_layout()
plt.savefig("success_by_isp.png")

# График 2: Распределение задержек
df_ok = df[df["probe_tls_to_server_with_sni"] == "ok"].copy()
df_ok["latency"] = df_ok["notes"].str.extract(r'lat=(\d+)ms').astype(float)
df_ok["latency"].hist(bins=50, title="Latency Distribution (ms)")
plt.xlabel("Latency (ms)")
plt.ylabel("Count")
plt.savefig("latency_distribution.png")
```

---

## 🔍 Классификация ошибок

### ✅ Считаются успешными (с флагами)

**С `--ok-on-wrong-version`:**
- `SSL: WRONG_VERSION_NUMBER` — сервер получил пакет, но версия TLS не совпала
- `SSL: PROTOCOL_VERSION` — аналогично
- `SSL: UNRECOGNIZED_NAME` — сервер не ожидал этот SNI
- `SSL: CERTIFICATE_UNKNOWN` — проблема с сертификатом на сервере
- `SSL: BAD_CERTIFICATE` — аналогично

**С `--ok-on-alert`:**
- `TLSv1 alert *` (кроме internal error) — TLS-предупреждения от сервера

**Почему это ok**: Эти ошибки означают, что **пакет дошёл до сервера**, а значит провайдер не заблокировал SNI на уровне DPI.

### ❌ Всегда считаются блокировкой

- `Connection reset by peer` — соединение сброшено (обычно DPI)
- `Connection refused` — порт закрыт или фильтр
- `Timed out` / `Operation timed out` — таймаут (может быть чёрная дыра)
- `Network unreachable` — проблемы с маршрутизацией

### 🕐 Интерпретация задержек

| Задержка | Вероятная причина |
|----------|-------------------|
| < 50ms | Локальная блокировка (DPI на уровне провайдера) |
| 50-200ms | Нормальное соединение до сервера |
| 200-1000ms | Высокая задержка (дальний сервер / плохой роутинг) |
| > 5000ms | Близко к таймауту, возможна деградация |

---

## 🛡️ Безопасность и этика

### ⚠️ Важные правила

1. **Не запускайте без разрешения** на чужих серверах
2. **Используйте только свои IP-адреса** в `--server-ip`
3. **Не перегружайте сервер** — используйте разумное количество workers (5-20)
4. **Проверяйте законность** в вашей юрисдикции
5. **Не тестируйте** критическую инфраструктуру (банки, госсайты, медицину)

### Рекомендации

- Делайте перерывы между запусками (минимум 10 минут)
- Используйте `--timeout 8-10` для снижения нагрузки
- Начинайте с `--workers 5` и увеличивайте постепенно
- Проверяйте логи сервера на признаки бана

---

## 🐛 Типичные проблемы

### Все домены показывают `fail`
**Причина**: Сервер недоступен или неправильно настроен REALITY  
**Решение**: 
1. Проверьте доступность сервера: `telnet 111.111.111.111 8080`
2. Убедитесь, что REALITY слушает на этом порту
3. Проверьте файрвол на сервере

### Очень низкая скорость сканирования
**Причина**: Слишком большой таймаут или мало workers  
**Решение**: `--timeout 5.0 --workers 20`

### Много `WRONG_VERSION_NUMBER`, но все в fail
**Причина**: Не указан флаг `--ok-on-wrong-version`  
**Решение**: Добавьте этот флаг — это нормальная реакция REALITY

### CSV-файл пустой
**Причина**: Ошибка записи или прерывание программы  
**Решение**: Проверьте права на запись, используйте абсолютный путь в `--out`

---

## 📚 Дополнительные ресурсы

- **REALITY протокол**: https://github.com/XTLS/REALITY
- **Документация VLESS**: https://xtls.github.io/
- **Анализ DPI**: https://github.com/ValdikSS/GoodbyeDPI

---

## 🤝 Contributing

Если вы нашли баг или хотите улучшить инструмент:
1. Проверьте список open issues
2. Создайте подробный issue с примером
3. Предложите pull request с тестами

---

**Версия**: 2.0 (с параллелизмом и расширенной аналитикой)  
**Лицензия**: MIT  
**Автор**: VPN Research Community
