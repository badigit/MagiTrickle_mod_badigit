<p align="center">
  <img src="https://gitlab.com/magitrickle/magitrickle/-/raw/develop/img/logo256.png" alt="MagiTrickle logo"/>
</p>

MagiTrickle
=======

<details>
<summary><b>Назначение</b></summary>

MagiTrickle (произносится как *Мэджитрикл*) – утилита для точечной маршрутизации сетевого трафика по заданным доменным именам. Представляет собой установочный пакет, устанавливаемый в дополнение к операционной системе маршрутизатора.

<p align="center">
  <img src="https://gitlab.com/magitrickle/magitrickle/-/raw/develop/img/main_screenshot.png" alt="MagiTrickle Screenshot"/>
</p>

Принцип работы основан на подмене основного DNS-сервера через промежуточный компонент без его отключения. Это позволяет перехватывать входящие DNS-запросы, кешировать ответы и сопоставлять IP-адреса с доменными именами. Благодаря этому становится возможной маршрутизация трафика без необходимости очистки DNS-кэша на стороне клиентов. Очистка кэша требуется только при запуске или перезапуске сервиса MagiTrickle, поскольку в этот момент кэш ещё не прогрет, и маршрутизация невозможна до первого запроса к нужному домену.

</details>

## Установка

> Это форк [MagiTrickle](https://gitlab.com/magitrickle/magitrickle) с дополнительными возможностями: redir-tproxy, подписки на правила, захват DNS-запросов и др.

**Entware (Keenetic):**
```shell
opkg update && opkg install wget-ssl ca-certificates && wget -qO- https://raw.githubusercontent.com/badigit/MagiTrickle_mod_badigit/mod_badigit/scripts/install.sh | sh
```

**OpenWrt:**
```shell
wget -qO- https://raw.githubusercontent.com/badigit/MagiTrickle_mod_badigit/mod_badigit/scripts/install.sh | sh
```

Скрипт автоматически определяет платформу (Entware / OpenWrt opkg / OpenWrt apk), архитектуру, скачивает последнюю версию с GitHub и устанавливает. Для обновления — та же команда.

<details>
<summary><b>Описание типов правил</b></summary>

### Namespace (Именное пространство)

Охватывает указанный домен и все его поддомены.

Например, при записи `example.com` будут обрабатываться:
```
✅ example.com
✅ sub.example.com
✅ sub.sub.example.com
❌ anotherexample.com
❌ example.net
```

### Wildcard (Подстановочный шаблон)

Шаблон с `*` и `?` — позволяет задавать гибкие условия:
- `*` — любое количество любых символов
- `?` — ровно один любой символ
- `.` — обычная точка в имени

Wildcard без `*` и `?` работает как Namespace и включает само имя и поддомены.

Например, при записи `*example.com` будут обрабатываться:
```
✅ example.com
✅ sub.example.com
✅ sub.sub.example.com
✅ anotherexample.com
❌ example.net
```

### Domain (Точный домен)

Правило применяется только к строго указанному домену, без поддоменов.

Например, при записи `sub.example.com` будут обрабатываться:
```
❌ example.com
✅ sub.example.com
❌ sub.sub.example.com
❌ anotherexample.com
❌ example.net
```

### RegExp (Регулярное выражение)

Для опытных пользователей. Используется парсер [dlclark/regexp2](https://github.com/dlclark/regexp2).

Например, при записи `^[a-z]*example\.com$` будут обрабатываться:
```
✅ example.com
❌ sub.example.com
❌ sub.sub.example.com
✅ anotherexample.com
❌ example.net
```

</details>

## Режим redir-tproxy (прозрачный прокси)

MagiTrickle поддерживает маршрутизацию трафика через прозрачный прокси (например, mihomo, sing-box) с использованием комбинации TCP REDIRECT + UDP TPROXY.

**Преимущества:**
- Не требуется промежуточный SOCKS-прокси — одна зависимость меньше, проще настройка
- В логах прокси-сервера (например, mihomo dashboard) видны IP-адреса конечных устройств — удобно для диагностики
- Нет проблемы с обрывом UDP-соединений спустя 20 секунд (характерной для режима с SOCKS-прокси)

**Ограничения:**
- Встроенный speed test MagiTrickle не работает в этом режиме — тест скорости возможен только с конечного устройства

### 1. Настройка прокси-сервера

Прокси-сервер (mihomo, sing-box и т.д.) должен принимать перенаправленный трафик (TCP REDIRECT + UDP TPROXY) на выбранном порту.

Пример для mihomo (`config.yaml`):

```yaml
redir-port: 5001
```

> **Важно:** в mihomo используйте именно `redir-port`, а не `tproxy-port`. MagiTrickle перенаправляет TCP через nat/REDIRECT, а UDP через mangle/TPROXY — `redir-port` корректно обрабатывает оба типа трафика на одном порту. При использовании `tproxy-port` TCP-соединения будут устанавливаться, но ответы не будут доходить до клиента.

> **Важно:** `allow-lan: true` обязателен. Без него mihomo слушает только на `127.0.0.1`, и перенаправленный iptables трафик от устройств в сети не будет принят.

Полный минимальный пример конфига mihomo: [`examples/mihomo-global.yaml`](examples/mihomo-global.yaml)

### 2. Настройка DNS (три варианта)

#### Вариант A. DNS роутера (базовый)

DNS-запросы обрабатывает роутер, mihomo DNS выключен. Самый простой вариант для режима global.

mihomo:
```yaml
dns:
  enable: false
```

MagiTrickle:
```yaml
app:
  dnsProxy:
    upstream:
      address: 127.0.0.1
      port: 53
```

#### Вариант B. DNS через mihomo (локальный резолв)

mihomo резолвит DNS и ведёт маппинг IP↔домен. Нужен, если mihomo использует доменные правила.

mihomo:
```yaml
dns:
  enable: true
  listen: 0.0.0.0:6868
  enhanced-mode: redir-host
  nameserver:
    - 8.8.8.8
    - 8.8.4.4
```

MagiTrickle:
```yaml
app:
  dnsProxy:
    upstream:
      address: 127.0.0.1
      port: 6868
```

#### Вариант C. DNS через mihomo + upstream-сервер (максимальная приватность)

То же, что вариант B, но DNS-запросы маршрутизируются через указанную proxy-group — провайдер не видит DNS. После `#` указывается имя группы из `proxy-groups`.

mihomo:
```yaml
dns:
  enable: true
  listen: 0.0.0.0:6868
  enhanced-mode: redir-host
  nameserver:
    - "8.8.8.8#GLOBAL"
    - "8.8.4.4#GLOBAL"
  proxy-server-nameserver:
    - 8.8.8.8
    - 8.8.4.4
```

`proxy-server-nameserver` — DNS для резолва адресов самих прокси-серверов (без `#`, напрямую, чтобы избежать рекурсии).

MagiTrickle:
```yaml
app:
  dnsProxy:
    upstream:
      address: 127.0.0.1
      port: 6868
```

В вариантах B и C `redir-host` позволяет mihomo сопоставлять IP-адреса с доменами из своего DNS-кэша.

### 3. Настройка MagiTrickle и перезапуск

В конфиге `/opt/var/lib/magitrickle/config.yaml` укажите порт прокси-сервера:

```yaml
netfilter:
  tproxyPort: 5001
```

Где `tproxyPort` — тот же порт, что настроен в прокси-сервере на шаге 1.

```shell
/opt/etc/init.d/S99magitrickle restart
```

После запуска в веб-интерфейсе MagiTrickle появится виртуальный интерфейс **redir-tproxy**. Назначьте его группам правил, трафик которых должен идти через прозрачный прокси.

### Исключение отдельных клиентов

В разделе «Настройки» можно указать IP-адреса или CIDR-подсети клиентов, трафик которых не должен обрабатываться MagiTrickle. Те же параметры доступны в конфиге:

```yaml
app:
  clientRouting:
    mode: exclude
    sourceNetworks:
      - 192.168.1.50
      - 192.168.2.0/24
      - 2001:db8:1234::/64
```

Изменение применяется к новым соединениям без перезапуска. Для отдельных IPv4-устройств рекомендуется закрепить адрес в DHCP; временные IPv6-адреса лучше исключать стабильной клиентской подсетью.

### Приоритет direct-групп

Если один и тот же IP попадает и в direct-группу, и в группу с туннелем, побеждает direct — независимо от того, где группы стоят в списке. Это поведение по умолчанию. Конфигам, где широкая direct-группа стоит внизу как catch-all, а узкие группы с туннелем выше, нужен режим «по порядку»:

```yaml
app:
  netfilter:
    directPriority: byOrder   # absolute (по умолчанию) | byOrder
```

В режиме `byOrder` direct участвует в общей очереди наравне с остальными группами: пересечение выигрывает та группа, что выше в списке. Настройка читается при старте, поэтому её смена требует перезапуска демона.

Поведение обоих режимов проверяется интеграционным тестом на настоящем netfilter — в изолированных network namespace, без участия роутера:

```bash
sudo bash scripts/integration-test.sh
```

Раннер поднимает пару namespace и гоняет в них ВСЕ интеграционные тесты пакета (включая проверку client-bypass, которая раньше писала в ядро хоста). Тест приоритета, соединённых veth, применяет правила рабочим кодом, пропускает трафик на IP, который лежит сразу в двух группах, и по счётчикам правил проверяет, какая группа его перехватила. Требуется Linux с root, `ip`, `iptables` и `ipset` (в WSL работает).

## Поддержка

* [Официальный сайт](https://magitrickle.dev)
* [Форум на Keenetic Community](https://forum.keenetic.ru/topic/20125-magitrickle)
* [Канал Telegram](https://t.me/MagiTrickle)
* [Чат Telegram](https://t.me/MagiTrickleChat)
* [Финансовая поддержка](https://boosty.to/magitrickle)
