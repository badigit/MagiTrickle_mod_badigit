## Исправлено

- **OpenWrt.** Обычные DNS-запросы больше не попадают в `daemon.err`. `procd` по-прежнему помечает ошибки демона как `daemon.err`.
- **Маршрутизация.** Удаление уже отсутствующих маршрутов, правил и записей ipset больше не прерывает очистку. Включение и выключение маршрутизации синхронизировано с изменением конфигурации.
- **Диагностика.** Nettrace связывает события ETW с захватом DNS. Для замеров DNS добавлен `tools/dns-bench`.

---

**Установка / обновление на Keenetic (Entware):**

```sh
opkg update && opkg install wget-ssl ca-certificates
wget -qO- https://raw.githubusercontent.com/badigit/MagiTrickle_mod_badigit/mod_badigit/scripts/install.sh | sh
```

Дальше можно обновляться прямо из веб-интерфейса, кнопкой «Обновить».
