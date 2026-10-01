# Script_audit_linux
Этот скрипт написан на bash, проверяет основные конфигурационные файлы, права на эти файлы у пользователей, ищет необновленные пакеты безопасности. Давайте пройдемся по самой написанной программе
#Строгий режим отладки
Включаем строгий режим отладки - программа прервется, если при ее выполнение произойдет ошибка
```
set -euo pipefail
```
# ПРОВЕРКА НА ROOT

Функция которая проверяет, кто именно исполняет этот файл. Если этот пользователь имеет права root, то все хорошо, скрипт дальше продолжает работу.
```
if [[ $EUID -ne 0 ]]; then
    echo -e "FAILED: Только root может запустить этот скрипт"
    exit 1
fi
```
# Проверка на наличие сторонних пользователей с UID=0

Чтобы проверить каких-либо пользователей на UID=0, нам необходимо обратиться к конфигурационному файлу в котором у нас хранятся все учетки в системе (/etc/passwd). Далее через awk присваиваем переменной 1 аргумент в строке конфигурационного файла (название пользователя), у которых 3 и 4 аргумент равны 0.
```
audit_user(){
    echo "=== Проверка пользователей с UID 0 ==="
    local user_zero
    user_zero=$(awk -F: '$3==0 && $4==0 {print $1}' /etc/passwd)
    # Обязательно берем в кавычки "$user_zero", чтобы не упасть при пустом значении
    if [ "$user_zero" != "root" ]; then
        echo "Найдены сторонние пользователи с UID 0: ${user_zero}"
    else
        echo 'Лишних root-пользователей не обнаружено.'
    fi
}
```
# Проверка на пустые пароли пользователей

В файле /etc/shadow находим через awk и регулярное выражение учетки с пустыми паролями. В конфиге пустые пароли обозначаются через *.
```
ереaudit_user_password_null(){
    echo "=== Проверка на пустые и заблокированные пароли ==="
    # Ищем тех, у кого пароль отключен (*)
    local user_zpassword
    user_zpassword=$(awk -F: '$2 ~ /^[*]/ {print $1}' /etc/shadow)
    echo "Учетки с отключенными паролями (*):"
    echo "${user_zpassword:-Никого не найдено}"
    # Ищем заблокированные учетки (!)
    local user_blockpassword
    user_blockpassword=$(awk -F: '$2 ~ /^[!]/ {print $1}' /etc/shadow)
    echo "Заблокированные учетки (!):"
    echo "${user_blockpassword:-Никого не найдено}"
}
```
# Проверка прав на критические конфигурационные файлы 

Составляем список critical_file и записываем в него самые критичные конфигурационные файлы. Далее через for проверяем каждые файл на избыточные права при помощи stat. И задаем условие, при котором, если права не равны 600, 640, 440, 755 тогда функция perm_status_file определяет как опасность для безопасности.
```
perm_status_file(){
    echo "=== Проверка прав на критические файлы ==="
    local critical_file=("/etc/passwd" "/etc/shadow" "/etc/group" "/etc/security/pwquality.conf" "/etc/pam.d/" "/etc/sudoers" "/etc/sudoers.d/" "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.d/" "~/.ssh/authorized_keys" "/etc/crontab" "/var/spool/cron/crontabs/" "/etc/anacrontab" "/etc/exports" "/etc/fstab" "/etc/hosts" "/etc/resolv.conf" "/etc/rc.local" "/etc/sysctl.conf" "/etc/sysctl.d/" "/etc/environment" "/etc/profile")
    for i in "${critical_file[@]}"; do
        if [ -e "$i" ]; then
            local status_permission
            status_permission=$(stat -c "%a" "$i")
            if [ "$status_permission" -ne 640 ] && [ "$status_permission" -ne 600 ] && [ "$status_permission" -ne 440 ] && [ "$status_permission" -ne 755 ]; then
                echo "[!] ОПАСНОСТЬ: Нетипичные права на ${i}: ${status_permission}"
            fi
        fi
    done
}
```
# Проверка доступных способов подключения по ssh пользователя root
В файле /etc/ssh/sshd_config находим параметры PubkeyAuthentication, PasswordAuthentication, PermitRootLogin. И в зависимости от того, какие значения присвоены этим параметрам выводит, что root может делать через ssh. Привожу пояснение:
1. PubkeyAuthentication no - запрещает всем пользователя подключаться по публичному ключу;
2. PubkeyAuthentication no - разрешает всем пользователя подключаться по публичному ключу;
3. PasswordAuthentication no - запрещает пользователям подключаться по ssh через пароль;
4. PasswordAuthentication yes - разрешает пользователям подключаться по ssh через пароль;
5. PermitRootLogin yes - разрешает подключаться по ssh пользователю root и по публичному ключу и по паролю;
6. PermitRootLogin no -  запрещает подключаться по ssh пользователю root;
7. PermitRootLogin prohibit-password - разрешает подключаться пользователю root по ssh через публичный ключ. 

```
ssh_audit_onlyroot(){
    echo "=== Проверка конфигурации SSH root ==="
    if grep -qE "^[[:space:]]*PubkeyAuthentication[[:space:]]+no" /etc/ssh/sshd_config && \
       grep -qE "^[[:space:]]*PasswordAuthentication[[:space:]]+no" /etc/ssh/sshd_config; then
        echo "Для root и для других пользователей запрещено подключаться по ssh через публичный ключ и по паролю"
        return
    elif grep -qE "^[[:space:]]*PermitRootLogin[[:space:]]+prohibit-password" /etc/ssh/sshd_config && \
         grep -qE "^[[:space:]]*PubkeyAuthentication[[:space:]]+yes" /etc/ssh/sshd_config && \
         grep -qE "^[[:space:]]*PasswordAuthentication[[:space:]]+no" /etc/ssh/sshd_config; then
        echo "Разрешен вход по SSH для root (только по ключам)!"
    elif grep -qE "^[[:space:]]*PermitRootLogin[[:space:]]+yes" /etc/ssh/sshd_config && \
         grep -qE "^[[:space:]]*PasswordAuthentication[[:space:]]+yes" /etc/ssh/sshd_config && \
         grep -qE "^[[:space:]]*PubkeyAuthentication[[:space:]]+yes" /etc/ssh/sshd_config; then
        echo "Подключение по ssh для root работает через пароль и по публичному ключу"
        echo 'ОПАСНО! Поменяй на prohibit-password, чтобы исключить подбор пароля через brute force'
    elif grep -qE "^[[:space:]]*PermitRootLogin[[:space:]]+no" /etc/ssh/sshd_config || \
         grep -qE "^[[:space:]]*PubkeyAuthentication[[:space:]]+no" /etc/ssh/sshd_config; then
        echo "Для root полностью закрыта возможность подключения через ssh"
    fi
}

```
# Проверка доступных способов подключения по ssh пользователя root
1. PubkeyAuthentication no - запрещает всем пользователя подключаться по публичному ключу;
2. PubkeyAuthentication no - разрешает всем пользователя подключаться по публичному ключу;
3. PasswordAuthentication no - запрещает пользователям подключаться по ssh через пароль;
4. PasswordAuthentication yes - разрешает пользователям подключаться по ssh через пароль;


```
ssh_audit_user(){
    echo "=== Проверка конфигурации SSH user ==="
    if grep -qE "^[[:space:]]*PubkeyAuthentication[[:space:]]+no" /etc/ssh/sshd_config && grep -qE "^[[:space:]]*PasswordAuthentication[[:space:]]+no" /etc/ssh/sshd_config; then
        echo "Для пользователей запрещено подключаться по ssh через публичный ключ и по паролю"
        return
    elif grep -qE "^[[:space:]]*PubkeyAuthentication[[:space:]]+yes" /etc/ssh/sshd_config && grep -qE "^[[:space:]]*PasswordAuthentication[[:space:]]+no" /etc/ssh/sshd_config; then
        echo "Разрешен безопасный вход по SSH!"
    elif grep -qE "^[[:space:]]*PasswordAuthentication[[:space:]]+yes" /etc/ssh/sshd_config && grep -qE "^[[:space:]]*PubkeyAuthentication[[:space:]]+yes" /etc/ssh/sshd_config; then
        echo "Подключение по ssh работает через пароль и по публичному ключу"
        echo 'Опасно! Поменяйте PasswordAuthentication на no'
    elif grep -qE "^[[:space:]]*PubkeyAuthentication[[:space:]]+no" /etc/ssh/sshd_config && grep -qE "^[[:space:]]*PasswordAuthentication[[:space:]]+yes" /etc/ssh/sshd_config; then
        echo "Подключение по ssh работает только по паролю"
    fi
}
```
# Проверка возможности подключения по ssh через tgt билет
```
ssh_audit_kerberos(){
    echo "=== Проверка конфигурации SSH Kerberos ==="
    if grep -qE "^[[:space:]]*KerberosAuthentication[[:space:]]+no" /etc/ssh/sshd_config; then
        echo "Запрет подключения по ssh через билеты kerberos"
    fi
    if grep -qE "^[[:space:]]*KerberosAuthentication[[:space:]]+yes" /etc/ssh/sshd_config; then
        echo "Разрешено подключаться по ssh через билеты kerberos"
        if grep -qE "^[[:space:]]*KerberosTicketCleanup[[:space:]]+no" /etc/ssh/sshd_config; then
            echo "Опасно! Поменяй параметр KerberosTicketCleanup на yes"
        fi
    fi
}
```
# Проверка возможности подключения по ssh через GSSAPI
Скажем так, это безопасный способ аутентификации через kerberose. В обычном kerberos при подключении ты вводишь пароль и получаешь tgt билет, а в gssapi, когда ты только вошел в систему тебе присвоили tgt билет и при подключении по ssh пароль уже не требуется.

```
ssh_audit_gssapi(){
    echo "=== Проверка конфигурации SSH GSSAPI ==="
    if grep -qE "^[[:space:]]*GSSAPIAuthentication[[:space:]]+no" /etc/ssh/sshd_config; then
        echo "Вход по SSH через GSSAPI (SSO) запрещен"
    fi
    if grep -qE "^[[:space:]]*GSSAPIAuthentication[[:space:]]+yes" /etc/ssh/sshd_config; then
        echo "Разрешено подключаться по SSH через GSSAPI. Проверьте настройки доменной авторизации."
    fi
    if grep -qE "^[[:space:]]*GSSAPICleanupCredentials[[:space:]]+no" /etc/ssh/sshd_config; then
        echo "Опасно! Параметр GSSAPICleanupCredentials установлен в no."
    fi
}
```

# Проверка сложности пароля

```
audit_password_policy() {
    echo "=== АУДИТ ПОЛИТИКИ СЛОЖНОСТИ ПАРОЛЕЙ ==="
    local config="/etc/security/pwquality.conf"
    if [ ! -f "$config" ]; then
        echo "[-] Файл конфигурации pwquality не найден."
        return 0
    fi
    local active_rules
    # Исправленная регулярка без лишних квадратных скобок
    active_rules=$(grep -E -v '^[[:space:]]*#|^[[:space:]]*$' "$config" || true)
    if [ -z "$active_rules" ]; then
        echo "[!] ВНИМАНИЕ: Все правила закомментированы! Действуют дефолтные мягкие настройки."
    else
        echo "[+] Активные правила безопасности паролей:"
        echo "$active_rules"
    fi
}
```
# Проверка открытых сетевых портов через netstat
```
network_audit(){
    echo '=== Проверка открытых сетевых портов ==='
    # netstat устарел, используем ss. Если ss нет, выполнится netstat
    if command -v ss &>/dev/null; then
        ss -tulnp
    else
        netstat -tlnup
    fi
}

```
# Вывод списка активных служб в автозагрузке через systemctl

```
audit_suid_sgid() {
    echo "=== АУДИТ БИНАРНИКОВ С ФЛАГАМИ SUID/SGID ==="
    # 1. Поиск SUID файлов (права -perm /4000 или -perm -4000)
    echo "[*] Поиск файлов с установленным флагом SUID (запуск от имени владельца)..."
    local suid_files
    # Ищем файлы (-type f) с маской прав 4000, ошибки "Permission denied" глушим через 2>/dev/null
    suid_files=$(find / -xdev -perm -4000 -type f 2>/dev/null || true)
    if [ -z "$suid_files" ]; then
        echo "    [+] SUID файлов не обнаружено."
    else
        echo "    [!] Обнаружены SUID файлы (проверьте их по базе GTFOBins):"
        echo "$suid_files" | while read -r file; do
            # Извлекаем владельца и права для наглядности
            local file_info
            file_info=$(stat -c "%U:%G (права: %a)" "$file" 2>/dev/null || echo "Не удалось прочитать")
            echo "        -> $file : $file_info"
        done
    fi
    echo ""
    # 2. Поиск SGID файлов (права -perm /2000 или -perm -2000)
    echo "[*] Поиск файлов с установленным флагом SGID (запуск от имени группы)..."
    local sgid_files
    sgid_files=$(find / -xdev -perm -2000 -type f 2>/dev/null || true)
    if [ -z "$sgid_files" ]; then
        echo "    [+] SGID файлов не обнаружено."
    else
        echo "    [!] Обнаружены SGID файлы:"
        echo "$sgid_files" | while read -r file; do
            local file_info
            file_info=$(stat -c "%U:%G (права: %a)" "$file" 2>/dev/null || echo "Не удалось прочитать")
            echo "        -> $file : $file_info"
        done
    fi
}
```

# Проверка обновления пакетов безопасности

```
audit_security_packages() {
    echo "=== АУДИТ ОБНОВЛЕНИЙ БЕЗОПАСНОСТИ ==="
    if command -v apt-get &>/dev/null; then
        echo "[*] Обновление кэша APT..."
        apt-get update -y &>/dev/null
        local security_updates
        security_updates=$(apt-get -s upgrade 2>/dev/null | grep "^Inst" | grep -iE "security|ubuntu.*-updates" || true)
        if [ -z "$security_updates" ]; then
            echo -e "[ ${GREEN}OK${NC} ] Критических устаревших пакетов безопасности не обнаружено."
        else
            echo -e "[ ${RED}WARN${NC} ] ОБНАРУЖЕНЫ УЯЗВИМЫЕ ПАКЕТЫ! Срочно требуются патчи безопасности:"
            echo "$security_updates" | awk '{print "    -> " $2 " (доступна версия: " $3 ")"}'
        fi
    elif command -v dnf &>/dev/null || command -v yum &>/dev/null; then
        local pkg_mgr
        command -v dnf &>/dev/null && pkg_mgr="dnf" || pkg_mgr="yum"
        echo "[*] Проверка эксплойтов через $pkg_mgr..."
        local dnf_updates
        dnf_updates=$($pkg_mgr check-update --security 2>/dev/null | grep -vE "Last metadata|Loaded plugins" | grep -v '^[[:space:]]*$' || true)
        if [ -z "$dnf_updates" ]; then
            echo "[ OK ] Обновлений безопасности не найдено."
        else
            echo "[ WARN ] Найдены уязвимые пакеты:"
            echo "$dnf_updates"
        fi
    fi
}
```


