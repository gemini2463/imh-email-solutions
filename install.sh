#!/bin/bash

set -eu

# Email Solutions installer
# Version: 0.0.1

readonly SCRIPT_VERSION="0.0.1"
readonly SCRIPT_NAME="imh-email-solutions"
readonly BASE_URL="https://raw.githubusercontent.com/gemini2463/${SCRIPT_NAME}/master"

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly BRIGHTBLUE='\033[1;34m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

print_message() {
  local color=$1
  local message=$2
  echo -e "${color}${message}${NC}"
}

error_exit() {
  print_message "$RED" "ERROR: $1" >&2
  exit 1
}

check_root() {
  if [[ ${EUID} -ne 0 ]]; then
    error_exit "This script must be run as root"
  fi
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

detect_control_panel() {
  if [[ (-d /usr/local/cpanel || -d /var/cpanel || -d /etc/cpanel) && (-f /usr/local/cpanel/cpanel || -f /usr/local/cpanel/version) ]]; then
    echo "cpanel"
  elif [[ -d /usr/local/cwpsrv ]]; then
    echo "cwp"
  else
    echo "none"
  fi
}

validate_url() {
  local url=$1
  if command_exists wget; then
    wget --spider -q "$url" 2>/dev/null || return 1
    return 0
  fi
  if command_exists curl; then
    curl -fsSL --head "$url" >/dev/null 2>&1 || return 1
    return 0
  fi
  return 1
}

download_file() {
  local url=$1
  local destination=$2

  if command_exists wget; then
    wget -q -O "$destination" "$url" || return 1
    [[ -s "$destination" ]] || return 1
    return 0
  fi
  if command_exists curl; then
    curl -fsSL "$url" -o "$destination" || return 1
    [[ -s "$destination" ]] || return 1
    return 0
  fi
  return 1
}

create_directory() {
  local dir=$1
  local mode=${2:-755}
  if [[ ! -d "$dir" ]]; then
    mkdir -p "$dir" || return 1
  fi
  chmod "$mode" "$dir" || true
}

install_cpanel() {
  print_message "$YELLOW" "Installing for cPanel/WHM..."

  create_directory "/usr/local/cpanel/whostmgr/docroot/cgi/$SCRIPT_NAME" 755

  local tmp
  tmp=$(mktemp -d) || error_exit "Failed to create temp dir"

  print_message "$BRIGHTBLUE" "Downloading files..."

  download_file "$BASE_URL/index.php" "$tmp/index.php" || error_exit "Failed to download index.php"
  download_file "$BASE_URL/${SCRIPT_NAME}.conf" "$tmp/${SCRIPT_NAME}.conf" || error_exit "Failed to download ${SCRIPT_NAME}.conf"
  download_file "$BASE_URL/${SCRIPT_NAME}.png" "$tmp/${SCRIPT_NAME}.png" || error_exit "Failed to download ${SCRIPT_NAME}.png"
  # JS is optional
  download_file "$BASE_URL/${SCRIPT_NAME}.js" "$tmp/${SCRIPT_NAME}.js" || true

  print_message "$BRIGHTBLUE" "Installing files..."

  install -m 755 "$tmp/index.php" "/usr/local/cpanel/whostmgr/docroot/cgi/$SCRIPT_NAME/index.php"
  install -m 644 "$tmp/${SCRIPT_NAME}.conf" "/usr/local/cpanel/whostmgr/docroot/cgi/$SCRIPT_NAME/${SCRIPT_NAME}.conf"
  install -m 644 "$tmp/${SCRIPT_NAME}.png" "/usr/local/cpanel/whostmgr/docroot/cgi/$SCRIPT_NAME/${SCRIPT_NAME}.png"
  if [[ -s "$tmp/${SCRIPT_NAME}.js" ]]; then
    install -m 644 "$tmp/${SCRIPT_NAME}.js" "/usr/local/cpanel/whostmgr/docroot/cgi/$SCRIPT_NAME/${SCRIPT_NAME}.js"
  fi

  if [[ -d "/usr/local/cpanel/whostmgr/docroot/addon_plugins" ]]; then
    install -m 644 "$tmp/${SCRIPT_NAME}.png" "/usr/local/cpanel/whostmgr/docroot/addon_plugins/${SCRIPT_NAME}.png" || true
  fi

  print_message "$BRIGHTBLUE" "Registering plugin..."

  if [[ -x "/usr/local/cpanel/bin/register_appconfig" ]]; then
    /usr/local/cpanel/bin/register_appconfig "/usr/local/cpanel/whostmgr/docroot/cgi/$SCRIPT_NAME/${SCRIPT_NAME}.conf" || true
  else
    print_message "$YELLOW" "Warning: register_appconfig not found; plugin may need manual registration."
  fi

  rm -rf "$tmp" || true

  print_message "$GREEN" "cPanel install complete."
}

update_cwp_config() {
  local target="/usr/local/cwpsrv/htdocs/resources/admin/include/3rdparty.php"
  local include_file="/usr/local/cwpsrv/htdocs/resources/admin/include/imh-plugins.php"
  local include_statement="include('${include_file}');"

  [[ -f "$target" ]] || return 0
  if grep -Eq "include\s*\(['\"]${include_file}['\"]\)" "$target"; then
    return 0
  fi

  # Insert include after opening <?php (best-effort)
  local tmp
  tmp=$(mktemp "${target}.XXXXXX")
  awk -v inc="$include_statement" '
    BEGIN{done=0}
    {print}
    /<\?php/ && !done {print inc; done=1}
  ' "$target" > "$tmp"

  mv "$tmp" "$target"
}

install_cwp() {
  print_message "$YELLOW" "Installing for CWP..."

  [[ -d "/usr/local/cwpsrv/htdocs/resources/admin/modules" ]] || error_exit "CWP modules directory not found"

  local tmp
  tmp=$(mktemp -d) || error_exit "Failed to create temp dir"

  print_message "$BRIGHTBLUE" "Downloading files..."

  download_file "$BASE_URL/${SCRIPT_NAME}.php" "$tmp/${SCRIPT_NAME}.php" || error_exit "Failed to download ${SCRIPT_NAME}.php"
  download_file "$BASE_URL/imh-plugins.php" "$tmp/imh-plugins.php" || error_exit "Failed to download imh-plugins.php"
  download_file "$BASE_URL/${SCRIPT_NAME}.png" "$tmp/${SCRIPT_NAME}.png" || error_exit "Failed to download ${SCRIPT_NAME}.png"
  download_file "$BASE_URL/${SCRIPT_NAME}.js" "$tmp/${SCRIPT_NAME}.js" || true

  print_message "$BRIGHTBLUE" "Installing files..."

  install -m 755 "$tmp/${SCRIPT_NAME}.php" "/usr/local/cwpsrv/htdocs/resources/admin/modules/${SCRIPT_NAME}.php"

  create_directory "/usr/local/cwpsrv/htdocs/admin/design/img" 755
  create_directory "/usr/local/cwpsrv/htdocs/admin/design/js" 755
  create_directory "/usr/local/cwpsrv/htdocs/resources/admin/include" 755

  install -m 644 "$tmp/${SCRIPT_NAME}.png" "/usr/local/cwpsrv/htdocs/admin/design/img/${SCRIPT_NAME}.png"
  if [[ -s "$tmp/${SCRIPT_NAME}.js" ]]; then
    install -m 644 "$tmp/${SCRIPT_NAME}.js" "/usr/local/cwpsrv/htdocs/admin/design/js/${SCRIPT_NAME}.js"
  fi

  install -m 644 "$tmp/imh-plugins.php" "/usr/local/cwpsrv/htdocs/resources/admin/include/imh-plugins.php"
  update_cwp_config || true

  rm -rf "$tmp" || true

  print_message "$GREEN" "CWP install complete."
}

install_plain() {
  print_message "$YELLOW" "Installing plain (no control panel detected)..."

  local dest="/root/${SCRIPT_NAME}"
  create_directory "$dest" 700

  local tmp
  tmp=$(mktemp -d) || error_exit "Failed to create temp dir"

  download_file "$BASE_URL/index.php" "$tmp/index.php" || error_exit "Failed to download index.php"
  download_file "$BASE_URL/${SCRIPT_NAME}.png" "$tmp/${SCRIPT_NAME}.png" || error_exit "Failed to download ${SCRIPT_NAME}.png"
  download_file "$BASE_URL/${SCRIPT_NAME}.js" "$tmp/${SCRIPT_NAME}.js" || true

  install -m 700 "$tmp/index.php" "$dest/index.php"
  install -m 600 "$tmp/${SCRIPT_NAME}.png" "$dest/${SCRIPT_NAME}.png"
  if [[ -s "$tmp/${SCRIPT_NAME}.js" ]]; then
    install -m 600 "$tmp/${SCRIPT_NAME}.js" "$dest/${SCRIPT_NAME}.js"
  fi

  rm -rf "$tmp" || true

  print_message "$GREEN" "Plain install complete: $dest"
}

uninstall_main() {
  print_message "$YELLOW" "Uninstalling ${SCRIPT_NAME}..."

  local panel
  panel=$(detect_control_panel)

  case "$panel" in
    cpanel)
      rm -rf "/usr/local/cpanel/whostmgr/docroot/cgi/${SCRIPT_NAME}" || true
      rm -f "/usr/local/cpanel/whostmgr/docroot/addon_plugins/${SCRIPT_NAME}.png" || true
      if [[ -x "/usr/local/cpanel/bin/unregister_appconfig" ]]; then
        /usr/local/cpanel/bin/unregister_appconfig "${SCRIPT_NAME}" || true
      fi
      ;;
    cwp)
      rm -f "/usr/local/cwpsrv/htdocs/resources/admin/modules/${SCRIPT_NAME}.php" || true
      rm -f "/usr/local/cwpsrv/htdocs/admin/design/img/${SCRIPT_NAME}.png" || true
      rm -f "/usr/local/cwpsrv/htdocs/admin/design/js/${SCRIPT_NAME}.js" || true
      ;;
    *)
      rm -rf "/root/${SCRIPT_NAME}" || true
      ;;
  esac

  print_message "$GREEN" "Uninstall complete."
}

main() {
  check_root

  if [[ "${1:-}" == "--uninstall" ]]; then
    uninstall_main
    exit 0
  fi

  # Basic sanity: verify URLs exist (best-effort)
  if ! validate_url "$BASE_URL/index.php"; then
    print_message "$YELLOW" "Warning: cannot validate BASE_URL (${BASE_URL}). Continuing anyway."
  fi

  local panel
  panel=$(detect_control_panel)

  case "$panel" in
    cpanel) install_cpanel ;;
    cwp) install_cwp ;;
    *) install_plain ;;
  esac
}

main "$@"
