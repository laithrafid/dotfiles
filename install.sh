#!/bin/bash
set -euo pipefail
#IFS=$'\n\t'

# inspired by
# https://gist.github.com/codeinthehole/26b37efa67041e1307db
# https://github.com/why-jay/osx-init/blob/master/install.sh
# https://github.com/timsutton/osx-vm-templates/blob/master/scripts/xcode-cli-tools.sh
# https://codeberg.org/lotharschulz/gists/src/branch/main/osx_bootstrap.sh
# you may have to enter your password 

install_xcode(){
echo "Checking Xcode CLI tools"
# Only run if the tools are not installed yet
# To check that try to print the SDK path
xcode-select -p &> /dev/null
if [ "$?" != "0" ]; then
  echo "Xcode CLI tools not found. Installing them..."
  touch /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress;
  PROD=$(softwareupdate -l |
    grep "\*.*Command Line" |
    tail -n 1 | sed 's/^[^C]* //')
    echo "Prod: ${PROD}"
  softwareupdate -i "$PROD" --verbose;
else
  echo "Xcode CLI tools OK"
fi
}

SUDO_USER=$(whoami)
INSTALLDIR=/Users/$SUDO_USER/dotfiles
PACKAGES=(
    bash-completion
    brew-cask-completion
    coreutils
    gnu-sed
    gnu-tar
    gnu-indent
    gnu-which
    findutils
    asciinema
    bash
    nmap
    ack
    autoconf
    automake
    autojump
    ffmpeg
    fx
    kompose
    terraform
    packer
    gettext
    gifsicle
    git
    graphviz
    gradle
    golang
    gnupg
    hub
    httpie
    helm
    maven
    imagemagick
    jq
    jpegoptim
    libjpeg
    libmemcached
    lynx
    markdown
    memcached
    mercurial
    minikube
    npm
    nvm
    htop
    ifstat
    skaffold
    curl
    netron
    node
    optipng
    pkg-config
    postgresql
    python
    python3
    pypy
    rabbitmq
    ripgrep
    rename
    ssh-copy-id
    tig
    terminal-notifier
    tesseract
    the_silver_searcher
    tmux
    tree
    yamllint
    vim
    watch
    wget
    yamllint
)

CASKS=(
    burp-suite
    google-cloud-sdk
    vagrant
    wireshark
    libreoffice
    gimp
    docker
    google-chrome
    miro
    protopie
    rectangle
    slack
    thunderbird
    vagrant
    virtualbox
    visual-studio-code
    vlc
    microsoft-remote-desktop
    sublime-text
    openphone
)
PYTHON_PACKAGES=(
    ipython
    virtualenv
    virtualenvwrapper
)


brew_install(){
    echo "Installing packages..."
    brew install ${PACKAGES[@]}
    echo "Installing cask apps..."
    sudo -u $SUDO_USER brew install --cask ${CASKS[@]}
    echo "Installing Python packages..."
    sudo -u $SUDO_USER pip3 install --upgrade pip
    sudo -u $SUDO_USER pip3 install --upgrade setuptools
    sudo -u $SUDO_USER pip3 install ${PYTHON_PACKAGES[@]}
    echo "Installing global npm packages..."
    sudo -u $SUDO_USER npm install marked -g
    echo "brew update"
    brew update
    echo "brew upgrade"
    brew upgrade
}

brew_uninstall(){
    echo "Uninstalling packages..."
    brew uninstall --force ----ignore-dependencies ${PACKAGES[@]}
    echo "Uninstalling cask apps..."
    sudo -u $SUDO_USER brew uninstall --ignore-dependencies --force --cask ${CASKS[@]}
    echo "Uninstalling Python packages..."
    sudo -u $SUDO_USER pip3 uninstall ${PYTHON_PACKAGES[@]}
    sudo -u $SUDO_USER pip3 uninstall setuptools
    sudo -u $SUDO_USER pip3 uninstall  pip
    echo "Uninsatll brew"
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/uninstall.sh)"
}

create_symlinks(){
	if [ ! -h ~/.conf.tmux ]; then
		ln -sfn $INSTALLDIR/tmux.conf ~/.tmux.conf
	else
		rm -rf ~/.tmux.conf
		ln -sfn $INSTALLDIR/tmux.conf ~/.tmux.conf
	fi
	
	if [ ! -h ~/.profile ]; then
		ln -sfn $INSTALLDIR/bash_profile ~/.profile
	else
		rm -rf ~/.profile
		ln -sfn $INSTALLDIR/bash_profile ~/.profile
	fi
	
	if [ ! -h ~/.vimrc ]; then
		ln -sfn $INSTALLDIR/vimrc ~/.vimrc
	else
		rm -rf ~/.vimrc
		ln -sfn $INSTALLDIR/vimrc ~/.vimrc
	fi
	
	if [ ! -h ~/.gitconfig ]; then
		ln -sfn $INSTALLDIR/gitconfig ~/.gitconfig
	else
		rm -rf ~/.gitconfig
		ln -sfn $INSTALLDIR/gitconfig ~/.gitconfig
	fi
}


install_deps(){
echo " installing dotfiles startet"
echo "checking if git exist"
which git > /dev/null
if [ "$?" != "0" ]; then
  echo "You need git installed to install configs."
  exit 1
else
  echo "Installing vundle into ~/.vim/bundle/ directory"
  rm -rf ~/.vim/*
  git clone https://github.com/VundleVim/Vundle.vim.git ~/.vim/bundle/Vundle.vim
fi
}
uninstall_homebrew(){
abort() {
  printf "%s\n" "$@"
  exit 1
}

# Fail fast with a concise message when not using bash
# Single brackets are needed here for POSIX compatibility
# shellcheck disable=SC2292
if [ -z "${BASH_VERSION:-}" ]
then
  abort "Bash is required to interpret this script."
fi

shopt -s extglob

strip_s() {
  local s
  for s in "$@"
  do
    s="${s## }"
    echo "${s%% }"
  done
}

dir_children() {
  local p
  for p in "$@"
  do
    [[ -d "${p}" ]] || continue
    find "${p}" -mindepth 1 -maxdepth 1
  done
}

# Set up temp dir
tmpdir="/tmp/uninstall.$$"
mkdir -p "${tmpdir}" || abort "Unable to create temp dir '${tmpdir}'"
trap '
  rm -fr "${tmpdir}"
  # Invalidate sudo timestamp before exiting
  /usr/bin/sudo -k
' EXIT

# Default options
opt_force=""
opt_quiet=""
opt_dry_run=""
opt_skip_cache_and_logs=""

# global status to indicate whether there is anything wrong.
failed=false

un="$(uname)"
case "${un}" in
  Linux)
    ostype=linux
    homebrew_prefix_default=/home/linuxbrew/.linuxbrew
    ;;
  Darwin)
    ostype=macos
    if [[ "$(uname -m)" == "arm64" ]]
    then
      homebrew_prefix_default=/opt/homebrew
    else
      homebrew_prefix_default=/usr/local
    fi
    realpath() {
      cd "$(dirname "$1")" && echo "$(pwd -P)/$(basename "$1")"
    }
    ;;
  *)
    abort "Unsupported system type '${un}'"
    ;;
esac

# string formatters
if [[ -t 1 ]]
then
  tty_escape() { printf "\033[%sm" "$1"; }
else
  tty_escape() { :; }
fi
tty_mkbold() { tty_escape "1;${1:-39}"; }
tty_blue="$(tty_mkbold 34)"
tty_red="$(tty_mkbold 31)"
tty_bold="$(tty_mkbold 39)"
tty_reset="$(tty_escape 0)"

unset HAVE_SUDO_ACCESS # unset this from the environment

have_sudo_access() {
  if [[ ! -x "/usr/bin/sudo" ]]
  then
    return 1
  fi

  local -a SUDO=("/usr/bin/sudo")
  if [[ -n "${SUDO_ASKPASS-}" ]]
  then
    SUDO+=("-A")
  fi

  if [[ -z "${HAVE_SUDO_ACCESS-}" ]]
  then
    "${SUDO[@]}" -l mkdir &>/dev/null
    HAVE_SUDO_ACCESS="$?"
  fi

  if [[ -z "${HOMEBREW_ON_LINUX-}" ]] && [[ "${HAVE_SUDO_ACCESS}" -ne 0 ]]
  then
    abort "Need sudo access on macOS (e.g. the user ${USER} needs to be an administrator)!"
  fi

  return "${HAVE_SUDO_ACCESS}"
}

shell_join() {
  local arg
  printf "%s" "$1"
  shift
  for arg in "$@"
  do
    printf " "
    printf "%s" "${arg// /\ }"
  done
}

resolved_pathname() { realpath "$1"; }

pretty_print_pathnames() {
  local p
  for p in "$@"
  do
    if [[ -L "${p}" ]]
    then
      printf '%s -> %s\n' "${p}" "$(resolved_pathname "${p}")"
    elif [[ -d "${p}" ]]
    then
      echo "${p}/"
    else
      echo "${p}"
    fi
  done
}

chomp() {
  printf "%s" "${1/"$'\n'"/}"
}

ohai() {
  printf "${tty_blue}==>${tty_bold} %s${tty_reset}\n" "$(shell_join "$@")"
}

warn() {
  printf "${tty_red}Warning${tty_reset}: %s\n" "$(chomp "$1")"
}

execute() {
  if ! "$@"
  then
    abort "$(printf "Failed during: %s" "$(shell_join "$@")")"
  fi
}

execute_sudo() {
  local -a args=("$@")
  if have_sudo_access
  then
    if [[ -n "${SUDO_ASKPASS-}" ]]
    then
      args=("-A" "${args[@]}")
    fi
    ohai "/usr/bin/sudo" "${args[@]}"
    system "/usr/bin/sudo" "${args[@]}"
  else
    ohai "${args[@]}"
    system "${args[@]}"
  fi
}

system() {
  if ! "$@"
  then
    warn "Failed during: $(shell_join "$@")"
    failed=true
  fi
}

####################################################################### script

homebrew_prefix_candidates=()

usage() {
  cat <<EOS
Homebrew Uninstaller
Usage: $0 [options]
    -p, --path=PATH  Sets Homebrew prefix. Defaults to ${homebrew_prefix_default}.
        --skip-cache-and-logs
                     Skips removal of HOMEBREW_CACHE and HOMEBREW_LOGS.
    -f, --force      Uninstall without prompting.
    -q, --quiet      Suppress all output.
    -n, --dry-run    Simulate uninstall but dont remove anything.
    -h, --help       Display this message.
EOS
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]
do
  case "$1" in
    -p*) homebrew_prefix_candidates+=("${1#-p}") ;;
    --path=*) homebrew_prefix_candidates+=("${1#--path=}") ;;
    --skip-cache-and-logs) opt_skip_cache_and_logs=1 ;;
    -f | --force) opt_force=1 ;;
    -q | --quiet) opt_quiet=1 ;;
    -d | -n | --dry-run) opt_dry_run=1 ;;
    -h | --help) usage ;;
    *)
      warn "Unrecognized option: '$1'"
      usage 1
      ;;
  esac
  shift
done

# Attempt to locate Homebrew unless `--path` is passed
if [[ "${#homebrew_prefix_candidates[@]}" -eq 0 ]]
then
  prefix="$(brew --prefix)"
  [[ -n "${prefix}" ]] && homebrew_prefix_candidates+=("${prefix}")
  prefix="$(command -v brew)" || prefix=""
  [[ -n "${prefix}" ]] && homebrew_prefix_candidates+=("$(dirname "$(dirname "$(strip_s "${prefix}")")")")
  homebrew_prefix_candidates+=("${homebrew_prefix_default}") # Homebrew default path
  homebrew_prefix_candidates+=("${HOME}/.linuxbrew")         # Linuxbrew default path
fi

HOMEBREW_PREFIX="$(
  for p in "${homebrew_prefix_candidates[@]}"
  do
    [[ -d "${p}" ]] || continue
    [[ ${p} == "${homebrew_prefix_default}" && -d "${p}/Homebrew/.git" ]] && echo "${p}" && break
    [[ -d "${p}/.git" || -x "${p}/bin/brew" ]] && echo "${p}" && break
  done
)"
[[ -n "${HOMEBREW_PREFIX}" ]] || abort "Failed to locate Homebrew!"

if [[ -d "${HOMEBREW_PREFIX}/.git" ]]
then
  HOMEBREW_REPOSITORY="$(dirname "$(realpath "${HOMEBREW_PREFIX}/.git")")"
elif [[ -x "${HOMEBREW_PREFIX}/bin/brew" ]]
then
  HOMEBREW_REPOSITORY="$(dirname "$(dirname "$(realpath "${HOMEBREW_PREFIX}/bin/brew")")")"
else
  abort "Failed to locate Homebrew!"
fi

if [[ -d "${HOMEBREW_PREFIX}/Cellar" ]]
then
  HOMEBREW_CELLAR="${HOMEBREW_PREFIX}/Cellar"
else
  HOMEBREW_CELLAR="${HOMEBREW_REPOSITORY}/Cellar"
fi

if [[ -s "${HOMEBREW_REPOSITORY}/.gitignore" ]]
then
  gitignore="$(<"${HOMEBREW_REPOSITORY}/.gitignore")"
else
  gitignore="$(curl -fsSL https://raw.githubusercontent.com/Homebrew/brew/HEAD/.gitignore)"
fi
[[ -n "${gitignore}" ]] || abort "Failed to fetch Homebrew .gitignore!"

{
  while read -r l
  do
    [[ "${l}" == \!* ]] || continue
    l="${l#\!}"
    l="${l#/}"
    [[ "${l}" == @(bin|share|share/doc) ]] && echo "REJECT: ${l}" >&2 && continue
    echo "${HOMEBREW_REPOSITORY}/${l}"
  done <<<"${gitignore}"

  if [[ "${HOMEBREW_PREFIX}" != "${HOMEBREW_REPOSITORY}" ]]
  then
    echo "${HOMEBREW_REPOSITORY}"
    directories=(
      bin/brew
      etc/bash_completion.d/brew
      share/doc/homebrew
      share/man/man1/brew.1
      share/man/man1/brew-cask.1
      share/man/man1/README.md
      share/zsh/site-functions/_brew
      share/zsh/site-functions/_brew_cask
      share/fish/vendor_completions.d/brew.fish
      var/homebrew
    )
    for p in "${directories[@]}"
    do
      echo "${HOMEBREW_PREFIX}/${p}"
    done
  else
    echo "${HOMEBREW_REPOSITORY}/.git"
  fi
  echo "${HOMEBREW_CELLAR}"
  echo "${HOMEBREW_PREFIX}/Caskroom"

  [[ -n ${opt_skip_cache_and_logs} ]] || cat <<-EOS
${HOME}/Library/Caches/Homebrew
${HOME}/Library/Logs/Homebrew
/Library/Caches/Homebrew
${HOME}/.cache/Homebrew
${HOMEBREW_CACHE:-}
${HOMEBREW_LOGS:-}
EOS

  if [[ "${ostype}" == macos ]]
  then
    dir_children "/Applications" "${HOME}/Applications" | while read -r p2; do
      [[ $(resolved_pathname "${p2}") == "${HOMEBREW_CELLAR}"/* ]] && echo "${p2}"
    done
  fi
} | while read -r l; do
  [[ -e "${l}" ]] && echo "${l}"
done | sort -u >"${tmpdir}/homebrew_files"
homebrew_files=()
while read -r l
do
  homebrew_files+=("${l}")
done <"${tmpdir}/homebrew_files"

if [[ -z "${opt_quiet}" ]]
then
  dry_str="${opt_dry_run:+would}"
  warn "This script ${dry_str:-will} remove:"
  pretty_print_pathnames "${homebrew_files[@]}"
fi

if [[ -t 0 && -z "${opt_force}" && -z "${opt_dry_run}" ]]
then
  read -rp "Are you sure you want to uninstall Homebrew? This will remove your installed packages! [y/N] "
  [[ "${REPLY}" == [yY]* ]] || abort
fi

[[ -n "${opt_quiet}" ]] || ohai "Removing Homebrew installation..."
paths=()
for p in Frameworks bin etc include lib opt sbin share var
do
  p="${HOMEBREW_PREFIX}/${p}"
  [[ -e "${p}" ]] && paths+=("${p}")
done
if [[ "${#paths[@]}" -gt 0 ]]
then
  if [[ "${ostype}" == macos ]]
  then
    args=(-E "${paths[@]}" -regex '.*/info/([^.][^/]*\.info|dir)')
  else
    args=("${paths[@]}" -regextype posix-extended -regex '.*/info/([^.][^/]*\.info|dir)')
  fi
  if [[ -n "${opt_dry_run}" ]]
  then
    args+=(-print)
    echo "Would delete:"
  else
    args+=(-exec /bin/bash -c)
    args+=("/usr/bin/install-info --delete --quiet {} \"\$(dirname {})/dir\"")
    args+=(';')
  fi
  system /usr/bin/find "${args[@]}"
  args=("${paths[@]}" -type l -lname '*/Cellar/*')
  if [[ -n "${opt_dry_run}" ]]
  then
    args+=(-print)
  else
    args+=(-exec unlink '{}' ';')
  fi
  [[ -n "${opt_dry_run}" ]] && echo "Would delete:"
  system /usr/bin/find "${args[@]}"
fi

for file in "${homebrew_files[@]}"
do
  if [[ -n "${opt_dry_run}" ]]
  then
    echo "Would delete ${file}"
  else
    if ! err="$(rm -fr "${file}" 2>&1)"
    then
      warn "Failed to delete ${file}"
      echo "${err}"
    fi
  fi
done

[[ -n "${opt_quiet}" ]] || ohai "Removing empty directories..."
paths=()
for p in bin etc include lib opt sbin share var Caskroom Cellar Homebrew Frameworks
do
  p="${HOMEBREW_PREFIX}/${p}"
  [[ -e "${p}" ]] && paths+=("${p}")
done
if [[ "${#paths[@]}" -gt 0 ]]
then
  if [[ "${ostype}" == macos ]]
  then
    args=("${paths[@]}" -name .DS_Store)
    if [[ -n "${opt_dry_run}" ]]
    then
      args+=(-print)
      echo "Would delete:"
    else
      args+=(-delete)
    fi
    execute_sudo /usr/bin/find "${args[@]}"
  fi
  args=("${paths[@]}" -depth -type d -empty)
  if [[ -n "${opt_dry_run}" ]]
  then
    args+=(-print)
    echo "Would remove directories:"
  else
    args+=(-exec rmdir '{}' ';')
  fi
  execute_sudo /usr/bin/find "${args[@]}"
fi

[[ -n "${opt_dry_run}" ]] && exit
if [[ "${HOMEBREW_PREFIX}" != "${homebrew_prefix_default}" && -e "${HOMEBREW_PREFIX}" ]]
then
  execute_sudo rmdir "${HOMEBREW_PREFIX}"
fi
if [[ "${HOMEBREW_PREFIX}" != "${HOMEBREW_REPOSITORY}" && -e "${HOMEBREW_REPOSITORY}" ]]
then
  execute_sudo rmdir "${HOMEBREW_REPOSITORY}"
fi

if [[ -z "${opt_quiet}" ]]
then
  if [[ "${failed}" == true ]]
  then
    warn "Homebrew partially uninstalled (but there were steps that failed)!"
    echo "To finish uninstalling rerun this script with \`sudo\`."
  else
    ohai "Homebrew uninstalled!"
  fi
fi

dir_children "${HOMEBREW_REPOSITORY}" "${HOMEBREW_PREFIX}" |
  sort -u >"${tmpdir}/residual_files"

if [[ -s "${tmpdir}/residual_files" && -z "${opt_quiet}" ]]
then
  echo "The following possible Homebrew files were not deleted:"
  while read -r f
  do
    pretty_print_pathnames "${f}"
  done <"${tmpdir}/residual_files"
  echo -e "You may wish to remove them yourself.\n"
fi

[[ "${failed}" != true ]]
}

install_homebrew(){
abort() {
  printf "%s\n" "$@"
  exit 1
}

# Fail fast with a concise message when not using bash
# Single brackets are needed here for POSIX compatibility
# shellcheck disable=SC2292
if [ -z "${BASH_VERSION:-}" ]
then
  abort "Bash is required to interpret this script."
fi

# Check if script is run non-interactively (e.g. CI)
# If it is run non-interactively we should not prompt for passwords.
if [[ ! -t 0 || -n "${CI-}" ]]
then
  NONINTERACTIVE=1
fi

# First check OS.
OS="$(uname)"
if [[ "${OS}" == "Linux" ]]
then
  HOMEBREW_ON_LINUX=1
elif [[ "${OS}" != "Darwin" ]]
then
  abort "Homebrew is only supported on macOS and Linux."
fi

# Required installation paths. To install elsewhere (which is unsupported)
# you can untar https://github.com/Homebrew/brew/tarball/master
# anywhere you like.
if [[ -z "${HOMEBREW_ON_LINUX-}" ]]
then
  UNAME_MACHINE="$(/usr/bin/uname -m)"

  if [[ "${UNAME_MACHINE}" == "arm64" ]]
  then
    # On ARM macOS, this script installs to /opt/homebrew only
    HOMEBREW_PREFIX="/opt/homebrew"
    HOMEBREW_REPOSITORY="${HOMEBREW_PREFIX}"
  else
    # On Intel macOS, this script installs to /usr/local only
    HOMEBREW_PREFIX="/usr/local"
    HOMEBREW_REPOSITORY="${HOMEBREW_PREFIX}/Homebrew"
  fi
  HOMEBREW_CACHE="${HOME}/Library/Caches/Homebrew"

  STAT_PRINTF=("stat" "-f")
  PERMISSION_FORMAT="%A"
  CHOWN=("/usr/sbin/chown")
  CHGRP=("/usr/bin/chgrp")
  GROUP="admin"
  TOUCH=("/usr/bin/touch")
else
  UNAME_MACHINE="$(uname -m)"

  # On Linux, it installs to /home/linuxbrew/.linuxbrew if you have sudo access
  # and ~/.linuxbrew (which is unsupported) if run interactively.
  HOMEBREW_PREFIX_DEFAULT="/home/linuxbrew/.linuxbrew"
  HOMEBREW_CACHE="${HOME}/.cache/Homebrew"

  STAT_PRINTF=("stat" "--printf")
  PERMISSION_FORMAT="%a"
  CHOWN=("/bin/chown")
  CHGRP=("/bin/chgrp")
  GROUP="$(id -gn)"
  TOUCH=("/bin/touch")
fi
CHMOD=("/bin/chmod")
MKDIR=("/bin/mkdir" "-p")
HOMEBREW_BREW_DEFAULT_GIT_REMOTE="https://github.com/Homebrew/brew"
HOMEBREW_CORE_DEFAULT_GIT_REMOTE="https://github.com/Homebrew/homebrew-core"

# Use remote URLs of Homebrew repositories from environment if set.
HOMEBREW_BREW_GIT_REMOTE="${HOMEBREW_BREW_GIT_REMOTE:-"${HOMEBREW_BREW_DEFAULT_GIT_REMOTE}"}"
HOMEBREW_CORE_GIT_REMOTE="${HOMEBREW_CORE_GIT_REMOTE:-"${HOMEBREW_CORE_DEFAULT_GIT_REMOTE}"}"
# The URLs with and without the '.git' suffix are the same Git remote. Do not prompt.
if [[ "${HOMEBREW_BREW_GIT_REMOTE}" == "${HOMEBREW_BREW_DEFAULT_GIT_REMOTE}.git" ]]
then
  HOMEBREW_BREW_GIT_REMOTE="${HOMEBREW_BREW_DEFAULT_GIT_REMOTE}"
fi
if [[ "${HOMEBREW_CORE_GIT_REMOTE}" == "${HOMEBREW_CORE_DEFAULT_GIT_REMOTE}.git" ]]
then
  HOMEBREW_CORE_GIT_REMOTE="${HOMEBREW_CORE_DEFAULT_GIT_REMOTE}"
fi
export HOMEBREW_{BREW,CORE}_GIT_REMOTE

# TODO: bump version when new macOS is released or announced
MACOS_NEWEST_UNSUPPORTED="13.0"
# TODO: bump version when new macOS is released
MACOS_OLDEST_SUPPORTED="10.15"

# For Homebrew on Linux
REQUIRED_RUBY_VERSION=2.6    # https://github.com/Homebrew/brew/pull/6556
REQUIRED_GLIBC_VERSION=2.13  # https://docs.brew.sh/Homebrew-on-Linux#requirements
REQUIRED_CURL_VERSION=7.41.0 # HOMEBREW_MINIMUM_CURL_VERSION in brew.sh in Homebrew/brew
REQUIRED_GIT_VERSION=2.7.0   # HOMEBREW_MINIMUM_GIT_VERSION in brew.sh in Homebrew/brew

# no analytics during installation
export HOMEBREW_NO_ANALYTICS_THIS_RUN=1
export HOMEBREW_NO_ANALYTICS_MESSAGE_OUTPUT=1

# string formatters
if [[ -t 1 ]]
then
  tty_escape() { printf "\033[%sm" "$1"; }
else
  tty_escape() { :; }
fi
tty_mkbold() { tty_escape "1;$1"; }
tty_underline="$(tty_escape "4;39")"
tty_blue="$(tty_mkbold 34)"
tty_red="$(tty_mkbold 31)"
tty_bold="$(tty_mkbold 39)"
tty_reset="$(tty_escape 0)"

unset HAVE_SUDO_ACCESS # unset this from the environment

have_sudo_access() {
  if [[ ! -x "/usr/bin/sudo" ]]
  then
    return 1
  fi

  local -a SUDO=("/usr/bin/sudo")
  if [[ -n "${SUDO_ASKPASS-}" ]]
  then
    SUDO+=("-A")
  elif [[ -n "${NONINTERACTIVE-}" ]]
  then
    SUDO+=("-n")
  fi

  if [[ -z "${HAVE_SUDO_ACCESS-}" ]]
  then
    if [[ -n "${NONINTERACTIVE-}" ]]
    then
      "${SUDO[@]}" -l mkdir &>/dev/null
    else
      "${SUDO[@]}" -v && "${SUDO[@]}" -l mkdir &>/dev/null
    fi
    HAVE_SUDO_ACCESS="$?"
  fi

  if [[ -z "${HOMEBREW_ON_LINUX-}" ]] && [[ "${HAVE_SUDO_ACCESS}" -ne 0 ]]
  then
    abort "Need sudo access on macOS (e.g. the user ${USER} needs to be an Administrator)!"
  fi

  return "${HAVE_SUDO_ACCESS}"
}

shell_join() {
  local arg
  printf "%s" "$1"
  shift
  for arg in "$@"
  do
    printf " "
    printf "%s" "${arg// /\ }"
  done
}

chomp() {
  printf "%s" "${1/"$'\n'"/}"
}

ohai() {
  printf "${tty_blue}==>${tty_bold} %s${tty_reset}\n" "$(shell_join "$@")"
}

warn() {
  printf "${tty_red}Warning${tty_reset}: %s\n" "$(chomp "$1")"
}

execute() {
  if ! "$@"
  then
    abort "$(printf "Failed during: %s" "$(shell_join "$@")")"
  fi
}

execute_sudo() {
  local -a args=("$@")
  if have_sudo_access
  then
    if [[ -n "${SUDO_ASKPASS-}" ]]
    then
      args=("-A" "${args[@]}")
    fi
    ohai "/usr/bin/sudo" "${args[@]}"
    execute "/usr/bin/sudo" "${args[@]}"
  else
    ohai "${args[@]}"
    execute "${args[@]}"
  fi
}

getc() {
  local save_state
  save_state="$(/bin/stty -g)"
  /bin/stty raw -echo
  IFS='' read -r -n 1 -d '' "$@"
  /bin/stty "${save_state}"
}

ring_bell() {
  # Use the shell's audible bell.
  if [[ -t 1 ]]
  then
    printf "\a"
  fi
}

wait_for_user() {
  local c
  echo
  echo "Press ${tty_bold}RETURN${tty_reset} to continue or any other key to abort:"
  getc c
  # we test for \r and \n because some stuff does \r instead
  if ! [[ "${c}" == $'\r' || "${c}" == $'\n' ]]
  then
    exit 1
  fi
}

major_minor() {
  echo "${1%%.*}.$(
    x="${1#*.}"
    echo "${x%%.*}"
  )"
}

version_gt() {
  [[ "${1%.*}" -gt "${2%.*}" ]] || [[ "${1%.*}" -eq "${2%.*}" && "${1#*.}" -gt "${2#*.}" ]]
}
version_ge() {
  [[ "${1%.*}" -gt "${2%.*}" ]] || [[ "${1%.*}" -eq "${2%.*}" && "${1#*.}" -ge "${2#*.}" ]]
}
version_lt() {
  [[ "${1%.*}" -lt "${2%.*}" ]] || [[ "${1%.*}" -eq "${2%.*}" && "${1#*.}" -lt "${2#*.}" ]]
}

should_install_command_line_tools() {
  if [[ -n "${HOMEBREW_ON_LINUX-}" ]]
  then
    return 1
  fi

  if version_gt "${macos_version}" "10.13"
  then
    ! [[ -e "/Library/Developer/CommandLineTools/usr/bin/git" ]]
  else
    ! [[ -e "/Library/Developer/CommandLineTools/usr/bin/git" ]] ||
      ! [[ -e "/usr/include/iconv.h" ]]
  fi
}

get_permission() {
  "${STAT_PRINTF[@]}" "${PERMISSION_FORMAT}" "$1"
}

user_only_chmod() {
  [[ -d "$1" ]] && [[ "$(get_permission "$1")" != 75[0145] ]]
}

exists_but_not_writable() {
  [[ -e "$1" ]] && ! [[ -r "$1" && -w "$1" && -x "$1" ]]
}

get_owner() {
  "${STAT_PRINTF[@]}" "%u" "$1"
}

file_not_owned() {
  [[ "$(get_owner "$1")" != "$(id -u)" ]]
}

get_group() {
  "${STAT_PRINTF[@]}" "%g" "$1"
}

file_not_grpowned() {
  [[ " $(id -G "${USER}") " != *" $(get_group "$1") "* ]]
}

# Please sync with 'test_ruby()' in 'Library/Homebrew/utils/ruby.sh' from the Homebrew/brew repository.
test_ruby() {
  if [[ ! -x "$1" ]]
  then
    return 1
  fi

  "$1" --enable-frozen-string-literal --disable=gems,did_you_mean,rubyopt -rrubygems -e \
    "abort if Gem::Version.new(RUBY_VERSION.to_s.dup).to_s.split('.').first(2) != \
              Gem::Version.new('${REQUIRED_RUBY_VERSION}').to_s.split('.').first(2)" 2>/dev/null
}

test_curl() {
  if [[ ! -x "$1" ]]
  then
    return 1
  fi

  local curl_version_output curl_name_and_version
  curl_version_output="$("$1" --version 2>/dev/null)"
  curl_name_and_version="${curl_version_output%% (*}"
  version_ge "$(major_minor "${curl_name_and_version##* }")" "$(major_minor "${REQUIRED_CURL_VERSION}")"
}

test_git() {
  if [[ ! -x "$1" ]]
  then
    return 1
  fi

  local git_version_output
  git_version_output="$("$1" --version 2>/dev/null)"
  version_ge "$(major_minor "${git_version_output##* }")" "$(major_minor "${REQUIRED_GIT_VERSION}")"
}

# Search for the given executable in PATH (avoids a dependency on the `which` command)
which() {
  # Alias to Bash built-in command `type -P`
  type -P "$@"
}

# Search PATH for the specified program that satisfies Homebrew requirements
# function which is set above
# shellcheck disable=SC2230
find_tool() {
  if [[ $# -ne 1 ]]
  then
    return 1
  fi

  local executable
  while read -r executable
  do
    if "test_$1" "${executable}"
    then
      echo "${executable}"
      break
    fi
  done < <(which -a "$1")
}

no_usable_ruby() {
  [[ -z "$(find_tool ruby)" ]]
}

outdated_glibc() {
  local glibc_version
  glibc_version="$(ldd --version | head -n1 | grep -o '[0-9.]*$' | grep -o '^[0-9]\+\.[0-9]\+')"
  version_lt "${glibc_version}" "${REQUIRED_GLIBC_VERSION}"
}

if [[ -n "${HOMEBREW_ON_LINUX-}" ]] && no_usable_ruby && outdated_glibc
then
  abort "$(
    cat <<EOABORT
Homebrew requires Ruby ${REQUIRED_RUBY_VERSION} which was not found on your system.
Homebrew portable Ruby requires Glibc version ${REQUIRED_GLIBC_VERSION} or newer,
and your Glibc version is too old. See:
  ${tty_underline}https://docs.brew.sh/Homebrew-on-Linux#requirements${tty_reset}
Please install Ruby ${REQUIRED_RUBY_VERSION} and add its location to your PATH.
EOABORT
  )"
fi

# USER isn't always set so provide a fall back for the installer and subprocesses.
if [[ -z "${USER-}" ]]
then
  USER="$(chomp "$(id -un)")"
  export USER
fi

# Invalidate sudo timestamp before exiting (if it wasn't active before).
if [[ -x /usr/bin/sudo ]] && ! /usr/bin/sudo -n -v 2>/dev/null
then
  trap '/usr/bin/sudo -k' EXIT
fi

# Things can fail later if `pwd` doesn't exist.
# Also sudo prints a warning message for no good reason
cd "/usr" || exit 1

####################################################################### script
if ! command -v git >/dev/null
then
  abort "$(
    cat <<EOABORT
You must install Git before installing Homebrew. See:
  ${tty_underline}https://docs.brew.sh/Installation${tty_reset}
EOABORT
  )"
elif [[ -n "${HOMEBREW_ON_LINUX-}" ]]
then
  USABLE_GIT="$(find_tool git)"
  if [[ -z "${USABLE_GIT}" ]]
  then
    abort "$(
      cat <<EOABORT
The version of Git that was found does not satisfy requirements for Homebrew.
Please install Git ${REQUIRED_GIT_VERSION} or newer and add it to your PATH.
EOABORT
    )"
  elif [[ "${USABLE_GIT}" != /usr/bin/git ]]
  then
    export HOMEBREW_GIT_PATH="${USABLE_GIT}"
    ohai "Found Git: ${HOMEBREW_GIT_PATH}"
  fi
fi

if ! command -v curl >/dev/null
then
  abort "$(
    cat <<EOABORT
You must install cURL before installing Homebrew. See:
  ${tty_underline}https://docs.brew.sh/Installation${tty_reset}
EOABORT
  )"
elif [[ -n "${HOMEBREW_ON_LINUX-}" ]]
then
  USABLE_CURL="$(find_tool curl)"
  if [[ -z "${USABLE_CURL}" ]]
  then
    abort "$(
      cat <<EOABORT
The version of cURL that was found does not satisfy requirements for Homebrew.
Please install cURL ${REQUIRED_CURL_VERSION} or newer and add it to your PATH.
EOABORT
    )"
  elif [[ "${USABLE_CURL}" != /usr/bin/curl ]]
  then
    export HOMEBREW_CURL_PATH="${USABLE_CURL}"
    ohai "Found cURL: ${HOMEBREW_CURL_PATH}"
  fi
fi

# Set HOMEBREW_DEVELOPER on Linux systems where usable Git/cURL is not in /usr/bin
if [[ -n "${HOMEBREW_ON_LINUX-}" && (-n "${HOMEBREW_CURL_PATH-}" || -n "${HOMEBREW_GIT_PATH-}") ]]
then
  ohai "Setting HOMEBREW_DEVELOPER to use Git/cURL not in /usr/bin"
  export HOMEBREW_DEVELOPER=1
fi

# shellcheck disable=SC2016
ohai 'Checking for `sudo` access (which may request your password)...'

if [[ -z "${HOMEBREW_ON_LINUX-}" ]]
then
  have_sudo_access
else
  if [[ -w "${HOMEBREW_PREFIX_DEFAULT}" ]] ||
     [[ -w "/home/linuxbrew" ]] ||
     [[ -w "/home" ]]
  then
    HOMEBREW_PREFIX="${HOMEBREW_PREFIX_DEFAULT}"
  elif [[ -n "${NONINTERACTIVE-}" ]]
  then
    if have_sudo_access
    then
      HOMEBREW_PREFIX="${HOMEBREW_PREFIX_DEFAULT}"
    else
      abort "Insufficient permissions to install Homebrew to \"${HOMEBREW_PREFIX_DEFAULT}\"."
    fi
  else
    trap exit SIGINT
    if ! /usr/bin/sudo -n -v &>/dev/null
    then
      ohai "Select a Homebrew installation directory:"
      echo "- ${tty_bold}Enter your password${tty_reset} to install to ${tty_underline}${HOMEBREW_PREFIX_DEFAULT}${tty_reset} (${tty_bold}recommended${tty_reset})"
      echo "- ${tty_bold}Press Control-D${tty_reset} to install to ${tty_underline}${HOME}/.linuxbrew${tty_reset}"
      echo "- ${tty_bold}Press Control-C${tty_reset} to cancel installation"
    fi
    if have_sudo_access
    then
      HOMEBREW_PREFIX="${HOMEBREW_PREFIX_DEFAULT}"
    else
      HOMEBREW_PREFIX="${HOME}/.linuxbrew"
    fi
    trap - SIGINT
  fi
  HOMEBREW_REPOSITORY="${HOMEBREW_PREFIX}/Homebrew"
fi
HOMEBREW_CORE="${HOMEBREW_REPOSITORY}/Library/Taps/homebrew/homebrew-core"

if [[ "${EUID:-${UID}}" == "0" ]]
then
  # Allow Azure Pipelines/GitHub Actions/Docker/Concourse/Kubernetes to do everything as root (as it's normal there)
  if ! [[ -f /proc/1/cgroup ]] ||
     ! grep -E "azpl_job|actions_job|docker|garden|kubepods" -q /proc/1/cgroup
  then
    abort "Don't run this as root!"
  fi
fi

if [[ -d "${HOMEBREW_PREFIX}" && ! -x "${HOMEBREW_PREFIX}" ]]
then
  abort "$(
    cat <<EOABORT
The Homebrew prefix ${tty_underline}${HOMEBREW_PREFIX}${tty_reset} exists but is not searchable.
If this is not intentional, please restore the default permissions and
try running the installer again:
    sudo chmod 775 ${HOMEBREW_PREFIX}
EOABORT
  )"
fi

if [[ -z "${HOMEBREW_ON_LINUX-}" ]]
then
  # On macOS, support 64-bit Intel and ARM
  if [[ "${UNAME_MACHINE}" != "arm64" ]] && [[ "${UNAME_MACHINE}" != "x86_64" ]]
  then
    abort "Homebrew is only supported on Intel and ARM processors!"
  fi
else
  # On Linux, support only 64-bit Intel
  if [[ "${UNAME_MACHINE}" == "arm64" ]]
  then
    abort "$(
      cat <<EOABORT
Homebrew on Linux is not supported on ARM processors.
You can try an alternate installation method instead:
  ${tty_underline}https://docs.brew.sh/Homebrew-on-Linux#arm${tty_reset}
EOABORT
    )"
  elif [[ "${UNAME_MACHINE}" != "x86_64" ]]
  then
    abort "Homebrew on Linux is only supported on Intel processors!"
  fi
fi

if [[ -z "${HOMEBREW_ON_LINUX-}" ]]
then
  macos_version="$(major_minor "$(/usr/bin/sw_vers -productVersion)")"
  if version_lt "${macos_version}" "10.7"
  then
    abort "$(
      cat <<EOABORT
Your Mac OS X version is too old. See:
  ${tty_underline}https://github.com/mistydemeo/tigerbrew${tty_reset}
EOABORT
    )"
  elif version_lt "${macos_version}" "10.10"
  then
    abort "Your OS X version is too old."
  elif version_ge "${macos_version}" "${MACOS_NEWEST_UNSUPPORTED}" ||
       version_lt "${macos_version}" "${MACOS_OLDEST_SUPPORTED}"
  then
    who="We"
    what=""
    if version_ge "${macos_version}" "${MACOS_NEWEST_UNSUPPORTED}"
    then
      what="pre-release version"
    else
      who+=" (and Apple)"
      what="old version"
    fi
    ohai "You are using macOS ${macos_version}."
    ohai "${who} do not provide support for this ${what}."

    echo "$(
      cat <<EOS
This installation may not succeed.
After installation, you will encounter build failures with some formulae.
Please create pull requests instead of asking for help on Homebrew\'s GitHub,
Twitter or any other official channels. You are responsible for resolving any
issues you experience while you are running this ${what}.
EOS
    )
" | tr -d "\\"
  fi
fi

ohai "This script will install:"
echo "${HOMEBREW_PREFIX}/bin/brew"
echo "${HOMEBREW_PREFIX}/share/doc/homebrew"
echo "${HOMEBREW_PREFIX}/share/man/man1/brew.1"
echo "${HOMEBREW_PREFIX}/share/zsh/site-functions/_brew"
echo "${HOMEBREW_PREFIX}/etc/bash_completion.d/brew"
echo "${HOMEBREW_REPOSITORY}"

# Keep relatively in sync with
# https://github.com/Homebrew/brew/blob/master/Library/Homebrew/keg.rb
directories=(
  bin etc include lib sbin share opt var
  Frameworks
  etc/bash_completion.d lib/pkgconfig
  share/aclocal share/doc share/info share/locale share/man
  share/man/man1 share/man/man2 share/man/man3 share/man/man4
  share/man/man5 share/man/man6 share/man/man7 share/man/man8
  var/log var/homebrew var/homebrew/linked
  bin/brew
)
group_chmods=()
for dir in "${directories[@]}"
do
  if exists_but_not_writable "${HOMEBREW_PREFIX}/${dir}"
  then
    group_chmods+=("${HOMEBREW_PREFIX}/${dir}")
  fi
done

# zsh refuses to read from these directories if group writable
directories=(share/zsh share/zsh/site-functions)
zsh_dirs=()
for dir in "${directories[@]}"
do
  zsh_dirs+=("${HOMEBREW_PREFIX}/${dir}")
done

directories=(
  bin etc include lib sbin share var opt
  share/zsh share/zsh/site-functions
  var/homebrew var/homebrew/linked
  Cellar Caskroom Frameworks
)
mkdirs=()
for dir in "${directories[@]}"
do
  if ! [[ -d "${HOMEBREW_PREFIX}/${dir}" ]]
  then
    mkdirs+=("${HOMEBREW_PREFIX}/${dir}")
  fi
done

user_chmods=()
mkdirs_user_only=()
if [[ "${#zsh_dirs[@]}" -gt 0 ]]
then
  for dir in "${zsh_dirs[@]}"
  do
    if [[ ! -d "${dir}" ]]
    then
      mkdirs_user_only+=("${dir}")
    elif user_only_chmod "${dir}"
    then
      user_chmods+=("${dir}")
    fi
  done
fi

chmods=()
if [[ "${#group_chmods[@]}" -gt 0 ]]
then
  chmods+=("${group_chmods[@]}")
fi
if [[ "${#user_chmods[@]}" -gt 0 ]]
then
  chmods+=("${user_chmods[@]}")
fi

chowns=()
chgrps=()
if [[ "${#chmods[@]}" -gt 0 ]]
then
  for dir in "${chmods[@]}"
  do
    if file_not_owned "${dir}"
    then
      chowns+=("${dir}")
    fi
    if file_not_grpowned "${dir}"
    then
      chgrps+=("${dir}")
    fi
  done
fi

if [[ "${#group_chmods[@]}" -gt 0 ]]
then
  ohai "The following existing directories will be made group writable:"
  printf "%s\n" "${group_chmods[@]}"
fi
if [[ "${#user_chmods[@]}" -gt 0 ]]
then
  ohai "The following existing directories will be made writable by user only:"
  printf "%s\n" "${user_chmods[@]}"
fi
if [[ "${#chowns[@]}" -gt 0 ]]
then
  ohai "The following existing directories will have their owner set to ${tty_underline}${USER}${tty_reset}:"
  printf "%s\n" "${chowns[@]}"
fi
if [[ "${#chgrps[@]}" -gt 0 ]]
then
  ohai "The following existing directories will have their group set to ${tty_underline}${GROUP}${tty_reset}:"
  printf "%s\n" "${chgrps[@]}"
fi
if [[ "${#mkdirs[@]}" -gt 0 ]]
then
  ohai "The following new directories will be created:"
  printf "%s\n" "${mkdirs[@]}"
fi

if should_install_command_line_tools
then
  ohai "The Xcode Command Line Tools will be installed."
fi

non_default_repos=""
additional_shellenv_commands=()
if [[ "${HOMEBREW_BREW_DEFAULT_GIT_REMOTE}" != "${HOMEBREW_BREW_GIT_REMOTE}" ]]
then
  ohai "HOMEBREW_BREW_GIT_REMOTE is set to a non-default URL:"
  echo "${tty_underline}${HOMEBREW_BREW_GIT_REMOTE}${tty_reset} will be used as the Homebrew/brew Git remote."
  non_default_repos="Homebrew/brew"
  additional_shellenv_commands+=("export HOMEBREW_BREW_GIT_REMOTE=\"${HOMEBREW_BREW_GIT_REMOTE}\"")
fi

if [[ "${HOMEBREW_CORE_DEFAULT_GIT_REMOTE}" != "${HOMEBREW_CORE_GIT_REMOTE}" ]]
then
  ohai "HOMEBREW_CORE_GIT_REMOTE is set to a non-default URL:"
  echo "${tty_underline}${HOMEBREW_CORE_GIT_REMOTE}${tty_reset} will be used as the Homebrew/homebrew-core Git remote."
  non_default_repos="${non_default_repos:-}${non_default_repos:+ and }Homebrew/homebrew-core"
  additional_shellenv_commands+=("export HOMEBREW_CORE_GIT_REMOTE=\"${HOMEBREW_CORE_GIT_REMOTE}\"")
fi

if [[ -z "${NONINTERACTIVE-}" ]]
then
  ring_bell
  wait_for_user
fi

if [[ -d "${HOMEBREW_PREFIX}" ]]
then
  if [[ "${#chmods[@]}" -gt 0 ]]
  then
    execute_sudo "${CHMOD[@]}" "u+rwx" "${chmods[@]}"
  fi
  if [[ "${#group_chmods[@]}" -gt 0 ]]
  then
    execute_sudo "${CHMOD[@]}" "g+rwx" "${group_chmods[@]}"
  fi
  if [[ "${#user_chmods[@]}" -gt 0 ]]
  then
    execute_sudo "${CHMOD[@]}" "go-w" "${user_chmods[@]}"
  fi
  if [[ "${#chowns[@]}" -gt 0 ]]
  then
    execute_sudo "${CHOWN[@]}" "${USER}" "${chowns[@]}"
  fi
  if [[ "${#chgrps[@]}" -gt 0 ]]
  then
    execute_sudo "${CHGRP[@]}" "${GROUP}" "${chgrps[@]}"
  fi
else
  execute_sudo "${MKDIR[@]}" "${HOMEBREW_PREFIX}"
  if [[ -z "${HOMEBREW_ON_LINUX-}" ]]
  then
    execute_sudo "${CHOWN[@]}" "root:wheel" "${HOMEBREW_PREFIX}"
  else
    execute_sudo "${CHOWN[@]}" "${USER}:${GROUP}" "${HOMEBREW_PREFIX}"
  fi
fi

if [[ "${#mkdirs[@]}" -gt 0 ]]
then
  execute_sudo "${MKDIR[@]}" "${mkdirs[@]}"
  execute_sudo "${CHMOD[@]}" "ug=rwx" "${mkdirs[@]}"
  if [[ "${#mkdirs_user_only[@]}" -gt 0 ]]
  then
    execute_sudo "${CHMOD[@]}" "go-w" "${mkdirs_user_only[@]}"
  fi
  execute_sudo "${CHOWN[@]}" "${USER}" "${mkdirs[@]}"
  execute_sudo "${CHGRP[@]}" "${GROUP}" "${mkdirs[@]}"
fi

if ! [[ -d "${HOMEBREW_REPOSITORY}" ]]
then
  execute_sudo "${MKDIR[@]}" "${HOMEBREW_REPOSITORY}"
fi
execute_sudo "${CHOWN[@]}" "-R" "${USER}:${GROUP}" "${HOMEBREW_REPOSITORY}"

if ! [[ -d "${HOMEBREW_CACHE}" ]]
then
  if [[ -z "${HOMEBREW_ON_LINUX-}" ]]
  then
    execute_sudo "${MKDIR[@]}" "${HOMEBREW_CACHE}"
  else
    execute "${MKDIR[@]}" "${HOMEBREW_CACHE}"
  fi
fi
if exists_but_not_writable "${HOMEBREW_CACHE}"
then
  execute_sudo "${CHMOD[@]}" "g+rwx" "${HOMEBREW_CACHE}"
fi
if file_not_owned "${HOMEBREW_CACHE}"
then
  execute_sudo "${CHOWN[@]}" "-R" "${USER}" "${HOMEBREW_CACHE}"
fi
if file_not_grpowned "${HOMEBREW_CACHE}"
then
  execute_sudo "${CHGRP[@]}" "-R" "${GROUP}" "${HOMEBREW_CACHE}"
fi
if [[ -d "${HOMEBREW_CACHE}" ]]
then
  execute "${TOUCH[@]}" "${HOMEBREW_CACHE}/.cleaned"
fi

if should_install_command_line_tools && version_ge "${macos_version}" "10.13"
then
  ohai "Searching online for the Command Line Tools"
  # This temporary file prompts the 'softwareupdate' utility to list the Command Line Tools
  clt_placeholder="/tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress"
  execute_sudo "${TOUCH[@]}" "${clt_placeholder}"

  clt_label_command="/usr/sbin/softwareupdate -l |
                      grep -B 1 -E 'Command Line Tools' |
                      awk -F'*' '/^ *\\*/ {print \$2}' |
                      sed -e 's/^ *Label: //' -e 's/^ *//' |
                      sort -V |
                      tail -n1"
  clt_label="$(chomp "$(/bin/bash -c "${clt_label_command}")")"

  if [[ -n "${clt_label}" ]]
  then
    ohai "Installing ${clt_label}"
    execute_sudo "/usr/sbin/softwareupdate" "-i" "${clt_label}"
    execute_sudo "/bin/rm" "-f" "${clt_placeholder}"
    execute_sudo "/usr/bin/xcode-select" "--switch" "/Library/Developer/CommandLineTools"
  fi
fi

# Headless install may have failed, so fallback to original 'xcode-select' method
if should_install_command_line_tools && test -t 0
then
  ohai "Installing the Command Line Tools (expect a GUI popup):"
  execute_sudo "/usr/bin/xcode-select" "--install"
  echo "Press any key when the installation has completed."
  getc
  execute_sudo "/usr/bin/xcode-select" "--switch" "/Library/Developer/CommandLineTools"
fi

if [[ -z "${HOMEBREW_ON_LINUX-}" ]] && ! output="$(/usr/bin/xcrun clang 2>&1)" && [[ "${output}" == *"license"* ]]
then
  abort "$(
    cat <<EOABORT
You have not agreed to the Xcode license.
Before running the installer again please agree to the license by opening
Xcode.app or running:
    sudo xcodebuild -license
EOABORT
  )"
fi

ohai "Downloading and installing Homebrew..."
(
  cd "${HOMEBREW_REPOSITORY}" >/dev/null || return

  # we do it in four steps to avoid merge errors when reinstalling
  execute "git" "init" "-q"

  # "git remote add" will fail if the remote is defined in the global config
  execute "git" "config" "remote.origin.url" "${HOMEBREW_BREW_GIT_REMOTE}"
  execute "git" "config" "remote.origin.fetch" "+refs/heads/*:refs/remotes/origin/*"

  # ensure we don't munge line endings on checkout
  execute "git" "config" "core.autocrlf" "false"

  execute "git" "fetch" "--force" "origin"
  execute "git" "fetch" "--force" "--tags" "origin"

  execute "git" "reset" "--hard" "origin/master"

  if [[ "${HOMEBREW_REPOSITORY}" != "${HOMEBREW_PREFIX}" ]]
  then
    if [[ "${HOMEBREW_REPOSITORY}" == "${HOMEBREW_PREFIX}/Homebrew" ]]
    then
      execute "ln" "-sf" "../Homebrew/bin/brew" "${HOMEBREW_PREFIX}/bin/brew"
    else
      abort "The Homebrew/brew repository should be placed in the Homebrew prefix directory."
    fi
  fi

  if [[ ! -d "${HOMEBREW_CORE}" ]]
  then
    ohai "Tapping homebrew/core"
    (
      execute "${MKDIR[@]}" "${HOMEBREW_CORE}"
      cd "${HOMEBREW_CORE}" >/dev/null || return

      execute "git" "init" "-q"
      execute "git" "config" "remote.origin.url" "${HOMEBREW_CORE_GIT_REMOTE}"
      execute "git" "config" "remote.origin.fetch" "+refs/heads/*:refs/remotes/origin/*"
      execute "git" "config" "core.autocrlf" "false"
      execute "git" "fetch" "--force" "origin" "refs/heads/master:refs/remotes/origin/master"
      execute "git" "remote" "set-head" "origin" "--auto" >/dev/null
      execute "git" "reset" "--hard" "origin/master"

      cd "${HOMEBREW_REPOSITORY}" >/dev/null || return
    ) || exit 1
  fi

  execute "${HOMEBREW_PREFIX}/bin/brew" "update" "--force" "--quiet"
) || exit 1

if [[ ":${PATH}:" != *":${HOMEBREW_PREFIX}/bin:"* ]]
then
  warn "${HOMEBREW_PREFIX}/bin is not in your PATH.
  Instructions on how to configure your shell for Homebrew
  can be found in the 'Next steps' section below."
fi

ohai "Installation successful!"
echo

ring_bell

# Use an extra newline and bold to avoid this being missed.
ohai "Homebrew has enabled anonymous aggregate formulae and cask analytics."
echo "$(
  cat <<EOS
${tty_bold}Read the analytics documentation (and how to opt-out) here:
  ${tty_underline}https://docs.brew.sh/Analytics${tty_reset}
No analytics data has been sent yet (nor will any be during this ${tty_bold}install${tty_reset} run).
EOS
)
"

ohai "Homebrew is run entirely by unpaid volunteers. Please consider donating:"
echo "$(
  cat <<EOS
  ${tty_underline}https://github.com/Homebrew/brew#donations${tty_reset}
EOS
)
"

(
  cd "${HOMEBREW_REPOSITORY}" >/dev/null || return
  execute "git" "config" "--replace-all" "homebrew.analyticsmessage" "true"
  execute "git" "config" "--replace-all" "homebrew.caskanalyticsmessage" "true"
) || exit 1

ohai "Next steps:"
case "${SHELL}" in
  */bash*)
    if [[ -r "${HOME}/.bash_profile" ]]
    then
      shell_profile="${HOME}/.bash_profile"
    else
      shell_profile="${HOME}/.profile"
    fi
    ;;
  */zsh*)
    shell_profile="${HOME}/.zprofile"
    ;;
  *)
    shell_profile="${HOME}/.profile"
    ;;
esac
if [[ "${UNAME_MACHINE}" == "arm64" ]] || [[ -n "${HOMEBREW_ON_LINUX-}" ]]
then
  cat <<EOS
- Run these two commands in your terminal to add Homebrew to your ${tty_bold}PATH${tty_reset}:
    echo 'eval "\$(${HOMEBREW_PREFIX}/bin/brew shellenv)"' >> ${shell_profile}
    eval "\$(${HOMEBREW_PREFIX}/bin/brew shellenv)"
EOS
fi
if [[ -n "${non_default_repos}" ]]
then
  plural=""
  if [[ "${#additional_shellenv_commands[@]}" -gt 1 ]]
  then
    plural="s"
  fi
  echo "- Run these commands in your terminal to add the non-default Git remote${plural} for ${non_default_repos}:"
  printf "    echo '%s' >> ${shell_profile}\n" "${additional_shellenv_commands[@]}"
  printf "    %s\n" "${additional_shellenv_commands[@]}"
fi

if [[ -n "${HOMEBREW_ON_LINUX-}" ]]
then
  echo "- Install Homebrew's dependencies if you have sudo access:"

  if [[ -x "$(command -v apt-get)" ]]
  then
    echo "    sudo apt-get install build-essential"
  elif [[ -x "$(command -v yum)" ]]
  then
    echo "    sudo yum groupinstall 'Development Tools'"
  elif [[ -x "$(command -v pacman)" ]]
  then
    echo "    sudo pacman -S base-devel"
  elif [[ -x "$(command -v apk)" ]]
  then
    echo "    sudo apk add build-base"
  fi

  cat <<EOS
  For more information, see:
    ${tty_underline}https://docs.brew.sh/Homebrew-on-Linux${tty_reset}
- We recommend that you install GCC:
    brew install gcc
EOS
fi

cat <<EOS
- Run ${tty_bold}brew help${tty_reset} to get started
- Further documentation:
    ${tty_underline}https://docs.brew.sh${tty_reset}

EOS
}
echo ----------------------------------------------------------------------------------------------------------
echo -----What would you like to do ? -----for install enter i ---- cleanUp enter c ---- update enter u -------
echo ----------------------------------------------------------------------------------------------------------
echo "to Proceed [i/c/u]:" 
read var


case $var in
i)	
    echo "bootstraping started ................"
    install_xcode
    install_homebrew
    brew_install
    if [ ! -d "$INSTALLDIR" ]; then 
	    git clone git@github.com:laithrafid/dotfiles.git "$INSTALLDIR" 
    fi
    echo "creating symlinks ....."
    create_symlinks
    source ~/.profile
    cd $INSTALLDIR
    install_deps
    vim +PluginInstall +qall
    ;;
u) 
    echo "upgrading started   ................"
    cd $INSTALLDIR
    git pull origin main
    install_homebrew
    brew_install
    create_symlinks
    install_deps
    source ~/.profile
    vim +PluginuInstall! +qall
    ;;
c) 
    echo "cleanup  started   ................"
    uninstall_homebrew
    brew_uninstall
    vim +PluginClean +qall
    rm -rf ~/.vim/*
    rm -rf $INSTALLDIR
    
    ;;
esac

if [ ! -f ~/.bashrc ]; then
    echo "if [ -f ~/.profile ]; then . ~/.profile ; fi" >> ~/.bashrc
    source ~/.bashrc
fi

echo "bootstrapping done"
