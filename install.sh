#!/usr/bin/env sh
set -euo pipefail
IFS=$'\n\t'

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
if [ $? -ne 0 ]; then
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

INSTALLDIR=${INSTALLDIR:-"~/.dotfiles"}
SUDO_USER=$(whoami)
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
    aws-iam-authenticator
    boot2docker
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
    echo "brew doctor"
    brew doctor
}

brew_uninstall(){
    echo "Uninstalling packages..."
    brew uninstall ${PACKAGES[@]}
    echo "Uninstalling cask apps..."
    sudo -u $SUDO_USER brew uninstall --cask ${CASKS[@]}
    echo "Uninstalling Python packages..."
    sudo -u $SUDO_USER pip3 uninstall ${PYTHON_PACKAGES[@]}
    sudo -u $SUDO_USER pip3 uninstall setuptools
    sudo -u $SUDO_USER pip3 uninstall  pip
    echo "brew update"
    brew update
    echo "brew upgrade"
    brew upgrade
    echo "brew doctor"
    brew doctor
}

create_symlinks () {

    if [ ! -f ~/.conf.tmux ]; then
        ln -sfn $INSTALLDIR/tmux.conf ~/.tmux.conf
    fi

    if [ ! -f ~/.profile ]; then
        ln -sfn $INSTALLDIR/bash_profile ~/.profile
    fi

    if [ ! -f ~/.vimrc ]; then
        ln -sfn $INSTALLDIR/vimrc ~/.vimrc
    fi

    if [ ! -f ~/.gitconfig ]; then
        ln -sfn $INSTALLDIR/gitconfig ~/.gitconfig
    fi
}


install_deps(){
echo " installing dotfiles startet"
sleep 5s 

echo "checking if git exist"
which git > /dev/null
if [ "$?" != "0" ]; then
  echo "You need git installed to install configs."
  exit 1
else
  echo "Installing vundle into ~/.vim/bundle/ directory"
  git clone https://github.com/VundleVim/Vundle.vim.git ~/.vim/bundle/Vundle.vim
fi

}

echo ----------------------------------------------------------------------------------------------------------
echo -----What would you like to do ? -----for install enter i ---- cleanUp enter c ---- update enter u -------
echo ----------------------------------------------------------------------------------------------------------
read var


if [ $var == 'i' ]; then
    echo "bootstraping started ................"
    
    install_xcode
    brew_install
    git clone git@github.com:laithrafid/dotfiles.git $INSTALLDIR
    create_symlinks
    source ~/.profile
    cd $INSTALLDIR
    install_deps
    vim +PluginInstall +qall
elif [ $var == 'u' ]; then 
    echo "upgrading started   ................"
    cd $INSTALLDIR
    git pull origin main
    brew_install
    create_symlinks
    install_deps
    source ~/.profile
    vim +PluginuInstall! +qall
elif [ $var == 'c' ]; then 
    echo "cleanup  started   ................"
    brew_uninstall
    vim +PluginClean +qall
    rm -rf ~/.vim/*
    rm -rf $INSTALLDIR
fi

if [ ! -f ~/.bashrc ]; then
    echo "if [ -f ~/.profile ]; then . ~/.profile ; fi" >> ~/.bashrc
    source ~/.bashrc
fi

echo "bootstrapping done"
