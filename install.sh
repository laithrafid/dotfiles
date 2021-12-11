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

install_test(){
homebrew="$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
which brew > /dev/null
if [ "$?" != "0" ]; then
echo "installing homebrew"
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
else 
echo "already installed"
fi
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
    install_test
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
    brew_install
    create_symlinks
    install_deps
    source ~/.profile
    vim +PluginuInstall! +qall
    ;;
c) 
    echo "cleanup  started   ................"
   # uninstall_homebrew
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
