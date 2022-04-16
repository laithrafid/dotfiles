#!/bin/bash
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
if [ "$?" != "0" ]; then
  echo "Xcode CLI tools not found. Installing them..."
  xcode-select --install && sleep 1
  osascript -e 'tell application "System Events"' -e 'tell process "Install Command Line Developer Tools"' -e 'keystroke return' -e 'click button "Agree" of window "License Agreement"' -e 'end tell' -e 'end tell'
  PROD=$(softwareupdate -l |
  grep "\*.*Command Line" |
  tail -n 1 | sed 's/^[^C]* //')
  echo "Prod: ${PROD}"
  softwareupdate -i "${PROD}" --verbose;
else
  echo "Xcode CLI tools OK"
fi
}

install_brew(){
    echo  "installing brew Command Line Tool ...."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"    
}
uninstall_brew(){
    echo  "installing brew Command Line Tool ...."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/uninstall.sh)"    
}

SUDO_USER=$(whoami)
INSTALLDIR=/Users/$SUDO_USER/dotfiles
PACKAGES=(  
awscli
azure-cli
ack
aom
apr
apr-util
argon2
asciinema
aspell
autoconf
autojump
automake
bash
bash-completion
bdw-gc
berkeley-db
brew-cask-completion
brotli
c-ares
ca-certificates
cairo
cjson
cmocka
composer
coreutils
curl
dav1d
docbook
docbook-xsl
docker-completion
doctl
erlang
ffmpeg
findutils
flac
fontconfig
freetds
freetype
frei0r
fribidi
fx
gd
gdbm
gdk-pixbuf
gettext
gh
ghostscript
giflib
gifsicle
git
glib
gmp
gnu-getopt
gnu-indent
gnu-sed
gnu-tar
gnu-which
gnupg
gnutls
go
gobject-introspection
gradle
graphite2
graphviz
grpcurl
gts
guile
harfbuzz
helm
htop
httpie
hub
icu4c
ifstat
imagemagick
imath
jasper
jbig2dec
jpeg
jpeg-xl
jpegoptim
jq
kompose
krb5
kubernetes-cli
lame
launchctl-completion
leptonica
libarchive
libass
libassuan
libavif
libb2
libbluray
libcbor
libde265
libevent
libffi
libfido2
libgcrypt
libgpg-error
libheif
libidn
libidn2
libksba
liblqr
libmemcached
libnghttp2
libogg
libomp
libpng
libpq
libpthread-stubs
librist
librsvg
libsamplerate
libsndfile
libsodium
libsoxr
libssh2
libtasn1
libtiff
libtool
libunistring
libusb
libuv
libvidstab
libvmaf
libvorbis
libvpx
libx11
libxau
libxcb
libxdmcp
libxext
libxrender
libyaml
libzip
little-cms2
lolcat
lsusb
lua
lynx
lz4
lzo
m4
markdown
maven
mbedtls
memcached
mercurial
minikube
mpdecimal
mysql-client
ncurses
netpbm
nettle
nmap
node
npth
nvm
oniguruma
opencore-amr
openexr
openjdk
openjdk@11
openjpeg
openldap
openssl@1.1
optipng
opus
p11-kit
packer
packer-completion
pango
pcre
pcre2
perl
php
pinentry
pixman
pkg-config
postgresql
protobuf
pypy
python@3.10
python@3.9
rabbitmq
rav1e
readline
rename
ripgrep
rtmpdump
rubberband
ruby
s3cmd
sdl2
shared-mime-info
six
skaffold
snappy
speex
sqlite
srt
ssh-copy-id
tcl-tk
terminal-notifier
terraform
terraform-docs
tesseract
the_silver_searcher
theora
tidy-html5
tig
tmux
tree
unbound
unixodbc
utf8proc
vagrant-completion
vim
watch
waypoint
webp
wget
wxwidgets
x264
x265
xmlto
xorgproto
xvid
xz
yamllint
zeromq
zimg
zstd
)

CASKS=(
    burp-suite
    #docker
    gimp
    google-chrome
    google-cloud-sdk
    microsoft-remote-desktop
    mysqlworkbench
    openphone
    postman
    rectangle
    slack
    sublime-merge
    sublime-text
    vagrant
    virtualbox
    visual-studio-code
    wireshark
    ##objective-c&dev security suite (non-cmd)
    reikey
    blockblock
    do-not-disturb
    little-snitch
    micro-snitch
    cleanmymac
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
    sudo brew install --cask ${CASKS[@]}
    echo "Installing Python packages..."
    sudo pip3 install --upgrade pip
    sudo pip3 install --upgrade setuptools
    sudo pip3 install ${PYTHON_PACKAGES[@]}
    echo "Installing global npm packages..."
    sudo npm install marked -g
    echo "brew update"
    brew update
    echo "brew upgrade"
    brew upgrade
    npm install -g browser-sync
    echo "installed"
}

brew_uninstall(){
    echo "Uninstalling Python packages..."
    sudo pip3 uninstall ${PYTHON_PACKAGES[@]}
    sudo pip3 uninstall setuptools
    sudo pip3 uninstall  pip
    echo "Uninstalling packages..."
    brew uninstall --force --ignore-dependencies ${PACKAGES[@]}
    echo "Uninstalling cask apps..."
    sudo brew uninstall --ignore-dependencies --force --cask ${CASKS[@]}
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
    if [ ! -h ~/.gitignore_global ]; then
        ln -sfn $INSTALLDIR/gitignore ~/.gitignore_global
    else
        rm -rf ~/.gitignore_global
        ln -sfn $INSTALLDIR/gitignore ~/.gitignore_global

    fi
       if [ ! -h ~/.inputrc ]; then
        ln -sfn $INSTALLDIR/inputrc ~/.inputrc
    else
        rm -rf ~/.gitignore_global
        ln -sfn $INSTALLDIR/inputrc ~/.inputrc

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



echo ----------------------------------------------------------------------------------------------------------
echo -----What would you like to do ? -----for install enter i ---- cleanUp enter c ---- update enter u -------
echo ----------------------------------------------------------------------------------------------------------
echo "to Proceed [i/c/u]:" 
read var


case $var in
i)	
    echo "bootstraping started ................"
    install_xcode
    install_brew
    brew_install
    if [ ! -d "$INSTALLDIR" ]; then 
	    git clone https://github.com/laithrafid/dotfiles.git "$INSTALLDIR" 
    fi
    echo "creating symlinks ....."
    create_symlinks
    source ~/.profile
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
    echo "cleanup started   ................"
    brew_uninstall
    vim +PluginClean +qall
    rm -rf ~/.vim/*
    rm -rf $INSTALLDIR
    uninstall_brew
    echo "Uninstalling devtools"
    sudo rm -rf /Library/Developer/CommandLineTools
    ;;
esac

if [ ! -f ~/.bashrc ]; then
    echo "if [ -f ~/.profile ]; then . ~/.profile ; fi" >> ~/.bashrc
    source ~/.bashrc
fi

echo "bootstrapping done"
