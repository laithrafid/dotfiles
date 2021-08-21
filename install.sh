#!/usr/bin/env sh

INSTALLDIR=${INSTALLDIR:-"$PWD/dotfiles"}
create_symlinks () {
    if [ ! -f ~/.vim ]; then
        echo "Now, we will create ~/.vim and ~/.vimrc files to configure Vim."
        ln -sfn $INSTALLDIR ~/.vim
    fi

    if [ ! -f ~/.vimrc ]; then
        ln -sfn $INSTALLDIR/vimrc ~/.vimrc
    fi

    if [ ! -f ~/.conf.tmux ]; then
        ln -sfn $INSTALLDIR/tmux.conf ~/.tmux.conf
    fi

    if [ ! -f ~/.profile ]; then
        ln -sfn $INSTALLDIR/bash_profile ~/.profile
    fi

    if [ ! -f ~/.bash_profile ]; then
        ln -sfn $INSTALLDIR/bash_profile ~/.bash_profile
    fi
    if [ ! -f ~/.inputrc ]; then
        ln -sfn $INSTALLDIR/inputrc ~/.inputrc
    fi
}

echo "You are about to config vim , tmux , your bash profile and inputrc file. Ready? Let us do some stuff for you."

echo "checking if git exist"
which git > /dev/null
if [ "$?" != "0" ]; then
  echo "You need git installed to install configs."
  exit 1
fi

echo "checking if vim exist"
which vim > /dev/null
if [ "$?" != "0" ]; then
  echo "You need vim installed to install configs."
  exit 1
fi

echo "checking if tmux exist"
which tmux > /dev/null
if ["$?" != "0" ]; then
    echo "you need to install tmux"
    exit 1
fi

if [ ! -d "$INSTALLDIR" ]; then
    echo "could't find dotfiles config in the current directory, we will clone from remote repo"
    git clone git@github.com:laithrafid/dotfiles.git $INSTALLDIR
    create_symlinks
    echo "sourcing new config"
    source ~/.bash_profile
    cd $INSTALLDIR

else
    echo "upgrade to new configs"
    cd $INSTALLDIR
    git pull origin main
    create_symlinks
fi

if [ ! -d "bundle" ]; then
    echo "Now, we will create a separate directory to store the bundles Vim will use."
    mkdir bundle
    mkdir -p tmp/backup tmp/swap tmp/undo
fi

if [ ! -d "bundle/vundle" ]; then
    echo "Then, we install Vundle (https://github.com/gmarik/vundle)."
    git clone https://github.com/gmarik/vundle.git bundle/vundle
fi

if [ ! -f local.vimrc ]; then
  echo "Let's create a 'local.vimrc' file so you have some bundles by default."
  echo "let g:configs_packages = ['general', 'fancy', 'css', 'js', 'os', 'html', 'coding', 'color']" > 'local.vimrc'
fi

    if [ ! -f ~/.bashrc ]; then
    echo "if [ -f ~/.bash_profile ]; then . ~/.bash_profile ; fi" >> ~/.bashrc
    source ~/.bashrc
    fi


vim +BundleInstall +qall 2>/dev/null

