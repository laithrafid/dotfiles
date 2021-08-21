#!/usr/bin/env sh

INSTALLDIR=${INSTALLDIR:-"$PWD/dotfiles/"}

create_symlinks () {

    if [ ! -f ~/.conf.tmux ]; then
        ln -sfn $INSTALLDIR/tmux.conf ~/.tmux.conf
    fi

    if [ ! -f ~/.profile ]; then
        ln -sfn $INSTALLDIR/bash_profile ~/.profile
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
    source ~/.profile
    cd $INSTALLDIR

else
    echo "upgrade to new configs"
    cd $INSTALLDIR
    git pull origin main
    create_symlinks
    source ~/.profile
fi
    if [ ! -f ~/.bashrc ]; then
    echo "if [ -f ~/.profile ]; then . ~/.profile ; fi" >> ~/.bashrc
    source ~/.bashrc
    fi



