#!/usr/env sh

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
}

echo "You are about to be configs. Ready? Let us do the stuff for you."

which git > /dev/null
if [ "$?" != "0" ]; then
  echo "You need git installed to install configs."
  exit 1
fi

which vim > /dev/null
if [ "$?" != "0" ]; then
  echo "You need vim installed to install configs."
  exit 1
fi


which tmux > /dev/null
if ["$?" != "0" ]; then
    echo "you need to install tmux"
    exit 1
fi

if [ ! -d "$INSTALLDIR" ]; then
    echo "As we can't find configs in the current directory, we will create it."
    git clone https://gitlab.com/laith.rafid/dotfiles.git $INSTALLDIR
    create_symlinks
    cd $INSTALLDIR

else
    echo "upgrade to new configs"
    cd $INSTALLDIR
    git pull origin master
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

