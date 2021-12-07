" vimrc 
" Author: Laith@bayt.cloud
" Source: placeholder

set nocompatible
filetype on
filetype off

syntax on

set rtp+=~/.vim/bundle/Vundle.vim
call vundle#begin()

Plugin 'VundleVim/Vundle.vim'
Plugin 'tpope/vim-fugitive'

call vundle#end()            " required
filetype plugin indent on    " required

" To ignore plugin indent changes, instead use:
"filetype plugin on
"
" Brief help
" :PluginList       - lists configured plugins
" :PluginInstall    - installs plugins; append `!` to update or just :PluginUpdate
" :PluginSearch foo - searches for foo; append `!` to refresh local cache
" :PluginClean      - confirms removal of unused plugins; append `!` to auto-approve removal
"To install from command line: vim +PluginInstall +qall 
" see :h vundle for more details or wiki for FAQ
" Put your non-Plugin stuff after this line

 
