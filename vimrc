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

" airline
Plugin 'vim-airline/vim-airline'
Plugin 'vim-airline/vim-airline-themes'
let g:airline#extensions#tabline#enabled = 1

" fuzzy search
Plugin 'junegunn/fzf'
" - To learn more about preview window options, see `--preview-window` section of `man fzf`.
let g:fzf_preview_window = ['right:50%', 'ctrl-/']

" Preview window on the upper side of the window with 40% height,
" hidden by default, ctrl-/ to toggle
let g:fzf_preview_window = ['up:40%:hidden', 'ctrl-/']

" Empty value to disable preview window altogether
let g:fzf_preview_window = []


" vim-git gutter shows git diff 
Plugin 'vim-gitgutter'
let g:gitgutter_terminal_reports_focus=0

" Nerd tree
Plugin 'scrooloose/nerdtree'

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

 
