#!/bin/bash

SESSION="laith"
SESSIONEXISTS=$(tmux list-sessions | grep -w "$SESSION")

if [ "$SESSIONEXISTS" = "" ]
then

  tmux new-session -d -s "$SESSION" -d -x "$(tput cols)" -y "$(tput lines)"

  tmux rename-window -t 1 'mon'
  tmux send-keys -t 'mon' 'nettop -n | lolcat' C-m
  tmux splitw -h

  tmux send-keys -t 'mon' 'htop' C-m
  tmux splitw -v
 
  tmux send-keys -t 'mon' 'watch -n 1 docker ps -aq | lolcat' C-m
  tmux select-pane -t 1
  tmux splitw -v

  tmux send-keys -t 'mon' 'watch -n 1 docker system df' C-m
  tmux select-pane -t 1

  tmux new-window -t "$SESSION":2 -n 'dev'
  tmux send-keys -t 'dev' 'cd $WDIR' C-m
  tmux splitw -h
  tmux send-keys -t 'dev' 'cd $WDIR' C-m
  tmux splitw -v
  tmux send-keys -t 'dev' 'cd $WDIR' C-m
  tmux select-pane -t 1
  tmux splitw -v
  tmux send-keys -t 'dev' 'cd $WDIR' C-m
  tmux select-pane -t 1

  tmux new-window -t "$SESSION":3 -n 'ssh'
  tmux send-keys -t 'ssh' '' C-m
  tmux splitw -h
  tmux send-keys -t 'ssh' '' C-m
  tmux splitw -v
  tmux send-keys -t 'ssh' '' C-m
  tmux select-pane -t 1
  tmux splitw -v
  tmux send-keys -t 'ssh' '' C-m
  tmux select-pane -t 1
fi

tmux attach-session -t "$SESSION":1

