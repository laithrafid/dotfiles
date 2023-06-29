#!/bin/bash

SESSION="laith"
SESSIONNOEXISTS=$(tmux list-sessions | grep -w "$SESSION")
# Get the rotation value for the "LG ULTRAWIDE" display
ROTATION=$(system_profiler SPDisplaysDataType | grep "LG ULTRAWIDE:" -A 7 | awk '/Rotation:/{print $2}')

standard(){
if [ "$SESSIONNOEXISTS" = "" ]; then
    # Create a new tmux session named "$SESSION" with dimensions based on the terminal size
    tmux new-session -d -s "$SESSION" -d -x "$(tput cols)" -y "$(tput lines)"

    # Create a new window named "mon" and run 'htop' command in it
    tmux rename-window -t 1 'mon'
    tmux send-keys -t 'mon' 'htop' C-m

    tmux new-window -t "$SESSION":2 -n 'net'
    tmux send-keys -t 'net' 'watch -n 1 sudo arp -lax | lolcat' C-m
    tmux splitw -h
    tmux send-keys -t 'net' 'sudo nettop -n | lolcat' C-m
    tmux select-pane -t 1
    tmux splitw -v
    tmux send-keys -t 'net' 'watch -n 1 sudo lsof +c0 -V -nP -iUDP | lolcat' C-m
    tmux select-pane -t 1
    tmux splitw -v
    tmux send-keys -t 'net' 'watch -n 1 sudo lsof +c0 -V -nP -iTCP -sTCP:LISTEN,ESTABLISHED -n | lolcat' C-m
    tmux select-pane -t 1


    # Create a new window named "dev" and change to the directory specified by the $WDIR variable
    tmux new-window -t "$SESSION":3 -n 'dev'
    tmux send-keys -t 'dev' 'sudo su laithrafid && cd $WDIR' C-m
    tmux splitw -h
    tmux send-keys -t 'dev' 'sudo su laithrafid && cd $WDIR' C-m
    tmux splitw -v
    tmux send-keys -t 'dev' 'sudo su laithrafid && cd $WDIR' C-m
    tmux select-pane -t 1
    tmux splitw -v
    tmux send-keys -t 'dev' 'sudo su laithrafid && cd $WDIR' C-m
    tmux select-pane -t 1

    # Create a new window named "ssh" for SSH connections
    tmux new-window -t "$SESSION":4 -n 'ssh'
    tmux send-keys -t 'ssh' 'sudo su laithrafid && cd $WDIR' C-m
    tmux splitw -h
    tmux send-keys -t 'ssh' 'sudo su laithrafid && cd $WDIR' C-m
    tmux splitw -v
    tmux send-keys -t 'ssh' 'sudo su laithrafid && cd $WDIR' C-m
    tmux select-pane -t 1
    tmux splitw -v
    tmux send-keys -t 'ssh' 'sudo su laithrafid && cd $WDIR' C-m
    tmux select-pane -t 1

    # Attach to the first window of the session
    tmux attach-session -t "$SESSION":1
  else
    # If the session already exists, attach to the first window of the session
    tmux attach-session -t "$SESSION":1
  fi
}

rotated(){
  if [ "$SESSIONNOEXISTS" = "" ]; then
    # Create a new tmux session named "$SESSION" with dimensions based on the terminal size
    tmux new-session -d -s "$SESSION" -d -x "$(tput cols)" -y "$(tput lines)"

    # Create a new window named "mon" and run 'sudo htop' command in it
    tmux rename-window -t 1 'mon'
    tmux send-keys -t 'mon' 'sudo htop' C-m
    tmux splitw -v

    # Create a new window named "net" and run 'sudo nettop' command in it
    tmux new-window -t "$SESSION":2 -n 'net'
    tmux send-keys -t 'net' 'sudo nettop -n | lolcat' C-m
    tmux splitw -v
    tmux send-keys -t 'net' 'watch -n 1 sudo arp -lax  | lolcat' C-m
    tmux select-pane -t 1
    tmux splitw -v
    tmux send-keys -t 'net' 'watch -n 1 sudo lsof +c0 -V -nP -iUDP | lolcat' C-m
    tmux select-pane -t 1
    tmux splitw -v
    tmux send-keys -t 'net' 'watch -n 1 sudo lsof +c0 -V -nP -iTCP -sTCP:LISTEN,ESTABLISHED -n  | lolcat' C-m
    tmux select-pane -t 1

    # Create a new window named "dev" and change to the directory specified by the $WDIR variable
    tmux new-window -t "$SESSION":3 -n 'dev'
    tmux send-keys -t 'dev' 'sudo su laithrafid && cd $WDIR' C-m
    tmux splitw -v
    tmux send-keys -t 'dev' 'sudo su laithrafid && cd $WDIR' C-m
    tmux splitw -v
    tmux send-keys -t 'dev' 'sudo su laithrafid && cd $WDIR' C-m
    tmux select-pane -t 1
    tmux splitw -v
    tmux send-keys -t 'dev' 'sudo su laithrafid && cd $WDIR' C-m
    tmux select-pane -t 1

    # Create a new window named "ssh" for SSH connections
    tmux new-window -t "$SESSION":4 -n 'ssh'
    tmux send-keys -t 'ssh' 'sudo su laithrafid && cd $WDIR' C-m
    tmux splitw -v
    tmux send-keys -t 'ssh' 'sudo su laithrafid && cd $WDIR' C-m
    tmux splitw -v
    tmux send-keys -t 'ssh' 'sudo su laithrafid && cd $WDIR' C-m
    tmux select-pane -t 1
    tmux splitw -v
    tmux send-keys -t 'ssh' 'sudo su laithrafid && cd $WDIR' C-m
    tmux select-pane -t 1

    # Attach to the first window of the session
    tmux attach-session -t "$SESSION":1
  else
    # If the session already exists, attach to the first window of the session
    tmux attach-session -t "$SESSION":1
  fi
}


if [ "$ROTATION" = "Supported" ]; then
  standard
elif [ "$ROTATION" = "270" ]; then
  rotated
else
  print "2nd monitor is not attached, will run standard tmux sessions"
  standard
fi
