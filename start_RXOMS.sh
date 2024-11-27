#!/bin/bash

tmux new-session -d -s RXOMS

# Split the window and run each command in a new pane
tmux send-keys -t RXOMS 'bash ./services/start_external_service.sh' C-m
tmux split-window -h -t RXOMS

sleep 5

tmux send-keys -t RXOMS 'python3.12 ./services/simulated_KG.py' C-m
tmux split-window -v -t RXOMS

tmux send-keys -t RXOMS 'python3.12 ./services/data_enrichment.py' C-m
tmux select-pane -t RXOMS.0
tmux split-window -v -t RXOMS

tmux send-keys -t RXOMS 'python3.12 ./services/incident_analysis.py' C-m
tmux select-pane -t RXOMS.2
tmux split-window -h -t RXOMS

tmux send-keys -t RXOMS 'python3.12 ./services/incident_validation.py' C-m
tmux select-pane -t RXOMS.4
tmux split-window -h -t RXOMS

tmux send-keys -t RXOMS 'python3.12 ./services/plan_enforcement.py' C-m

# Select the first pane
tmux select-pane -t RXOMS.0

# Attach to the tmux session
tmux attach-session -t RXOMS
