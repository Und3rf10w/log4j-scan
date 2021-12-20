#! /bin/bash

if [ -z "${PROJECT_HOME}" ]; then
    PROJECT_HOME="$(dirname "$(dirname "$(readlink -f "$0")")")"
    echo "Defaulting PROJECT_HOME to '$PROJECT_HOME'"
fi


if [ -d "${PROJECT_HOME}/venv" ]; then
    echo "A virtual environment already exists at ${PROJECT_HOME}/venv to recreate it please delete this first"
    [[ "$0" = "$BASH_SOURCE" ]] && exit 0 || return 0 # handle exits from shell or function but don't exit interactive shell
fi

which virtualenv
if [ $? -ne 0 ]; then
    echo "virtualenv not available, installing"
    apt-get update
    apt-get install -y python3-virtualenv python3.8-venv
fi

virtualenv --python=python3.8 "${PROJECT_HOME}/venv"

if [ $? -ne 0 ]; then
    echo "Unable to init venv"
    [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1 # handle exits from shell or function but don't exit interactive shell
fi

source "${PROJECT_HOME}/venv/bin/activate"
if [ $? -ne 0 ]; then
    echo "Unable to activate venv"
    [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1 # handle exits from shell or function but don't exit interactive shell
fi

if [ "x${PIP_EXTRA_URL}" != "x" ]; then
    pip config set global.extra-index-url "${PIP_EXTRA_URL}"
fi

pip install -r "$PROJECT_HOME/requirements.txt" --upgrade
