#!/bin/bash

if [ -z command -v curl 2> /dev/null ]; then
	echo "Install Curl"
	sudo update
	sudo apt install curl
	sudo upgrade
fi

if [ ! -f ~/.vimrc ]; then
	echo ".vimrc is not exists..."
	curl -fLo ~/.vim/autoload/plug.vim --create-dirs "https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim"
	touch ~/.vimrc
	echo "call plug#begin('~/.vim/plugged')" >> ~/.vimrc
	echo "Plug 'mg979/vim-visual-multi', {'branch': 'master'}" >> ~/.vimrc
	echo "call plug#end()" >> ~/.vimrc
fi

echo "Please enter \":PlugInstall\" in vi or vim mode!"

