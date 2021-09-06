#!/bin/bash
#
# As funcoes devem ser declaradas antes da chamada principal do Dialog
#
dialog --title 'Projeto final - atividade 4 - item A - Menu Principal' \
	--menu 'Escolha uma das opcoes do ICMP-Ping.py' \
		0 0 0 \
		PING_GOOGLE 'Ping google.com' \
		PING_ESCOLHA 'Ping em um dominio a ser informado' \
		SAIR '' 2> /tmp/escolha_vm
		opt=$(cat /tmp/escolha_vm)
			case $opt in
				"PING_GOOGLE")
				config_VM1
				;;
				"PING_ESCOLHA")
				Dialog --msgbox 'Escolha do dominio' 5 40
				;;
				"SAIR")
				break
				;;
				*) echo Opcao Invalida
		esac
	clear

PING_GOOGLE() {
dialog --title 'Projeto final - atividade 4 - item A - Ping google.com' \
	--menu 'Ping google.com' \
	
}

PING_GOOGLE() {
dialog --title 'Projeto final - atividade 4 - item A - Ping em um dominio a ser informado' \
	--menu 'Ping em um dominio a ser informado' \
	
}

#declaracao da função config_VM1()
config_VM1() {
dialog --title 'Configuracao Manual das Interface de Redes' \
	--menu 'Escolhe uma Interface' \
		0 0 0 \
		enp0s3 'Interface n. 1' \
		enp0s8 'Interface n. 2' \
		SAIR '' 2> /tmp/opcao
		opt=$(cat /tmp/opcao)
			case $opt in
				"enp0s3")
				sudo ip a flush $(opt /tmp/opcao)
				dialog --backtitle "Configuracao enp0s3" \
					--inputbox "Digitar o IP (x.x.x.x/y):" -1 -1 '' \
						2> /tmp/enp0s8
				sudo ip a add $(cat /tmp/enp0s8) dev $(cat /tmp/opcao)
				sudo ip a show $(cat /tmp/opcao) > /tmp/opcao2
				dialog --title 'Configuracao realizada' --textbox /tmp/opcao2 22 70
				config_VM1
				;;
				"SAIR")
				break
				;;
				*) echo Opcao Invalida
		esac
	clear
}
