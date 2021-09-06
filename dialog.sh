#!/bin/bash

PING_GOOGLE(){
	sudo python3 ICMP-Ping_Dialog.py google.com > /tmp/ping 
	
	dialog --stdout               \
             	    --title 'Ping google.com'  \
             	    --textbox /tmp/ping \
             	    0 0 
}


PING_OUTROS(){

	DOMINIO=$(dialog --stdout --inputbox 'Por favor digite o dominio a ser pingado' 0 0)

	sudo python3 ICMP-Ping_Dialog.py $DOMINIO > /tmp/ping

	dialog --textbox /tmp/ping 0 0

}

while : ; do

    resposta=$(
      dialog --stdout               \
             --title 'Projeto final - atividade 4 - item A'  \
             --menu 'Menu Principal' \
            0 0 0                   \
            1 'Ping google.com' \
            2 'Ping em um dominio a ser informado'  \
            0 'Sair' )

    # Usuario pressionou ESC ou Cancelar
    [ $? -ne 0 ] && break

    # De acordo com a opcao escolhida faz o ping
    case "$resposta" in
         1) PING_GOOGLE ;;
         2) PING_OUTROS ;;
         0) break ;;
    esac

done

clear


