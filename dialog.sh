#!/bin/bash

INPUT_CRYPTO(){
	CRYPTO=$(dialog --stdout --inputbox 'Por favor, informe se a criptografia estará habilitada ("Y" ou "N"):' 0 0)
}

INPUT_KEY(){
	KEY=$(dialog --stdout --inputbox 'Por favor, informe a chave a ser utilizada na criptografia:' 0 0)
}

INPUT_MSG(){
	MSG=$(dialog --stdout --inputbox 'Por favor, informe a mensagem a ser escondida:' 0 0)
}

PING_GOOGLE(){
  INPUT_MSG
  INPUT_CRYPTO

  if [ "$CRYPTO" = "Y" ] || [ "$CRYPTO" = "y" ];then
    INPUT_KEY
	  sudo python3 ICMP-Ping_Dialog.py google.com "\"$MSG\"" "\"$CRYPTO\"" "\"$KEY\""> /tmp/ping
  else
    sudo python3 ICMP-Ping_Dialog.py google.com "\"$MSG\"" "\"$CRYPTO\"" > /tmp/ping
  fi

  dialog --stdout               \
        --title 'Ping google.com'  \
        --textbox /tmp/ping \
        0 0
}


PING_OUTROS(){
  INPUT_MSG
  INPUT_CRYPTO

  DOMINIO=$(dialog --stdout --inputbox 'Por favor digite o dominio a ser pingado' 0 0)

  if [ "$CRYPTO" = "Y" ] || [ "$CRYPTO" = "y" ];then
    INPUT_KEY
    sudo python3 ICMP-Ping_Dialog.py $DOMINIO "\"$MSG\"" "\"$CRYPTO\"" "\"$KEY\""> /tmp/ping
  else
    sudo python3 ICMP-Ping_Dialog.py $DOMINIO "\"$MSG\"" "\"$CRYPTO\"" > /tmp/ping
  fi

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


