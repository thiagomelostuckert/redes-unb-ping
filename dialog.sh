#!/bin/bash

PING_SIMPLES(){
  DOMINIO=$(dialog --stdout --inputbox 'Por favor digite o destino a ser pingado' 0 0)
  MSG=""
  CRYPTO="N"
  sudo python3 ICMP-Ping_Dialog.py --Host $DOMINIO --Mensagem "\"$MSG\"" --Crypto $CRYPTO > /tmp/ping

	dialog --stdout               \
      --title 'Ping simples'  \
      --textbox /tmp/ping \
      0 0
}

PING_AVANCADO(){
  DOMINIO=$(dialog --stdout --inputbox 'Por favor digite o destino a ser pingado' 0 0)
  MSG=$(dialog --stdout --inputbox 'Por favor, informe a mensagem a ser escondida:' 0 0)
  CRYPTO="N"
  sudo python3 ICMP-Ping_Dialog.py --Host $DOMINIO --Mensagem "\"$MSG\"" --Crypto $CRYPTO > /tmp/ping
	dialog --stdout               \
      --title 'Ping avançado'  \
      --textbox /tmp/ping \
      0 0

}

PING_CRIPTOGRAFADO(){
  DOMINIO=$(dialog --stdout --inputbox 'Por favor digite o destino a ser pingado' 0 0)
  MSG=$(dialog --stdout --inputbox 'Por favor, informe a mensagem a ser escondida:' 0 0)
  CRYPTO="Y"
  KEY=$(dialog --stdout --inputbox 'Por favor, informe a chave a ser utilizada na criptografia:' 0 0)
  NONCE=$(dialog --stdout --inputbox 'Por favor, informe o nonce a ser utilizado na criptografia:' 0 0)
  sudo python3 ICMP-Ping_Dialog.py --Host $DOMINIO --Mensagem "\"$MSG\"" --Crypto $CRYPTO --Key "\"$KEY\"" --Nonce "\"$NONCE\""> /tmp/ping

	dialog --stdout               \
      --title 'Ping criptografado'  \
      --textbox /tmp/ping \
      0 0
}

while : ; do
    resposta=$(
      dialog --stdout               \
             --title 'Projeto final - atividade 4 - item A'  \
             --menu 'Menu Principal' \
            0 0 0                   \
            1 'Simples (sem esteganografia)' \
            2 'Avançado (com esteganografia)'  \
            3 'Criptografado'  \
            0 'Sair' )

    # Usuario pressionou ESC ou Cancelar
    [ $? -ne 0 ] && break

    # De acordo com a opcao escolhida faz o ping
    case "$resposta" in
         1) PING_SIMPLES ;;
         2) PING_AVANCADO ;;
         3) PING_CRIPTOGRAFADO ;;
         0) break ;;
    esac
done
clear