# redes-unb-ping
Ping utilizado no projeto final da máteria de redes

# Setup

Instalação do dialog: 
sudo apt install dialog 

Para executar o script é necessário estar com o Python3 instalado na máquina (https://phoenixnap.com/kb/how-to-install-python-3-ubuntu): 
sudo apt install python3.8

Na criptografia dos dados é utilizada a biblioteca Crypto: 
sudo apt-get -y install python3-pip
sudo pip3 install pycryptodome==3.4.3

Instalação da biblioteca para cálculo 
sudo pip3 install numpy

# Execução
Utilize o seguinte comando para executar o script:

sudo python3 ICMP-Ping_Dialog.py --Host "google.com" --Mensagem "msg a ser escondida" --Crypto "Y" --Key "chave" --Nonce "nonce" --Qtde 1

# Possíveis Melhorias

Melhoria na mensagem no caso de mensagens escondidas 

Criação de uma tela  permitindo informar o código utilizado no icmp echo request



 

