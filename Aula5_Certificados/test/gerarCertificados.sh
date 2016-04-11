#Comandos:

#-- Certificado
echo "Gerar Certificado Principal"
openssl genrsa -des3 -out certificateKey.key 2048
echo "Chave RSA gerada para o CA"
openssl req -new -x509 -days 128 -nodes -key certificateKey.key -sha256 -set_serial 01 -out certificate.pem
echo "CA criado com sucesso"
openssl x509 -inform PEM -in certificate.pem -outform DER -out CA.cer

#-- Cliente
echo "Gerar certificado Cliente"
openssl genrsa -des3 -out clienteKey.key 2048
echo "Chave RSA gerada para o Cliente"
openssl req -new -key clienteKey.key -out certificateCliente.csr
echo "Fase 1 Cliente terminada"
openssl x509 -req -days 128 -in certificateCliente.csr -CA certificate.pem -CAkey certificateKey.key -set_serial 02 -out certificateCliente2.crt -sha256
echo "Fase 2 Cliente terminada"
openssl pkcs12 -export -out Cliente.p12 -inkey clienteKey.key -in certificateCliente2.crt -name Cliente1

#-- Servidor
echo "Gerar certificado Servidor"
openssl genrsa -des3 -out servidorKey.key 2048
echo "Chave RSA gerada para o Servidor"
openssl req -new -key servidorKey.key -out certificateServidor.csr
echo "Fase 1 Servidor terminada"
openssl x509 -req -days 128 -in certificateServidor.csr -CA certificate.pem -CAkey certificateKey.key -set_serial 03 -out certificateServidor2.crt -sha256
echo "Fase 2 Servidor terminada"
openssl pkcs12 -export -out Servidor.p12 -inkey servidorKey.key -in certificateServidor2.crt -name Servidor
