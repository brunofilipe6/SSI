
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collections;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class Cliente {

    static public void main(String []args) throws InvalidKeyException {
	try {
	    Socket s = new Socket("localhost",4567);

	    ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
	    ObjectInputStream ois = new ObjectInputStream(s.getInputStream());

            // Gerar chave publica e privada DH
            DHParameterSpec dhps = new DHParameterSpec(DiffieHellman.p,DiffieHellman.g);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(dhps, new SecureRandom());
            
            // Par de chaves DH
            KeyPair kp = kpg.generateKeyPair();
            
            // Recebe do servidor a chave publica DH
            byte[] chavePublicaServidor = (byte[])ois.readObject();
            
            // Envia para o servidor a ChavePublica do cliente DH
            oos.writeObject(kp.getPublic().getEncoded());
            
            // Certificado Cliente
            String certificadoCliente = "test/Cliente.p12";
            String aliasCliente = "Cliente1";
            char[] password = "1234".toCharArray();
            
            FileInputStream fIn = new FileInputStream(certificadoCliente);
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(fIn, password);
            
            // Obter chave privada do Certificado Cliente.p12
            PrivateKey privKey = (PrivateKey) keyStore.getKey(aliasCliente, password);
            
            // Assinar e enviar assinatura
            Signature sign = Signature.getInstance("SHA256withRSA");
            sign.initSign(privKey);
            sign.update(kp.getPublic().getEncoded());
            sign.update(chavePublicaServidor);
            
            byte[] assinaturaCliente = sign.sign();
            
            // Enviar para o servidor a assinatura
            oos.writeObject(assinaturaCliente);
            
            // Enviar certificado
            Certificate[] certArrayCliente = keyStore.getCertificateChain(aliasCliente);
            oos.writeObject(certArrayCliente[0]);
            
            // Receber assinatura do servidor
            byte[] assinaturaServidor = (byte[])ois.readObject();
            
            // Recebe o Certificado do Servidor
            Certificate certificadoServidor = (Certificate) ois.readObject();
       

            // Preparar certificado recebido para verificação
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");  
            CertPath certPath = certFactory.generateCertPath(Arrays.asList(certificadoServidor));
            Certificate cacert = certFactory.generateCertificate(new FileInputStream("test/CA.cer"));

            
            // Verificar se certificado enviado é do cliente que enviou
            CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
            // TrustAnchor representa os pressupostos de confiança que se aceita como válidos
            // (neste caso, unicamente a CA que emitiu os certificados)
            TrustAnchor anchor = new TrustAnchor((X509Certificate) cacert, null);
            // Podemos também configurar o próprio processo de validação
            // (e.g. requerer a presença de determinada extensão).
            PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
            // ...no nosso caso, vamos simplesmente desactivar a verificação das CRLs
            params.setRevocationEnabled(false);
            CertPathValidatorResult cpvResult = cpv.validate(certPath, params);
            
   
            // Utilizar Chave publica para verificar se assinatura enviada corresponde à recebida
            PublicKey pubKey = certificadoServidor.getPublicKey();
            
            // Verificar assinatura
            sign = Signature.getInstance("SHA256withRSA");
            sign.initVerify(pubKey);
            sign.update(kp.getPublic().getEncoded());
            sign.update(chavePublicaServidor);
            

            // Verificar se são as mesmas
            if(!sign.verify(assinaturaServidor)){
                System.out.println("Assinaturas diferentes");
                return;
            }
            
            // Criar chave a partir das chave DH
            KeyAgreement kagr = KeyAgreement.getInstance("DiffieHellman");
            kagr.init(kp.getPrivate());
            PublicKey clienteDHkey = KeyFactory.getInstance("DiffieHellman").
                    generatePublic(new X509EncodedKeySpec(chavePublicaServidor));
            kagr.doPhase(clienteDHkey,true);
            
            SecretKey chave = kagr.generateSecret("AES");
            
            // Nova chave, com 32 bytes, 256 bits
            byte[] chave32 = new byte[32];
            System.arraycopy(chave.getEncoded(), 0, chave32, 0, 32);
            
            // Chave MAC e Chave AES
            byte[] chaveMAC = new byte[16];
            byte[] chaveAES = new byte[16];

            System.arraycopy(chave32, 0, chaveMAC, 0, 16);
            System.arraycopy(chave32, 16, chaveAES, 0, 16);

            SecretKey mackey = new SecretKeySpec(chaveMAC,"AES");
            SecretKey aeskey = new SecretKeySpec(chaveAES,"AES");
       
            // Ler para imprimir no servidor
            String test;
            BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("[Escreva a mensagem pretendida]");
            while((test = stdIn.readLine()) != null){
                byte[] mensagem = cifrar(test.getBytes(),mackey,aeskey);
                
                if(mensagem == null){
                    System.out.println("Erro a Cifrar mensagem: MAC");
                }
                else{
                    // Enviar mensagem
                    oos.writeObject(mensagem);
                }
            }
            
	}
	catch (IOException | IllegalStateException | NoSuchAlgorithmException ex){
	    System.out.println("Erro 1: InPutStream or OutPutStream or DH");
            System.err.println(ex.getMessage());
        } catch (InvalidAlgorithmParameterException ex) {
            System.out.println("Erro 2: SecureRandom");
            System.err.println(ex.getMessage());
        } catch (InvalidKeySpecException | ClassNotFoundException | SignatureException ex) {
            System.out.println("Erro 3: Private and Public Key RSA or Assinar");
            System.err.println(ex.getMessage());
        } catch (NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException ex) {
            System.out.println("Erro 4: Cifrar");
            System.err.println(ex.getMessage());
        } catch (KeyStoreException | CertificateException | UnrecoverableKeyException ex) {
            System.out.println("Erro 5: Certificado");
            System.err.println(ex.getMessage());
        } catch (CertPathValidatorException ex) {
            System.out.println("Erro 6: Certificado Validador");
            System.err.println(ex.getMessage());
        }
    }

    private static byte[] cifrar(byte[] test,SecretKey keymac,SecretKey keyaes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, SignatureException, IOException {
       
       // Calcular IV
       IvParameterSpec iv = new IvParameterSpec(new SecureRandom().generateSeed(16));
       
       // Cifrar mensagem
       Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
       c.init(Cipher.ENCRYPT_MODE,keyaes,iv);
       byte[] dados = c.doFinal(test); 

       // MAC _ Calcular
       byte[] macBytes = new byte[32];
       Mac mac = Mac.getInstance("HmacSHA256");
       try {
            mac.init(keymac);
            macBytes = mac.doFinal(dados);
       } catch (InvalidKeyException ex) {
            System.out.println("Erro a inicializar: mac " + ex.getMessage());
            return null;
        }

       // Mensagem a enviar
       byte[] mensagem = new byte[dados.length + 16 + 32];

       // Copiar para mensagem final
       System.arraycopy(iv.getIV(), 0, mensagem, 0, 16);
       System.arraycopy(dados,0,mensagem,16,dados.length);
       System.arraycopy(macBytes, 0, mensagem, 16 + dados.length, 32);
    
       return mensagem;
    }
}
