import java.net.*;
import java.io.*;
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

// Thread para cada cliente

public class TServidor extends Thread {
    
    private final int ct;
    protected Socket s;

    TServidor(Socket s, int c) {
	this.ct = c;
	this.s = s;
    }

    @Override
    public void run() {
	try {
            
            ObjectInputStream ois = new ObjectInputStream(this.s.getInputStream());
            ObjectOutputStream oos = new ObjectOutputStream(this.s.getOutputStream());
	    byte[] test;
            
            // Gerar chave publica e privada DH
            DHParameterSpec dhps = new DHParameterSpec(DiffieHellman.p,DiffieHellman.g);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman");
            kpg.initialize(dhps, new SecureRandom());
            
            // Par de chaves DH
            KeyPair kp = kpg.generateKeyPair();
            
            // Enviar para cliente ChavePublica do Servidor DH
            oos.writeObject(kp.getPublic().getEncoded());
          
            // Recebe ChavePublica Cliente DH
            byte[] chavePublicaCliente = (byte[])ois.readObject();
            
            // Recebe assinatura 
            byte[] assinaturaCliente = (byte[])ois.readObject();
            
            // Recebe Certificado
            Certificate certificadoCliente = (Certificate) ois.readObject();
            
            
            // Preparar certificado recebido para verificação
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");  
            CertPath certPath = certFactory.generateCertPath(Arrays.asList(certificadoCliente));
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
            PublicKey pubKey = certificadoCliente.getPublicKey();
            
            // Verificar assinatura
            Signature sign = Signature.getInstance("SHA256withRSA");
            sign.initVerify(pubKey);
            sign.update(chavePublicaCliente);
            sign.update(kp.getPublic().getEncoded());
            
            if(!sign.verify(assinaturaCliente)){
                return;
            }
            
            // Certificado Servidor
            String certificadoServidor = "test/Servidor.p12";
            String aliasServidor = "Servidor";
            char[] password = "1234".toCharArray();
            
            FileInputStream fIn = new FileInputStream(certificadoServidor);
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(fIn, password);
            
            // Obter chave privada do Certificado Cliente.p12
            PrivateKey privKey = (PrivateKey) keyStore.getKey(aliasServidor, password);
            
            // Assinar com a chave privada servidor e enviar para cliente
            sign.initSign(privKey);
            sign.update(chavePublicaCliente);
            sign.update(kp.getPublic().getEncoded());
            byte[] assinaturaServidor = sign.sign();
            
            // Enviar para cliente AssinaturaServidor
            oos.writeObject(assinaturaServidor);
            
            // Enviar Certificado para o cliente
            Certificate[] certArrayCliente = keyStore.getCertificateChain(aliasServidor);
            oos.writeObject(certArrayCliente[0]);
            
            
            // Criar chave a partir das chave DH
            KeyAgreement kagr = KeyAgreement.getInstance("DiffieHellman");
            kagr.init(kp.getPrivate());
            PublicKey servidorDHkey = KeyFactory.getInstance("DiffieHellman").
                    generatePublic(new X509EncodedKeySpec(chavePublicaCliente));
            kagr.doPhase(servidorDHkey,true);
            
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
            
            // Ler e imprimir
            System.out.println("["+ct+" Hello]");
            while(true){
                byte[] dados = (byte[])ois.readObject();
                byte[] dadosOriginais = decifrar(dados, mackey, aeskey);
                
                if(dadosOriginais == null){
                    System.out.println("Mensagem com erros!");
                }
                else{
                    System.out.println(ct + " : " + new String(dadosOriginais));
                }
            }
                    
	} catch(EOFException ex){
            System.out.println("["+ct+"]");
        } catch (IOException ex) {
	    System.out.println("Erro 1: OutPutStream and InPutStream");
            System.err.println(ex.getMessage());
	} catch (NoSuchAlgorithmException ex) { 
            System.out.println("Erro 2: GetInstance DH");
            System.err.println(ex.getMessage());
        } catch (InvalidAlgorithmParameterException ex) {
            System.out.println("Erro 3: SecureRandom");
            System.err.println(ex.getMessage());
        } catch (ClassNotFoundException | InvalidKeySpecException ex) {
            System.out.println("Erro 4: Private and Public Key RSA");
            System.err.println(ex.getMessage());
        } catch (InvalidKeyException | SignatureException ex) {
            System.out.println("Erro 5: Assinar");
            System.err.println(ex.getMessage());
        } catch (NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException ex) {
            System.out.println("Erro 6: Decifrar");
            System.err.println(ex.getMessage());
        } catch (CertificateException | KeyStoreException | UnrecoverableKeyException ex) {
            System.out.println("Erro 7: Certificados");
            System.err.println(ex.getMessage());
        } catch (CertPathValidatorException ex) {
            System.out.println("Erro 8: Certificados Validador");
            System.err.println(ex.getMessage());
        }
    }

    private byte[] decifrar(byte[] mensagem,SecretKey mackey, SecretKey aeskey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, SignatureException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        
       // Obter IV
       byte[] iv = new byte[16];
       System.arraycopy(mensagem, 0, iv, 0, 16);
       
       // Obter MAC
       byte[] macRecebido = new byte[32];
       System.arraycopy(mensagem, mensagem.length - 32, macRecebido, 0, 32);
       
       // Mensagem Cifrada
       byte[] mensagemCifrada = new byte[mensagem.length - 32 - 16];
       System.arraycopy(mensagem, 16, mensagemCifrada, 0, mensagem.length - 32 - 16);

       // Decifrar mensagem
       Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
       c.init(Cipher.DECRYPT_MODE,aeskey,new IvParameterSpec(iv));
       byte[] mensagemOriginal = c.doFinal(mensagemCifrada);
       
       // MAC _ Calcular
       byte[] macBytes = new byte[32];
       Mac mac = Mac.getInstance("HmacSHA256");
       try {
            mac.init(mackey);
            macBytes = mac.doFinal(mensagemCifrada);
       } catch (InvalidKeyException ex) {
            System.out.println("Erro a inicializar: mac " + ex.getMessage());
            return null;
        }
       
       // Verificar mac
       if(Arrays.equals(macBytes, macRecebido)){
           return mensagemOriginal;
       }
       else{
           return null;
       }
    }
}