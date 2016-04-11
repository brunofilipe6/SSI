import java.net.*;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
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
            
            /// Chaves RSA
            PrivateKey chaveRSApriv = obterChavePrivadaCliente("test/ServidorPrivate");
            PublicKey chaveRSApub = obterChavePublicaCliente("test/ClientePublic");
            
            // Enviar para cliente ChavePublica do Servidor DH
            oos.writeObject(kp.getPublic().getEncoded());
          
            // Recebe ChavePublica Cliente DH
            byte[] chavePublicaCliente = (byte[])ois.readObject();
            
            // Recebe assinatura 
            byte[] assinaturaCliente = (byte[])ois.readObject();
            
            // Verificar assinatura
            Signature sign = Signature.getInstance("SHA256withRSA");
            sign.initVerify(chaveRSApub);
            sign.update(chavePublicaCliente);
            sign.update(kp.getPublic().getEncoded());
            
            if(!sign.verify(assinaturaCliente)){
                return;
            }
            
            // Assinar com a chave privada servidor e enviar para cliente
            sign.initSign(chaveRSApriv);
            sign.update(chavePublicaCliente);
            sign.update(kp.getPublic().getEncoded());
            byte[] assinaturaServidor = sign.sign();
            
            // Enviar para cliente AssinaturaServidor
            oos.writeObject(assinaturaServidor);
            
            // Criar chave a partir das chave DH
            KeyAgreement kagr = KeyAgreement.getInstance("DiffieHellman");
            kagr.init(kp.getPrivate());
            PublicKey servidorDHkey = KeyFactory.getInstance("DiffieHellman").
                    generatePublic(new X509EncodedKeySpec(chavePublicaCliente));
            kagr.doPhase(servidorDHkey,true);
            
            SecretKey chave = kagr.generateSecret("AES");
            
            // Nova chave, com menos bits do que a chave DH
            byte[] chave16 = new byte[16];
            System.arraycopy(chave.getEncoded(), 0, chave16, 0, 16);
            SecretKey novaChave = new SecretKeySpec(chave16,0,16,"AES");
            
            // Ler e imprimir
            System.out.println("["+ct+" Hello]");
            while(true){
                byte[] dados = (byte[])ois.readObject();
                byte[] assinatura = (byte[])ois.readObject();
                byte[] dadosOriginais = decifrar(novaChave,sign,dados,assinatura,chaveRSApub);
                
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
        }
    }
    
    /** Obter Chave Publica do Ficheiro do Cliente */
    private static PublicKey obterChavePublicaCliente(String fileKeyPublic) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException{
        try (ObjectInputStream inpub = new ObjectInputStream(new FileInputStream(fileKeyPublic))){
            byte[] pub = (byte[]) inpub.readObject();
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(new X509EncodedKeySpec(pub));
        }    
    }
    
    /** Obter Chave Privada do Ficheiro do Cliente */
    private static PrivateKey obterChavePrivadaCliente(String fileKeyPrivate) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, ClassNotFoundException {
        try (ObjectInputStream inpriv = new ObjectInputStream(new FileInputStream(fileKeyPrivate))){
            byte[] priv = (byte[]) inpriv.readObject();
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return (PrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(priv));
        }    
    }

    private byte[] decifrar(SecretKey novaChave, Signature sign, byte[] mensagem, byte[] assinatura, PublicKey chaveRSApub) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, SignatureException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        
       // Obter IV
       byte[] iv = new byte[16];
       System.arraycopy(mensagem, 0, iv, 0, 16);

       // obter mensagem restante
       byte[] dadosCifrados = new byte[mensagem.length - 16];
       System.arraycopy(mensagem,16,dadosCifrados,0,mensagem.length - 16);
       
       // Calcular assinatura e verificar
       sign.initVerify(chaveRSApub);
       sign.update(dadosCifrados);
       
       if(sign.verify(assinatura)){
           // Decifrar mensagem
           Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
           c.init(Cipher.DECRYPT_MODE,novaChave,new IvParameterSpec(iv));
           return c.doFinal(dadosCifrados);   
       }
       return null;
    }
}