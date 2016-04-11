
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
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.AbstractMap;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
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
            
            // Chaves RSA
            PrivateKey chaveRSApriv = obterChavePrivadaCliente("test/ClientePrivate");
            PublicKey chaveRSApub = obterChavePublicaCliente("test/ServidorPublic");
            
            // Recebe do servidor a chave publica DH
            byte[] chavePublicaServidor = (byte[])ois.readObject();
            
            // Envia para o servidor a ChavePublica do cliente DH
            oos.writeObject(kp.getPublic().getEncoded());
            
            // Assinar e enviar assinatura
            Signature sign = Signature.getInstance("SHA256withRSA");
            sign.initSign(chaveRSApriv);
            sign.update(kp.getPublic().getEncoded());
            sign.update(chavePublicaServidor);
            
            byte[] assinatura = sign.sign();
            
            // Enviar para o servidor a assinatura
            oos.writeObject(assinatura);
            
            // Receber assinatura do servidor
            byte[] assinaturaServidor = (byte[])ois.readObject();
            
            // Comparar assinatura
            sign.initVerify(chaveRSApub);
            sign.update(kp.getPublic().getEncoded());
            sign.update(chavePublicaServidor);
            

            // Verificar se são as mesmas
            if(!sign.verify(assinaturaServidor)){
                return;
            }
            
            // Criar chave a partir das chave DH
            KeyAgreement kagr = KeyAgreement.getInstance("DiffieHellman");
            kagr.init(kp.getPrivate());
            PublicKey clienteDHkey = KeyFactory.getInstance("DiffieHellman").
                    generatePublic(new X509EncodedKeySpec(chavePublicaServidor));
            kagr.doPhase(clienteDHkey,true);
            
            SecretKey chave = kagr.generateSecret("AES");
            
            // Nova chave, com 16 bytes, 128 bits
            byte[] chave16 = new byte[16];
            System.arraycopy(chave.getEncoded(), 0, chave16, 0, 16);
            SecretKey novaChave = new SecretKeySpec(chave16,0,16,"AES");
            
            // Ler para imprimir no servidor
            String test;
            BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("[Escreva a mensagem pretendida]");
            while((test = stdIn.readLine()) != null){
                Map.Entry<byte[],byte[]> mensagem = cifrar(test.getBytes(),sign,chaveRSApriv,novaChave);
                // Enviar mensagem
                oos.writeObject(mensagem.getKey());
                // Enviar assinatura
                oos.writeObject(mensagem.getValue());
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
            System.out.println("Erro 4: Cifrar e enviar");
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

    private static Map.Entry<byte[],byte[]> cifrar(byte[] test, Signature signa, PrivateKey chaveRSApriv, SecretKey chave) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, SignatureException, IOException {
       
       // Cifrar mensagem
       IvParameterSpec iv = new IvParameterSpec(new SecureRandom().generateSeed(16));
       Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
       c.init(Cipher.ENCRYPT_MODE,chave,iv);
       byte[] dados = c.doFinal(test); 
       
       // Assinar mensagem
       signa.initSign(chaveRSApriv);
       signa.update(dados);
       byte[] dadosAssinados = signa.sign();
       
       // Mensagem a enviar
       byte[] mensagem = new byte[dados.length + 16];

       // Copiar para mensagem final
       System.arraycopy(iv.getIV(), 0, mensagem, 0, 16);
       System.arraycopy(dados,0,mensagem,16,dados.length);

       // Enviar mensagem e assinatura
       return new AbstractMap.SimpleEntry<>(mensagem,dadosAssinados);
    }
}
