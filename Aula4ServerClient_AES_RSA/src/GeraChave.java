
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

/*
 * Gerar , para utilizar
 */

public class GeraChave {
    
    // Nome dos ficheiros das chaves
    private final String privateKeyName;
    private final String publicKeyName;
    
    // Contrutor
    public GeraChave(final String privateName, final String publicName){
       this.privateKeyName = privateName;
       this.publicKeyName = publicName;
    }
    
    // Main para gerar chaves de cliente
    public static void main(String[] args) {
        GeraChave geraChave = new GeraChave("ClientePrivate","ClientePublic");
        geraChave.gerador();
    }

    // Gerador de chaves
    public void gerador(){
        
        try {
            
            // Gerador de Chaves (publica e secreta)
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024, new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();
            
            // Obter chaves
            PrivateKey privateKey = kp.getPrivate();
            PublicKey publicKey = kp.getPublic();
            
            // Guardar chave privada em bytes
            try (ObjectOutputStream outpriv = new ObjectOutputStream(new FileOutputStream("test/" + this.privateKeyName))){
                outpriv.writeObject(privateKey.getEncoded());
            }
           
            // Guardar no ficheiro a chave publica em bytes
            try ( ObjectOutputStream outpub = new ObjectOutputStream(new FileOutputStream("test/" + this.publicKeyName))) {
                outpub.writeObject(publicKey.getEncoded());
            }
        }   catch (NoSuchAlgorithmException ex) {
            System.out.println("Erro 1: RSA");
            System.err.println(ex.getMessage());
        } catch (IOException ex) {
           System.out.println("Erro 2: Guardar Chave privada");
           System.err.println(ex.getMessage());
        }
    }
    
}