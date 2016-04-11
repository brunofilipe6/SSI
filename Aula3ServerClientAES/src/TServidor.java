import java.net.*;
import java.io.*;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
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
            
            // Protocolo DiffieHellman
            DiffieHellman dh = new DiffieHellman();
            
            // Gerar x, com 1024 bits
            BigInteger x = new BigInteger(1024,new SecureRandom());
            BigInteger gx = dh.gerarValor(x);
        
            // Espera por receber o valor de gy (do cliente)
            BigInteger gy = (BigInteger)ois.readObject();
            
            // Envia para o cliente o gx
            oos.writeObject(gx);
            
            // Calcular o gy^x
            BigInteger gyx = dh.elevarCalcular(gy, x);
            
            // Obtem a masterkey (key + mac), 32 bytes
            // Usada uma função de hash para derivar as chaves usadas no AES e MAC 
            // cada chave com 128 bits, 16 bytes
            MessageDigest hash;  
            try {
                hash = MessageDigest.getInstance("SHA-256");
                byte[] master = hash.digest(gyx.toByteArray());
           
                byte[] key = new byte[16];
                byte[] mac = new byte[16];
            
                System.arraycopy(master, 0, key, 0, 16);
                System.arraycopy(master, 16, mac, 0, 16);

                // Create SecretKeys
                SecretKeySpec chaveCifra = new SecretKeySpec(key, "AES");
                SecretKey chaveMac = new SecretKeySpec(mac,"AES");
            
                // Cifra AES e PADDING
                Cipher cifraAES = Cipher.getInstance("AES/CBC/PKCS5Padding");
            
            
                try {
                    
                    // Aplicar a cifra AES
                    while (true) {
                        test = (byte[])ois.readObject();
                        
                        // Contruir iv, dadosCifrados, mac
                        byte[] valorIV = new byte[16];
                        byte[] valorMAC = new byte[32];
                        byte[] dadosCifrados = new byte[test.length-32-16];
                        
                        System.arraycopy(test, 0, dadosCifrados, 0, test.length-32-16);
                        System.arraycopy(test, test.length-32-16, valorMAC, 0, 32);
                        System.arraycopy(test, test.length-16, valorIV,0, 16);
                        
                        IvParameterSpec vIV = new IvParameterSpec(valorIV);
                       
                        // Iniciar a cifra para decifrar
                        cifraAES.init(Cipher.DECRYPT_MODE, chaveCifra, vIV);
                        
                        // Obter o que o cliente realmente escreveu
                        byte[] dadosOriginais = cifraAES.doFinal(dadosCifrados);

                        // Calcular MAC
                        Mac macAux = Mac.getInstance("HmacSHA256");
                        macAux.init(chaveMac);
                        byte[] mac2 = macAux.doFinal(dadosCifrados);
                        
                        // Verificar se são iguais
                        if(Arrays.equals(valorMAC, mac2)){
                            String nova = new String(dadosOriginais);
                            System.out.println(ct + " : " + nova);
                        }
                        else{
                            System.out.println(ct + " : " + "MACS não correspondem");
                        }
                        
                    }
                } 
                catch (EOFException e) {
                            System.out.println("["+ct + "]");
                } catch (InvalidKeyException | InvalidAlgorithmParameterException ex) {
                    System.out.println("Erro: ValorIV");
                } catch (IllegalBlockSizeException | BadPaddingException ex) {
                    System.out.println("Erro: Decifrar");
                } 
                finally {
                    if (ois!=null) ois.close();
                    if (oos!=null) oos.close();
                }
            
            
            
            } catch (NoSuchAlgorithmException ex) {
                System.out.println("Erro1: Falha na função de hash");
            } catch (NoSuchPaddingException ex) {
                System.out.println("Erro2: Instanciar Padding");
            }
            
	} catch (IOException | ClassNotFoundException e) {
	    System.out.println(e.getMessage());
	} 
    }
}
