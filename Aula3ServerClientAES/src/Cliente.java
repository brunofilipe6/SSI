import java.net.*;
import java.io.*;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Cliente {

    static public void main(String []args) {
	try {
	    Socket s = new Socket("localhost",4567);

	    ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
	    ObjectInputStream ois = new ObjectInputStream(s.getInputStream());

	    String test;
            BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
            
            // Protocolo DiffieHellman
            DiffieHellman dh = new DiffieHellman();
            
            // Gerar y, com 1024 bits
            BigInteger y = new BigInteger(1024,new SecureRandom());
            BigInteger gy = dh.gerarValor(y);
            
            // Enviar para o servidor o gy
            oos.writeObject(gy);

            // Espera Receber do Servidor o gx
            BigInteger gx = (BigInteger)ois.readObject();
            
            // Calcula gxy
            BigInteger gxy = dh.elevarCalcular(gx,y);
            
            // Obtem a masterkey (key + mac), 32 bytes
            // Usada uma função de hash para derivar as chaves usadas no AES e MAC 
            // cada chave com 128 bits, 16 bytes
            MessageDigest hash = MessageDigest.getInstance("SHA-256");  
            byte[] master = hash.digest(gxy.toByteArray());
            
            byte[] key = new byte[16];
            byte[] mac = new byte[16];
            
            System.arraycopy(master, 0, key, 0, 16);
            System.arraycopy(master, 16, mac, 0, 16);
            
            // Create SecretKeys
            SecretKeySpec chaveCifra = new SecretKeySpec(key, "AES");
            SecretKey chaveMac = new SecretKeySpec(mac,"AES");
            
            // Modo CBC, Cifra criada, AES
            Cipher cifraAES = Cipher.getInstance("AES/CBC/PKCS5Padding");
            
            // Aplicar a cifra
            while((test=stdIn.readLine())!=null) {

                // Obter valor IvParameterSpec
                IvParameterSpec valorIV = new IvParameterSpec((new SecureRandom()).generateSeed(16));
                
                // Inicia a cifra
                cifraAES.init(Cipher.ENCRYPT_MODE, chaveCifra,valorIV);
                
                // Converter String to bytes e cifra
                byte[] dados = test.getBytes();
                byte[] dadosCifrados = cifraAES.doFinal(dados);
                
                // Calcular Mac
                byte[] dadosMac;
                Mac macAux = Mac.getInstance("HmacSHA256");
                macAux.init(chaveMac);
                dadosMac = macAux.doFinal(dadosCifrados);
                
                // Juntar dados e enviar
                byte[] send = new byte[dadosCifrados.length + dadosMac.length + 16];
                System.arraycopy(dadosCifrados, 0, send, 0, dadosCifrados.length);
                System.arraycopy(dadosMac, 0, send, dadosCifrados.length, dadosMac.length);
                System.arraycopy(valorIV.getIV(), 0, send, dadosCifrados.length + dadosMac.length, 16);
                
                // Enviar dados
                oos.writeObject(send);
      	    }
	}
	catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | IllegalStateException e){
	    System.out.println(e.getMessage());
	}
    }
}
