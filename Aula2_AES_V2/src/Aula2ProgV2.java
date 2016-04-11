
import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import javax.crypto.SecretKey;
import static java.lang.System.out;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import static java.security.KeyStore.getInstance;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 
 *  Classe para arrancar o programa
 *  Cifra AES
 *  Com MasterKey: 256 bits, 32 bytes
 *  128 bits para chaveSecreta, 16 bytes
 *  128 bits para chaveMac, 16 bytes
 *  Melhoria na criação da chave
 * 
 */


public class Aula2ProgV2 {

    public static void main(String[] args) {
        
        imprimirMenu();
        
        if(args.length >= 1){

            switch(args[0]){

                case "-genKey":
                        // Gerar chave
                        if(args.length == 2){
                            geraChave(args[1]);
                        }
                        else{
                             System.out.println("Não foram inseridos parâmetros suficientes para gerar a chave!");   
                        }
                        break;

                case "-enc":
                        // Cifrar
                        if(args.length == 4){
                            cifrarChave(args[1],args[2],args[3]);
                        }
                        else{
                             System.out.println("Não foram inseridos parâmetros suficientes para cifrar!");   
                        }
                        break;

                case "-dec":
                        // Decifrar
                        if(args.length == 4){
                            decifrarChave(args[1],args[2],args[3]);
                        }
                        else{
                             System.out.println("Não foram inseridos parâmetros suficientes para decifrar!");   
                        }
                        break;

                default:
                        System.out.println("Não foram inseridos parâmetros válidos!");
                        break;
            } 
         }
        else{
            System.out.println("Não foram inseridos parâmetros!");
        }
    }

    // Gerar chave
    private static void geraChave(String chaveFile) {
        
        try {
            
            // Aceder ao KeyStore
            KeyStore keys = getInstance("JCEKS");
            
            // Pedir password
            Console cnsl = System.console();
            char[] ficheiroPassword = cnsl.readPassword("Insira a password da Chave: ");
        
            // Ficheiro recebido
            File ficheiro = new File(chaveFile);
                
            //  Verificar se ficheiro existe
            if (ficheiro.exists()) {
                keys.load(new FileInputStream(ficheiro), ficheiroPassword);
            } 
            // Caso contrário cria-se
            else {
                // é preciso fazer o load do keystore
                keys.load(null, null);
                keys.store(new FileOutputStream(ficheiro),ficheiroPassword);
            }
        
            // Gerar chave com 256 bits, 32 bytes, AES KEY     
            KeyGenerator gerador = KeyGenerator.getInstance("AES");
            gerador.init(256);
            SecretKey chaveSecreta = gerador.generateKey();

            // Uma entrada de armazenamento de chaves que contém uma chave secreta
            SecretKeyEntry ske = new SecretKeyEntry(chaveSecreta);
            
            // Senha para proteger password
            PasswordProtection pp = new PasswordProtection(ficheiroPassword);
            keys.setEntry("securityKey", ske, pp);
            keys.store(new FileOutputStream(ficheiro), ficheiroPassword);
            
            System.out.println("Chave criada com sucesso!");
        } 
        catch (KeyStoreException ex) {
            System.out.println("Erro1: " + ex);
        } 
        catch (FileNotFoundException ex) {
            System.out.println("Erro2: " + ex);
        } 
        catch (IOException ex) {
            System.out.println("Erro3: " + ex);
        } 
        catch (NoSuchAlgorithmException ex) {
            System.out.println("Erro4: " + ex);
        } 
        catch (CertificateException ex) {
            System.out.println("Erro5: " + ex);
        }      
    }   
    
    // imprimir Menu
    private static void imprimirMenu(){
        out.println("Menu:");
        out.println("------------- CIFRA RC4 -------------");
        out.println("Gerar Chaves: prog -genKey <inputFile>");
        out.println("Gerar Chaves: prog -enc <inputFile> <inputFile> <outputFile>");
        out.println("Gerar Chaves: prog -dec <inputFile> <inputFile> <outputFile>");
    }

    // Decifrar Chave
    private static void decifrarChave(String chaveFile,String textoLimpo, String textoCodificado) {
        cifdec(Cipher.DECRYPT_MODE,chaveFile,textoLimpo,textoCodificado);
    }

    // Cifrar Chave
    private static void cifrarChave(String chaveFile, String textoCodificado, String textoLimpo2) {
        cifdec(Cipher.ENCRYPT_MODE,chaveFile,textoCodificado,textoLimpo2);
    }
    
    // Cifrar & Decifrar
    private static void cifdec(int modo, String chaveFile,String in, String out) {
        
        // Verificar se ficheiro da chave existe
        File ficheiroChave = new File(chaveFile);
        
        // Pedir password
        Console cnsl = System.console();
        char[] passwordChave = cnsl.readPassword("Insira a password da Chave: ");
        
        
        if(!ficheiroChave.exists()){
            System.out.println("Ficheiro " + chaveFile + " não existe!");
            return;
        }
        
        try {
            // Usar chave do ficheiro e carregar
            KeyStore keystore = getInstance("JCEKS");
            keystore.load(new FileInputStream(ficheiroChave),passwordChave);
            
            PasswordProtection pass = new PasswordProtection(passwordChave);
            SecretKeyEntry chave = (SecretKeyEntry) keystore.getEntry("securityKey", pass);
            
            // Dividir a MasterKey
            byte[] chaves = chave.getSecretKey().getEncoded();
            
            // 128 bits, 16 bytes
            byte[] keyMAC = new byte[16];
            byte[] keyCIFRA = new byte[16];
            
            // copiar 8 bytes para cada chave
            System.arraycopy(keyCIFRA, 0, chaves, 0, 8);
            System.arraycopy(keyMAC, 0, chaves, 8, 16);
            
            // Obter chave para o mac e chave para a cifra
            SecretKeySpec chaveCifra = new SecretKeySpec(keyCIFRA, "AES");
            SecretKey chaveMac = new SecretKeySpec(keyMAC, "AES");
            
            // Cifra AEs
            Cipher cifraAES = Cipher.getInstance("AES/CBC/PKCS5Padding");
            
            // Ler bytes do ficheiro
            byte[] ficheiroIn;

            try{
                ficheiroIn = lerBytesFile(in);
            }
            catch (IOException ex) {
                System.out.println("Erro ao ler do ficheiro");
                return;
            } 

            if(ficheiroIn == null){
                System.out.println("Erro na leitura do ficheiro in");
                return;
            }
                
            // Cifrar
            if(modo == Cipher.ENCRYPT_MODE){
                
                // Obter valor IvParameterSpec
                IvParameterSpec valorIV = new IvParameterSpec((new SecureRandom()).generateSeed(16));
                
                try {
                    cifraAES.init(Cipher.ENCRYPT_MODE, chaveCifra,valorIV);
                } catch (InvalidKeyException | InvalidAlgorithmParameterException ex) {
                    System.out.println("Erro ao inicializar a cifra");
                    return;
                }
                
                // Encriptar os dados do bytes do ficheiro in
                byte[] dados;
                try {
                    dados = cifraAES.doFinal(ficheiroIn);
                } catch (IllegalBlockSizeException | BadPaddingException ex) {
                    System.out.println("Erro a codificar os dados lidos");
                    return;
                }
                
                if(dados == null) {
                    System.out.println("Erro a codificar os dados lidos");
                    return;
                }
                
                // MAC _ Calcular
                byte[] macBytes = new byte[32];
                Mac mac = Mac.getInstance("HmacSHA256");
                try {
                    mac.init(chaveMac);
                    macBytes = mac.doFinal(dados);
                } catch (InvalidKeyException ex) {
                    System.out.println("Erro a inicializar: mac");
                    return;
                }
                
                // utilizar mac para encriptar dados
                byte[] dadosAux = new byte[dados.length + 16 + 32];
                System.arraycopy(dados, 0, dadosAux, 0, dados.length);
                System.arraycopy(valorIV.getIV(), 0, dadosAux, dados.length, 16);
                System.arraycopy(macBytes, 0, dadosAux, dados.length + 16, 32);
                

                // Escrever no ficheiro destino
                try{
                    escreverBytesFile(out,dadosAux);
                }
                catch(FileNotFoundException ex){
                    System.out.println("Erro ao escrever no ficheiro out");
                }
                catch(IOException ex){
                    System.out.println("Erro ao escrever no ficheiro out");
                } 
                
                System.out.println("Ficheiro cifrado com sucesso!");
                
            }
            
            // Decifrar
            else{
                
                // Obter Mac, Valor do IV e dados em modo AEs
                byte[] dadosAES = new byte[ficheiroIn.length - 32 - 16];
                byte[] valorIV = new byte[16];
                byte[] mac = new byte[32];
                
                System.arraycopy(ficheiroIn, 0, dadosAES, 0, ficheiroIn.length - 32 - 16);
                System.arraycopy(ficheiroIn, ficheiroIn.length - 32 - 16, valorIV,0,16);
                System.arraycopy(ficheiroIn, ficheiroIn.length - 32, mac, 0, 32);
               
                try {
                    // inicializar cifra para decifrar
                    cifraAES.init(Cipher.DECRYPT_MODE, chaveCifra, new IvParameterSpec(valorIV));
                } catch (InvalidKeyException | InvalidAlgorithmParameterException ex) {
                    System.out.println("Erro a inicializar a cifra na decifração");
                    return;
                }
                
                // Para obter texto limpo
                byte[] dados;
                try {
                    dados = cifraAES.doFinal(dadosAES);
                } catch (IllegalBlockSizeException | BadPaddingException ex) {
                    System.out.println("Erro na conversão dos dados");
                    return;
                }
                
                if(verificarMac(mac,chaveMac,dadosAES)){

                    //Escrever no ficheiro destino
                    try{
                        escreverBytesFile(out,dados);
                    }
                    catch(FileNotFoundException ex){
                        System.out.println("Erro ao escrever no ficheiro out");
                    }
                    catch(IOException ex){
                        System.out.println("Erro ao escrever no ficheiro out");
                    }
                }
                else{
                    System.out.println("Erro ao decifrar, MAC não é o mesmo que foi criado a cifrar");
                }
                
                System.out.println("Ficheiro Decifrado com sucesso!");
                
            }
            
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException ex) {
            System.out.println("Erro Adquirir keystore");
        } catch (FileNotFoundException ex) {
            System.out.println("Erro Adquirir keystore");
        } catch (IOException ex) {
            System.out.println("Erro Adquirir keystore");
        } catch (UnrecoverableEntryException ex) {
            System.out.println("Erro Adquirir SecretKeyEntry");
        } catch (NoSuchPaddingException ex) {
            System.out.println("Erro getInstance");
        }     
    }
    
    // Funcao para guardar nos ficheiros pretendidos
    private static byte[] lerBytesFile(String in) throws IOException{
      byte[] ficheiroInBytes = Files.readAllBytes(Paths.get(in));
      return ficheiroInBytes;
    }
    
    private static void escreverBytesFile(String out, byte[] bytes) throws FileNotFoundException, IOException{
            FileOutputStream ficheiroOut = new FileOutputStream(out);
            ficheiroOut.write(bytes);
            ficheiroOut.close();
    }

    // Verificar se os macs das mensagens são iguais, para verificar se mensagem é a mesma
    private static boolean verificarMac(byte[] mac, SecretKey chave, byte[] dadosAES){
        
        try{
            Mac macAux = Mac.getInstance("HmacSHA256");
            macAux.init(chave);
            return Arrays.equals(mac, macAux.doFinal(dadosAES));  
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            System.out.println("Erro no calculo do MAC");
        }
        return false;
    }
}
