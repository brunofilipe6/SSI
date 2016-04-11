
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import static java.lang.System.out;
import java.security.InvalidKeyException;
import static java.security.KeyStore.getInstance;
import java.security.UnrecoverableEntryException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;

/**
 * 
 *  Classe para arrancar o programa
 *  Cifra RC4
 * 
 */


public class Aula1Prog {

    public static void main(String[] args) {
        
        imprimirMenu();
        
        if(args.length >= 1){

            switch(args[0]){

                case "-genKey":
                        // Gerar chave
                        if(args.length == 3){
                            geraChave(args[1],args[2]);
                        }
                        else{
                             System.out.println("Não foram inseridos parâmetros suficientes para gerar a chave!");   
                        }
                        break;

                case "-enc":
                        // Cifrar
                        if(args.length == 5){
                            cifrarChave(args[1],args[2],args[3],args[4]);
                        }
                        else{
                             System.out.println("Não foram inseridos parâmetros suficientes para cifrar!");   
                        }
                        break;

                case "-dec":
                        // Decifrar
                        if(args.length == 5){
                            decifrarChave(args[1],args[2],args[3],args[4]);
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
    private static void geraChave(String chaveFile, String passFile) {
        
        try {
            
            // Aceder ao KeyStore
            KeyStore keys = getInstance("JCEKS");
            
            // Converter password a caracteres
            char[] ficheiroPassword = passFile.toCharArray();
        
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
        
            // Gerar chave secreta para a Cifra RC4
            SecretKey chaveSecreta = KeyGenerator.getInstance("RC4").generateKey();
            // Uma entrada de armazenamento de chaves que contém uma chave secreta
            SecretKeyEntry ske = new SecretKeyEntry(chaveSecreta);
            // Senha para proteger password
            PasswordProtection pp = new PasswordProtection(ficheiroPassword);
            keys.setEntry("securityKey", ske, pp);
            keys.store(new FileOutputStream(ficheiro), ficheiroPassword);
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
        out.println("Gerar Chaves: prog -genKey <inputFile> <passFile>");
        out.println("Gerar Chaves: prog -enc <inputFile> <passFile> <inputFile> <outputFile>");
        out.println("Gerar Chaves: prog -dec <inputFile> <passFile> <inputFile> <outputFile>");
    }

    // Decifrar Chave
    private static void decifrarChave(String chaveFile,String password, String textoLimpo, String textoCodificado) {
        cifdec(Cipher.DECRYPT_MODE,chaveFile,password,textoLimpo,textoCodificado);
    }

    // Cifrar Chave
    private static void cifrarChave(String chaveFile,String password, String textoCodificado, String textoLimpo2) {
        cifdec(Cipher.ENCRYPT_MODE,chaveFile,password,textoCodificado,textoLimpo2);
    }
    
    // Cifrar & Decifrar
    private static void cifdec(int modo, String chaveFile, String password,String in, String out) {
        
        // Verificar se ficheiro da chave existe
        File ficheiroChave = new File(chaveFile);
        char[] passwordChave = password.toCharArray();
        
        if(!ficheiroChave.exists()){
            System.out.println("Ficheiro " + chaveFile + " não existe!");
            return;
        }
        
        // Abrir ficheiros recebidos
        FileInputStream inFile;
        FileOutputStream outFile = null;
        
        try {
            // Verificar se o ficheiro de entrada existe
            inFile = new FileInputStream(in);
        } catch (FileNotFoundException ex) {
            System.out.println("Erro: " + ex);
            return;
        }
        
        try {
            // Verificar se já existe
            outFile = new FileOutputStream(out);
        } catch (FileNotFoundException ex) {
            System.out.println("Ficheiro out criado");
        }
        
        try {
            // Usar chave do ficheiro e carregar
            KeyStore keystore = getInstance("JCEKS");
            keystore.load(new FileInputStream(ficheiroChave),passwordChave);
            
            PasswordProtection pass = new PasswordProtection(passwordChave);
            SecretKeyEntry chave = (SecretKeyEntry) keystore.getEntry("securityKey", pass);
            
            // Chave secreta
            SecretKey chaveSecreta = chave.getSecretKey();
            
            // Cifra RC4
            Cipher cifraRC4 = Cipher.getInstance("RC4");
            
            // Cifrar
            if(modo == Cipher.ENCRYPT_MODE){
                cifraRC4.init(Cipher.ENCRYPT_MODE,chaveSecreta);
                CipherInputStream cis = new CipherInputStream(inFile,cifraRC4);
                copia(cis,outFile);
                System.out.println("Ficheiro cifrado com sucesso");
            }
            // Decifrar
            else{
                cifraRC4.init(Cipher.DECRYPT_MODE,chaveSecreta);
                CipherOutputStream cos = new CipherOutputStream(outFile,cifraRC4);
                copia(inFile,cos);
                System.out.println("Ficheiro decifrado com sucesso");
            }
            
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException ex) {
            System.out.println("Erro Adquirir keystore");
        } catch (FileNotFoundException ex) {
            System.out.println("Erro Adquirir keystore");
        } catch (IOException ex) {
            System.out.println("Erro Adquirir keystore");
        } catch (UnrecoverableEntryException ex) {
            System.out.println("Erro Adquirir SecretKeyEntry");
        } catch (InvalidKeyException ex) {
            System.out.println("Erro init");
        } catch (NoSuchPaddingException ex) {
            System.out.println("Erro getInstance");
        }     
    }
    
    private static void copia(InputStream in, OutputStream out){
        
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        int b;
        try {
            while((b = in.read()) != -1) {
                bos.write(b);
            }
        } catch (IOException ex) {
            System.out.println("Erro a ler bytes do in");
        }
        byte[] ba = bos.toByteArray(); 
        
        try {
            out.write(ba);
        } catch (IOException ex) {
            System.out.println("Erro a copiar bytes para out");
        }
    }
}
