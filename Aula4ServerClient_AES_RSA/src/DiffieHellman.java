
import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.spec.DHParameterSpec;

// Classe para tratar do protocolo de Diffie Hellman, gerar valores aleatorios

public class DiffieHellman {
    
    // P
    public static BigInteger p = new BigInteger("994940966501393371061869339776185139741462748315667681795817"
               + "59037259788798151499814653951492724365471316253651463342255785311748602922"
               + "45879520138244532349993162545127260017318013612324544120413351580049591724"
               + "20118635587217233036615233725724772116201440388096736925120255666737469935"
               + "93384600667047373692203583"); 
    
    // G
    public static BigInteger g = new BigInteger("4415740483796032876887268067768680265099916322676669479765081"
               + "037907641646314726540108449111366762405455733539476160487688244692492984068"
               + "199010697431493501550157133302477317244035247535875066821344460735387275465"
               + "080503191286669211981937704190164273245591150986772821839454274533001407104"
               + "0326856846990119719675");

    // Algoritmo
    private static final String ALGORITHM = "DiffieHellman";

    // Constutor
    public DiffieHellman(){
        this.gerador();
    }
    
    // Gerador P e G
    private void gerador() {
        try {
            // gerador para algoritmo
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance(ALGORITHM);
            paramGen.init(1024,new SecureRandom());
            
            AlgorithmParameters params = paramGen.generateParameters();
            
            DHParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);
           
            // P
            DiffieHellman.p = dhSpec.getP();
            
            // G
            DiffieHellman.g = dhSpec.getG();

            
        } catch (NoSuchAlgorithmException ex) {
           System.out.println("Erro 1: Algoritmo");
           System.err.println(ex.getMessage());
        } catch (InvalidParameterSpecException ex) {
            System.out.println("Erro 2: Algoritmo");
           System.err.println(ex.getMessage());
        }
    }
    
}
