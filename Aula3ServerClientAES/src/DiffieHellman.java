
import java.math.BigInteger;


// Classe para tratar do protocolo de Diffie Hellman

public class DiffieHellman {
    
    BigInteger p;
    BigInteger g;
    
    public DiffieHellman(){
       this.p = new BigInteger("994940966501393371061869339776185139741462748315667681795817"
               + "59037259788798151499814653951492724365471316253651463342255785311748602922"
               + "45879520138244532349993162545127260017318013612324544120413351580049591724"
               + "20118635587217233036615233725724772116201440388096736925120255666737469935"
               + "93384600667047373692203583"); 
       this.g = new BigInteger("4415740483796032876887268067768680265099916322676669479765081"
               + "037907641646314726540108449111366762405455733539476160487688244692492984068"
               + "199010697431493501550157133302477317244035247535875066821344460735387275465"
               + "080503191286669211981937704190164273245591150986772821839454274533001407104"
               + "0326856846990119719675");
    }
    
    // Gerar elemento
    // Recebe a chave de 1024 bits e aplica e calcula o valor
    // fazer gx mod p
    public BigInteger gerarValor(BigInteger letra){
        return this.g.modPow(letra, this.p);
    }
    
    // fazer (gx elevado a y) mode p
    public BigInteger elevarCalcular(BigInteger gletra,BigInteger letra){
        return gletra.modPow(letra, this.p);
    }
    
}
