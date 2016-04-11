import java.net.*;

public class Servidor {
    
    // Numero de clientes
    static private int tcount;
	
    static public void main(String []args) {
	tcount = 0;
	try {
	    ServerSocket ss = new ServerSocket(4567);
	    
            // Gerar Chave RSA (Servidor sempre as mesmas)
            GeraChave g = new GeraChave("ServidorPrivate","ServidorPublic");
            g.gerador();
        
            // Chaves criadas com sucesso!
            System.out.println("Chaves do servidor criadas com sucesso!");
            
            // Sempre que um cliente se ligar à porta do servidor
            // é inicializada uma thread para cada um
	    while(true) {
		Socket s = ss.accept();
		tcount++;
		TServidor ts = new TServidor(s,tcount);
	        ts.start();
	    }
	}
	catch (Exception e){
            System.out.println(e.getMessage());
	}
    }
}