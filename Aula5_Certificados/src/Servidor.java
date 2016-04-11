import java.net.*;

public class Servidor {
    
    // Numero de clientes
    static private int tcount;
	
    static public void main(String []args) {
	tcount = 0;
	try {
	    ServerSocket ss = new ServerSocket(4567);

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