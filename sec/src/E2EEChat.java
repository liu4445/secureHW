import java.net.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.*;

public class E2EEChat {
	private Socket clientSocket = null;

	public Socket getSocketContext() {
		return clientSocket;
	}

	// 접속 정보, 필요시 수정
	private final String hostname = "homework.islab.work";
	private final int port = 8080;
	static PrivateKey myPrivatekey; // 자신의 비밀키
	
	public E2EEChat() throws Exception {
		clientSocket = new Socket();
		clientSocket.connect(new InetSocketAddress(hostname, port));

		InputStream stream = clientSocket.getInputStream();

		Thread senderThread = new Thread(new MessageSender(this));
		senderThread.start();

		while (true) {
			try {
				if (clientSocket.isClosed() || !senderThread.isAlive()) {
					break;
				}

				byte[] recvBytes = new byte[2048];
				int recvSize = stream.read(recvBytes);

				if (recvSize == 0) {
					continue;
				}

				String recv = new String(recvBytes, 0, recvSize, StandardCharsets.UTF_8);

				parseReceiveData(recv);
			} catch (IOException ex) {
				System.out.println("소켓 데이터 수신 중 문제가 발생하였습니다.");
				break;
			}
		}

		try {
			System.out.println("입력 스레드가 종료될때까지 대기중...");
			senderThread.join();

			if (clientSocket.isConnected()) {
				clientSocket.close();
			}
		} catch (InterruptedException ex) {
			System.out.println("종료되었습니다.");
		}
	}

	public void parseReceiveData(String recvData) throws Exception {
		// 여기부터 3EPROTO 패킷 처리를 개시합니다.
		// 3EPROTO 이후의 텍스트에 따라 다음과 같이 처리한다 . 
		String plainText = "";
		String[] recvDatalist = recvData.split(" ");
		String[] temp = recvDatalist[1].split("\n");
		if (temp[0].equals("KEYXCHG")) { 
			//키교환 시 상대방의 공개키를 받아온다.
			//
			MessageSender.desPublicKey = getDeskey(recvData);
			System.out.println(recvData + "\n==== recv ====");

		}

		else if (temp[0].equals("MSGRECV")) {
			//메세지를 받았을 때 본문을 찾아 복호화를 진행하여 평문을 출력한다. 
			String[] temp2 = recvData.split("\n\n");
			String bodytext = temp2[1];
			String[] temp3 = temp2[0].split("\n");
			String[] temp4 = temp3[3].split(":");
			
			plainText = decryptRSA(bodytext, myPrivatekey);
			System.out.println(temp4[1] + ": " + plainText);
			System.out.println("==== recv ====");

		}
		else if (temp[0].equals("MSGSENDOK")) 	
			System.out.println("== MSGSEND ok ==");
			
		else
			System.out.println(recvData + "\n==== recv ====");
	
	}

	public PublicKey getDeskey(String recvData) throws Exception {
		//상대방의 String 형태로 전송된 키를 다시 PublicKey 형태로 만들어주기 전 split을 통해 분해를 해준다.
		String[] temp = recvData.split("\n\n");
		return getPublicKeyFromBase64Encrypted(temp[1]);

	}

	public static String decryptRSA(String encrypted, PrivateKey privateKey) throws Exception {
		//RSA 방식으로 복호화를 진행한다.
		
		Cipher cipher = Cipher.getInstance("RSA");
		byte[] byteEncrypted = Base64.getDecoder().decode(encrypted.getBytes());

		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] bytePlain = cipher.doFinal(byteEncrypted);
		return new String(bytePlain, "UTF-8");
	}
// 	아래 함수는 AES-CBC 에서 사용되었지만 RSA방식에서는 사용되지않기떄문에 주석처리 하였다.
//	public String Dcrypt(String iv, String key, String text) throws Exception {
//		IvParameterSpec ivp = new IvParameterSpec(iv.getBytes("UTF-8"));
//		SecretKeySpec keySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
//		Cipher ci = Cipher.getInstance("AES/CBC/NoPadding");
//
//		ci.init(Cipher.DECRYPT_MODE, keySpec, ivp);
//
//		byte[] byteStr = Base64.getDecoder().decode((text.getBytes("UTF-8")));
//		String decStr = new String(ci.doFinal(byteStr), StandardCharsets.UTF_8);
//		return decStr;
//
//	}
	public static PublicKey getPublicKeyFromBase64Encrypted(String base64PublicKey) throws Exception {
		//상대방에게 받은 String의 키형식을 PublicKey로 풀어낸다. 
		byte[] decodedBase64PubKey = Base64.getDecoder().decode(base64PublicKey);

		return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decodedBase64PubKey));
	}

	// 필요한 경우 추가로 메서드를 정의하여 사용합니다.

	public static void main(String[] args) throws Exception {

		try {
			new E2EEChat();
		} catch (UnknownHostException ex) {
			System.out.println("연결 실패, 호스트 정보를 확인하세요.");
		} catch (IOException ex) {
			System.out.println("소켓 통신 중 문제가 발생하였습니다.");
		}
	}
}

// 사용자 입력을 통한 메세지 전송을 위한 Sender Runnable Class
// 여기에서 메세지 전송 처리를 수행합니다.

class MessageSender implements Runnable {
	E2EEChat clientContext;
	OutputStream socketOutputStream;
	String temp = "";

	// 접속에 관한 기타정보를 갖고 있다.
	private String myName = "";
	private String desName = "";
	private String Algoname = "RSA";
//	RSA방식으로 진행할것이기에 바꿔주었다.
	private String Nonce = "A/xqf";

	static PublicKey desPublicKey;
	static PublicKey myPublicKey;

	public MessageSender(E2EEChat context) throws IOException {
		clientContext = context;

		Socket clientSocket = clientContext.getSocketContext();
		socketOutputStream = clientSocket.getOutputStream();

	}
	//AES-CBC방식에서 사용된 암호화 함수
//	private String Encrypt(String iv, String key, String bodytext) throws Exception {
//		
//		IvParameterSpec ivp = new IvParameterSpec(iv.getBytes("UTF-8"));
//		SecretKeySpec keySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
//
//		Cipher ci = Cipher.getInstance("AES/CBC/NoPadding");
//		ci.init(Cipher.ENCRYPT_MODE, keySpec, ivp);
//
//		byte[] encrypted = ci.doFinal(bodytext.getBytes("UTF-8"));
//		String enStr = new String(Base64.getEncoder().encode((encrypted)));
//
//		return enStr;
//	}

		
	public static String encryptRSA(String Text, PublicKey publicKey) throws Exception {
		//RSA방식으로 암호화를 처리하기위해서 만든 함수이며 평문을 암호화시킨다.
		Cipher ci = Cipher.getInstance("RSA");
		ci.init(Cipher.ENCRYPT_MODE, publicKey);

		byte[] bytePlain = ci.doFinal(Text.getBytes("UTF-8"));
		String Str = Base64.getEncoder().encodeToString(bytePlain);
		return Str;
	}

	private void make3EPROTO() {
		temp = temp + "3EPROTO ";
		//단순하게 3EPROTO 를 집어넣기위한함수
	}

	/* *****************************************
	 * 서버에 메세지를 전송하는 함수를 구현하기 위해서 temp 라는 String에 값들을 추가해 가는 방식을 차용하였다.
	 * 
	 * *****************************************/
	
	private void connectUser(String name) throws Exception {
		
		make3EPROTO();
		myName = name;
		temp = temp + "CONNECT\n" + "Credential: " + myName;
		byte[] payload = temp.getBytes(StandardCharsets.UTF_8);

		socketOutputStream.write(payload, 0, payload.length);
		temp = "";
		//Connect 함과 동시에 자신의 공개키와 개인키 쌍을만들게된다.
		KeyPair kp = genRSAKeyPair();
		myPublicKey = kp.getPublic();
		E2EEChat.myPrivatekey = kp.getPrivate();
	}

	private void keyCHG(String des) throws IOException {
		make3EPROTO();
		// 키교환 단계에서는 상대방에게 자신의 공개키를 전달해 줌으로써 
		//	 상대방이 메세지를 보낼때 나의 공개키로 암호화 해서 보내도록 한다.
		desName = des;
		temp = temp + "KEYXCHG\n";
		temp = temp + "Algo: " + Algoname + "\n";
		temp = temp + "From: " + myName + "\n";
		temp = temp + "To: " + desName + "\n";
		temp = temp + "\n\n";
		 byte[] bytePublicKey = myPublicKey.getEncoded();
	     String StringMyPublicKey = Base64.getEncoder().encodeToString(bytePublicKey);
		temp = temp + StringMyPublicKey;
		byte[] payload = temp.getBytes(StandardCharsets.UTF_8);

		socketOutputStream.write(payload, 0, payload.length);
		temp = "";

	}

	private void mesSend(String message) throws Exception {
		//메세지를 보내는 함수
		make3EPROTO();
		temp = temp + "MSGSEND\n";
		temp = temp + "From: " + myName + "\n";
		temp = temp + "To: " + desName + "\n";
		temp = temp + "Nonce: " + "A/Xqf" + "\n";
		temp = temp + "\n\n";

		temp = temp + encryptRSA(message, desPublicKey);

		byte[] payload = temp.getBytes(StandardCharsets.UTF_8);

		socketOutputStream.write(payload, 0, payload.length);
		temp = "";
	}

	public KeyPair genRSAKeyPair() throws NoSuchAlgorithmException {
		//개인키 공개키 쌍을 만든다. 
		//RSA방식은 최소 1024 비트이상을 요구하므로 1024 비트의 random 한 값으로 이루어져있다.
		SecureRandom a = new SecureRandom();
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(1024, a);
		
		return gen.genKeyPair();
	}

	@Override
	public void run() {
		Scanner scanner = new Scanner(System.in);
		int index = 0;
		while (true) {
			try {
				// 사전에 index 라는 값을 설정해 connect -> Keyxchg -> message 순서대로 이루어지도록 한다.
				// keychg 이후에는 메세지 전송만 이루어지게 하였다.
				if (index == 0) {
					System.out.print("[CONNECT] name: ");
					String message = scanner.nextLine().trim();
					connectUser(message);
					index++;
					
				}

				else if (index == 1) {
					Thread.sleep(1000);
					System.out.print("[KEYCHANGE] Destination: ");
					String message = scanner.nextLine().trim();
					keyCHG(message);
					
					index++;
					
				} else {
					Thread.sleep(1000);
					System.out.print("MESSAGE: ");
				String message = scanner.nextLine().trim();

				mesSend(message);
				}
			} catch (Exception ex) {
				break;
			}
		}

		System.out.println("MessageSender runnable end");
	}
}

