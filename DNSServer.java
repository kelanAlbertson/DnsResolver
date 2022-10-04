import java.io.IOException;
import java.net.*;
import java.util.ArrayList;

/**
 * This class runs the server for answering DNS queries
 */
public class DNSServer {

    private static void run() throws IOException {
        //open a socket on port 8053 (port 53 is normally reserved for DNS)
        DatagramSocket clientSocket = new DatagramSocket(8053);

        DNSCache cache = new DNSCache();

        byte[] bytes = new byte[512];

        boolean serverIsRunning = true;
        while (serverIsRunning) {
            // create a datagram packet to receive the data
            DatagramPacket packet = new DatagramPacket(bytes, bytes.length);
            // waits to receive and then puts message received into the byte array
            clientSocket.receive(packet);

            // log the address and port of the client so that we can send response to the right place later
            InetAddress address = packet.getAddress();
            int port = packet.getPort();

            // decode the incoming message (this will include decoding the header and any queries or records)
            DNSMessage request = DNSMessage.decodeMessage(bytes);

            System.out.println("dig query:");
            System.out.println(request);

            // this server will only handle 1 question at a time
            ArrayList<DNSRecord> answers = new ArrayList<>();
            byte[] responseBytes;
            // if there is a valid answer in the cache then create a response message with that answer
            if (cache.hasValidResponse(request.getQuestions().get(0))) {
                System.out.println("IN CACHE");
                answers.add(cache.getAnswer(request.getQuestions().get(0)));
                DNSMessage response = DNSMessage.buildResponse(request, answers);
                responseBytes = response.getRawMessage_();

                System.out.println("DNS response");
                System.out.println(response);
            }
            // otherwise create another UDP socket to forward the request Google (8.8.8.8) and await their response
            else {
                System.out.println("NOT IN CACHE, ASK GOOGLE");
                DatagramSocket googleSocket = new DatagramSocket();
                DatagramPacket forwardPacket = new DatagramPacket(bytes, bytes.length, InetAddress.getByName("8.8.8.8"), 53);
                googleSocket.send(forwardPacket);
                DatagramPacket googleResponse = new DatagramPacket(bytes, bytes.length);
                googleSocket.receive(googleResponse);
                DNSMessage googleMessage = DNSMessage.decodeMessage(bytes);
                // if the domain name does not exist then the format of the DNS response is very tricky (particularly
                // the authoritative name server record that must be included) and so for the time being I handle this
                // by directly forwarding Google's entire response to the original client (and I do not cache it)
                if (googleMessage.getHeader().getRcode_() == 3) {
                    responseBytes = googleMessage.getRawMessage_();
                    System.out.println("Google response");
                    System.out.println(googleMessage);
                }
                // otherwise create a new response of my own that includes Google's answer
                else {
                    answers.add(googleMessage.getAnswers().get(0));
                    cache.add(request.getQuestions().get(0), googleMessage.getAnswers().get(0)); // this assumes one question and one answer only
                    DNSMessage response = DNSMessage.buildResponse(request, answers);
                    responseBytes = response.getRawMessage_();
                    System.out.println("DNS response");
                    System.out.println(response);
                }
            }

            // create a packet with the response bytes and send back to the original client
            packet = new DatagramPacket(responseBytes, responseBytes.length, address, port);
            clientSocket.send(packet);
        }
        clientSocket.close();
    }

    public static void main(String[] args) {
        try {
            run();
        }
        catch (IOException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}
