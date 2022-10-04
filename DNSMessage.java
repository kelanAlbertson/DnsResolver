import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

/**
 * This class represents an entire DNS message including the header and any questions or records
 */
public class DNSMessage {
    private byte[] rawMessage_;
    private DNSHeader header_;
    private ArrayList<DNSQuestion> questions_;
    private ArrayList<DNSRecord> answers_;
    private ArrayList<DNSRecord> authorityRecords_;
    private ArrayList<DNSRecord> additionalRecords_;


    /**
     * creates, fills, and returns a DNSMessage object from the provided byte array of packet bytes
     *
     * @param bytes - byte array of full message to parse into all message info
     * @return DNSMessage object with all info parsed
     */
    public static DNSMessage decodeMessage(byte[] bytes) throws IOException {
        DNSMessage message = new DNSMessage();

        // store everything in completeMessage_
        message.rawMessage_ = bytes;

        // turn byte array into stream and now go back to decode all info from it
        InputStream input = new ByteArrayInputStream(bytes);
        // get header
        message.header_ = DNSHeader.decodeHeader(input);
        // get all questions
        message.questions_ = new ArrayList<>();
        for (int i = 0; i < message.header_.getQDcount(); ++i) {
            message.questions_.add(DNSQuestion.decodeQuestion(input, message));
        }
        // get all answers
        message.answers_ = new ArrayList<>();
        for (int i = 0; i < message.header_.getANcount(); ++i) {
            message.answers_.add(DNSRecord.decodeRecord(input, message));
        }
        // get all authority records
        message.authorityRecords_ = new ArrayList<>();
        for (int i = 0; i < message.header_.getNScount(); ++i) {
            message.authorityRecords_.add(DNSRecord.decodeRecord(input, message));
        }
        // get all additional records
        message.additionalRecords_ = new ArrayList<>();
        for (int i = 0; i < message.header_.getARcount(); ++i) {
            message.additionalRecords_.add(DNSRecord.decodeRecord(input, message));
        }

        return message;
    }

    /**
     * read the pieces of a domain name starting from the current position of the input stream
     *
     * @param input - stream to read domain name from
     * @return domain name labels in ArrayList
     */
    public ArrayList<String> readDomainName(InputStream input) throws IOException {

        boolean readingName = true;
        ArrayList<String> octets = new ArrayList<>();
        while(readingName) {
            int length = input.read();
            // if the byte is 0 then the label sequence is done and we exit loop
            if (length == 0) {
                readingName = false;
            }
            // if the first two bits are 11 then the following 14 bits will be a pointer to another location in
            // the message that the desired domain name was written in full
            else if ((length & 0xc0) >> 6 == 0x3) {
                int secondByte = input.read();
                int offset = ((((length & 0xff) << 8) | (secondByte & 0xff)) & 0x3f);
                octets.addAll(readDomainName(offset));
                readingName = false;
            }
            //otherwise read it in normally, octet by octet
            else {
                byte[] bytes = input.readNBytes(length);
                octets.add(new String(bytes, StandardCharsets.UTF_8));
            }
        }
        return octets;
    }

    /**
     * read the pieces of a domain name starting from a specified byte in the message's entire byte array
     *
     * @param firstByte - byte number of the first byte of the domain name piece in the message's byte array
     * @return domain name labels in ArrayList
     */
    public ArrayList<String> readDomainName(int firstByte) throws IOException {

        // create a ByteArrayInputStream that starts at firstByte
        // I'm unsure how long the length parameter should be in this so I am leaving it at 63 bytes
        InputStream input = new ByteArrayInputStream(rawMessage_, firstByte, 63);
        return readDomainName(input);
    }

    /**
     * build a response based on the request and the answers
     *
     * @param request - request message to build response to
     * @param answers - answers to include in response
     * @return full DNSMessage that responds to request
     */
    public static DNSMessage buildResponse(DNSMessage request, ArrayList<DNSRecord> answers) throws IOException {
        DNSMessage response = new DNSMessage();
        response.header_ = DNSHeader.buildResponseHeader(request);
        response.questions_ = request.getQuestions();
        response.answers_ = answers;
        response.authorityRecords_ = new ArrayList<>();
        response.additionalRecords_ = new ArrayList<>();
        response.additionalRecords_.add(DNSRecord.buildStandardAdditionalRecord());
        response.rawMessage_ = response.toBytes();
        return response;
    }

    /**
     * get the message in byte array form for sending through socket
     *
     * @return byte array of all bytes for message
     */
    public byte[] toBytes() throws IOException {
        // create stream that will be filled and then converted to byte array
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        header_.writeBytes(byteStream);
        HashMap<String,Integer> domainNameLocations = new HashMap<>();
        // get all questions
        for (int i = 0; i < header_.getQDcount(); ++i) {
            questions_.get(i).writeBytes(byteStream, domainNameLocations);
        }
        // get all answers
        for (int i = 0; i < header_.getANcount(); ++i) {
            answers_.get(i).writeBytes(byteStream, domainNameLocations);
        }
        // get all authority records
        for (int i = 0; i < header_.getNScount(); ++i) {
            authorityRecords_.get(i).writeBytes(byteStream, domainNameLocations);
        }
        // get all additional records
        for (int i = 0; i < header_.getARcount(); ++i) {
            additionalRecords_.get(i).writeBytes(byteStream, domainNameLocations);
        }
        return byteStream.toByteArray();
    }

    /**
     * write the domain name to the output stream using compression if possible
     *
     * If this is the first time we've seen this domain name in the packet, write it using the DNS encoding
     * (each segment of the domain prefixed with its length, 0 at the end), and add it to the hash map.
     * Otherwise, write a back pointer to where the domain has been seen previously
     *
     * @param output - stream to write domain name to
     * @param domainLocations - HashMap keeping track of byte locations of domain names that have been written in full so far
     * @param domainPieces - labels of the domain name to be written
     */
    public static void writeDomainName(ByteArrayOutputStream output, HashMap<String,Integer> domainLocations, ArrayList<String> domainPieces) throws IOException {
        // if at end of domain name or domain is root then write a 0
        if (domainPieces.size() == 0) {
            output.write(0);
        }
        // otherwise look to see if the domain name was already written
        else if (domainLocations.containsKey(octetsToString(domainPieces))) {
            // assemble pointer with 11 in first 2 bits and the offset in the remaining 14 bits
            int pointer = (0xc000 | (domainLocations.get(octetsToString(domainPieces))) & 0x3fff);
            int byte1 = (pointer & 0xff00) >> 8;
            int byte2 = pointer & 0xff;
            output.write(byte1);
            output.write(byte2);
        }
        // if we reach this point then we write the next piece of the domain from the domainPieces list
        // in the format of one octet signifying a length followed by that number of octets representing characters
        else {
            // save the remaining domain name and current location in the stream to the domainLocations HashMap
            domainLocations.put(octetsToString(domainPieces), output.size());
            // handles only the very next piece of the domain name in the list
            int numOctets = domainPieces.get(0).length();
            output.write(numOctets);
            output.write(domainPieces.get(0).getBytes(StandardCharsets.US_ASCII));
            // then removes it
            domainPieces.remove(0);
            // and call this method again but using only the remaining domain pieces
            writeDomainName(output, domainLocations, domainPieces);
        }
    }

    /**
     * join the pieces of a domain name with dots ([ "utah", "edu"] -> "utah.edu" )
     *
     * @param octets - labels to join
     * @return String of all labels assembled into full domain name (including '.' between labels)
     */
    public static String octetsToString(ArrayList<String> octets) {
        String result = "";
        // a zero length label indicates the "ROOT"
        if (octets.size() == 0) {
            return "ROOT";
        }
        // otherwise append the strings into one long domain name
        for (String octet : octets) {
            result += octet + '.';
        }
        // trim off last char, which should be an extra '.'
        return result.substring(0, result.length()-1);
    }

    /**
     * split a domain name in string form into an array of its label pieces
     *
     * @param domainName - the string form of the domain name to split
     * @return ArrayList of the labels
     */
    public static ArrayList<String> stringToOctets(String domainName) {
        // if the domain name is root then the ArrayList should just be empty
        if (domainName.equals("ROOT")) {
            return new ArrayList<>();
        }
        // otherwise split the string into a string array and then convert to ArrayList
        String[] octetArray = domainName.split("\\.");
        return new ArrayList<>(Arrays.asList(octetArray));
    }


    // auto-generated functions
    @Override
    public String toString() {
        return "DNSMessage:" +
                "\n  header: " + header_ +
                "\n  questions(" + questions_.size() + "): " + questions_ +
                "\n  answers(" + answers_.size() + "): " + answers_ +
                "\n  authorityRecords(" + authorityRecords_.size() + "): " + authorityRecords_ +
                "\n  additionalRecords(" + additionalRecords_.size() + "): " + additionalRecords_ +
                '}';
    }

    public DNSHeader getHeader() {
        return header_;
    }

    public ArrayList<DNSQuestion> getQuestions() {
        return questions_;
    }

    public ArrayList<DNSRecord> getAnswers() {
        return answers_;
    }

    public byte[] getRawMessage_() {
        return rawMessage_;
    }
}
